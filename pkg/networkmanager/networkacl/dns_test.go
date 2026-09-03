// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networkacl

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSConcurrencyLimiterBoundsGlobalAndPerSandboxWork(t *testing.T) {
	limiter, err := newDNSConcurrencyLimiter(2, 1)
	require.NoError(t, err)

	releaseA, ok := limiter.tryAcquire(net.ParseIP("10.88.0.2"))
	require.True(t, ok)
	_, ok = limiter.tryAcquire(net.ParseIP("10.88.0.2"))
	assert.False(t, ok, "one sandbox must not exceed its share")

	releaseB, ok := limiter.tryAcquire(net.ParseIP("10.88.0.3"))
	require.True(t, ok)
	_, ok = limiter.tryAcquire(net.ParseIP("10.88.0.4"))
	assert.False(t, ok, "all sandboxes together must not exceed the global limit")

	releaseA()
	releaseC, ok := limiter.tryAcquire(net.ParseIP("10.88.0.4"))
	require.True(t, ok)
	releaseB()
	releaseC()
	assert.Empty(t, limiter.sandboxInFlight)
}

func TestDNSConcurrencyLimiterRejectsInvalidLimits(t *testing.T) {
	_, err := newDNSConcurrencyLimiter(0, 1)
	require.Error(t, err)
	_, err = newDNSConcurrencyLimiter(1, 0)
	require.Error(t, err)
	_, err = newDNSConcurrencyLimiter(1, 2)
	require.Error(t, err)
}

func TestDNSErrorResponseUsesServerFailureForOverload(t *testing.T) {
	name, err := dnsmessage.NewName("example.com.")
	require.NoError(t, err)
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := message.Pack()
	require.NoError(t, err)

	response, err := dnsErrorResponse(payload, dnsmessage.RCodeServerFailure)
	require.NoError(t, err)
	header, questions, _, err := parseDNSQuestions(response)
	require.NoError(t, err)
	assert.True(t, header.Response)
	assert.Equal(t, dnsmessage.RCodeServerFailure, header.RCode)
	assert.Len(t, questions, 1)
}

func TestTrafficGrantNamesIgnoresParallelAAAAQueries(t *testing.T) {
	nameA := testDNSName(t, "packages.example.")
	nameAll := testDNSName(t, "registry.example.")
	nameCNAME := testDNSName(t, "alias.example.")

	assert.Equal(t, []string{"packages.example", "registry.example"}, trafficGrantNames([]dnsmessage.Question{
		{Name: nameA, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
		{Name: nameA, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		{Name: nameA, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		{Name: nameAll, Type: dnsmessage.TypeALL, Class: dnsmessage.ClassINET},
		{Name: nameCNAME, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
	}))
}

func TestValidateDNSResponseRejectsMismatchedTransactionAndQuestion(t *testing.T) {
	question := dnsmessage.Question{
		Name: testDNSName(t, "packages.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}
	requestHeader := dnsmessage.Header{ID: 42, OpCode: 0}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 42, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{question},
	}
	payload, err := response.Pack()
	require.NoError(t, err)
	require.NoError(t, validateDNSResponse(payload, requestHeader, []dnsmessage.Question{question}))

	response.Header.ID++
	payload, err = response.Pack()
	require.NoError(t, err)
	require.ErrorContains(t, validateDNSResponse(payload, requestHeader, []dnsmessage.Question{question}), "header")

	response.Header.ID = requestHeader.ID
	response.Questions[0].Name = testDNSName(t, "other.example.")
	payload, err = response.Pack()
	require.NoError(t, err)
	require.ErrorContains(t, validateDNSResponse(payload, requestHeader, []dnsmessage.Question{question}), "question 0")
}

func TestResolveDNSResponseFollowsCNAMEAndRejectsPoisonedAddresses(t *testing.T) {
	question := testDNSName(t, "packages.example.")
	canonical := testDNSName(t, "cdn.example.")
	poison := testDNSName(t, "poison.example.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{Name: question, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: question, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30},
				Body:   &dnsmessage.CNAMEResource{CNAME: canonical},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: canonical, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: poison, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 99}},
			},
		},
	}
	payload, err := message.Pack()
	require.NoError(t, err)
	rewritten, resolved, err := resolveDNSResponse(payload, []string{"packages.example."})
	require.NoError(t, err)
	assert.Equal(t, []resolvedAddress{{IP: [4]byte{192, 0, 2, 10}, TTL: 30}}, resolved["packages.example"])

	var parsed dnsmessage.Message
	require.NoError(t, parsed.Unpack(rewritten))
	require.Len(t, parsed.Answers, 3)
	assert.Equal(t, uint32(30), parsed.Answers[1].Header.TTL, "A TTL is bounded by the complete CNAME chain")
}

func TestResolveDNSResponseUsesTightestConvergingCNAMEPath(t *testing.T) {
	question := testDNSName(t, "packages.example.")
	longPath := testDNSName(t, "long.example.")
	shortPath := testDNSName(t, "short.example.")
	canonical := testDNSName(t, "cdn.example.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 9, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{Name: question, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: question, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.CNAMEResource{CNAME: longPath},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: question, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 10},
				Body:   &dnsmessage.CNAMEResource{CNAME: shortPath},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: longPath, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.CNAMEResource{CNAME: canonical},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: shortPath, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 10},
				Body:   &dnsmessage.CNAMEResource{CNAME: canonical},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: canonical, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
			},
		},
	}
	payload, err := message.Pack()
	require.NoError(t, err)

	_, resolved, err := resolveDNSResponse(payload, []string{"packages.example."})
	require.NoError(t, err)
	assert.Equal(t, []resolvedAddress{{IP: [4]byte{192, 0, 2, 10}, TTL: 10}}, resolved["packages.example"])
}

func TestResolveDNSResponseDoesNotGrantFromNegativeOrTruncatedAnswers(t *testing.T) {
	name := testDNSName(t, "packages.example.")
	for _, header := range []dnsmessage.Header{
		{ID: 10, Response: true, RCode: dnsmessage.RCodeNameError},
		{ID: 11, Response: true, RCode: dnsmessage.RCodeSuccess, Truncated: true},
	} {
		message := dnsmessage.Message{
			Header:    header,
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
			}},
		}
		payload, err := message.Pack()
		require.NoError(t, err)
		_, resolved, err := resolveDNSResponse(payload, []string{"packages.example."})
		require.NoError(t, err)
		assert.Empty(t, resolved["packages.example"])
	}
}

func TestResolveDNSResponseCapsReachableAddresses(t *testing.T) {
	name := testDNSName(t, "many.example.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 8, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	for index := 0; index <= maxDNSAddresses; index++ {
		message.Answers = append(message.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(index + 1)}},
		})
	}
	payload, err := message.Pack()
	require.NoError(t, err)
	_, _, err = resolveDNSResponse(payload, []string{"many.example."})
	require.ErrorContains(t, err, "maximum is 64")
}

func testDNSName(t *testing.T, value string) dnsmessage.Name {
	t.Helper()
	name, err := dnsmessage.NewName(value)
	require.NoError(t, err)
	return name
}
