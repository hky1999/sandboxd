package main

import (
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"strings"
	"testing"
)

func TestReviewSourceReceiptSchema(t *testing.T) {
	good := migrationJournal{SourceOpRequestDigest: strings.Repeat("a", 64), SourceRootDigest: strings.Repeat("b", 64), SourceRootScheme: checkpointroot.Scheme}
	if err := good.requireReceipt("review"); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"scheme", "request", "root"} {
		t.Run(field, func(t *testing.T) {
			j := good
			switch field {
			case "scheme":
				j.SourceRootScheme = "unknown-scheme"
			case "request":
				j.SourceOpRequestDigest = strings.Repeat("A", 64)
			case "root":
				j.SourceRootDigest = strings.Repeat("B", 64)
			}
			if err := j.requireReceipt("review"); err == nil {
				t.Fatal("invalid source receipt accepted")
			}
		})
	}
}
