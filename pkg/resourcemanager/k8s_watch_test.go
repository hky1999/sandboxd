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

package resourcemanager

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

func TestNextRetryInterval(t *testing.T) {
	assert.Equal(t, watchRetryMinInterval, nextRetryInterval(0))
	assert.Equal(t, 2*watchRetryMinInterval, nextRetryInterval(watchRetryMinInterval))
	assert.Equal(t, 32*time.Second, nextRetryInterval(16*time.Second))
	assert.Equal(t, watchRetryMaxInterval, nextRetryInterval(watchRetryMaxInterval))
	assert.Equal(t, watchRetryMaxInterval, nextRetryInterval(2*watchRetryMaxInterval))
}

func TestCalcPodRequestWithInitContainers(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("100m"),
							corev1.ResourceMemory: apiresource.MustParse("128Mi"),
						},
					},
				},
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("200m"),
							corev1.ResourceMemory: apiresource.MustParse("256Mi"),
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("500m"),
							corev1.ResourceMemory: apiresource.MustParse("64Mi"),
						},
					},
				},
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("150m"),
							corev1.ResourceMemory: apiresource.MustParse("600Mi"),
						},
					},
				},
			},
		},
	}

	req := calcPodRequest(pod)
	assert.Equal(t, int64(500), req.cpuMilli)
	assert.Equal(t, int64(600<<20), req.memBytes)
}

func TestCalcPodRequestIncludesRestartableInitAndOverhead(t *testing.T) {
	restartAlways := corev1.ContainerRestartPolicyAlways
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU:    apiresource.MustParse("500m"),
					corev1.ResourceMemory: apiresource.MustParse("512Mi"),
				}},
			}},
			InitContainers: []corev1.Container{
				{
					RestartPolicy: &restartAlways,
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU:    apiresource.MustParse("200m"),
						corev1.ResourceMemory: apiresource.MustParse("128Mi"),
					}},
				},
				{
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU:    apiresource.MustParse("900m"),
						corev1.ResourceMemory: apiresource.MustParse("1Gi"),
					}},
				},
			},
			Overhead: corev1.ResourceList{
				corev1.ResourceCPU:    apiresource.MustParse("50m"),
				corev1.ResourceMemory: apiresource.MustParse("64Mi"),
			},
		},
	}

	req := calcPodRequest(pod)
	assert.Equal(t, int64(1150), req.cpuMilli)
	assert.Equal(t, int64(1216<<20), req.memBytes)
}

func TestShouldCountPod(t *testing.T) {
	assert.False(t, shouldCountPod(nil, "node-a"))

	running := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "100m", "128Mi")
	assert.True(t, shouldCountPod(running, "node-a"))

	pending := running.DeepCopy()
	pending.Status.Phase = corev1.PodPending
	assert.True(t, shouldCountPod(pending, "node-a"))

	succeeded := running.DeepCopy()
	succeeded.Status.Phase = corev1.PodSucceeded
	assert.False(t, shouldCountPod(succeeded, "node-a"))

	failed := running.DeepCopy()
	failed.Status.Phase = corev1.PodFailed
	assert.False(t, shouldCountPod(failed, "node-a"))

	otherNode := running.DeepCopy()
	otherNode.Spec.NodeName = "node-b"
	assert.False(t, shouldCountPod(otherNode, "node-a"))
}

func TestPodKey(t *testing.T) {
	assert.Equal(t, "", podKey(nil))

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod"}}
	assert.Equal(t, "ns/pod", podKey(pod))
}

func TestMaxInt64(t *testing.T) {
	assert.Equal(t, int64(10), maxInt64(10, 0))
	assert.Equal(t, int64(0), maxInt64(-1, 0))
	assert.Equal(t, int64(3), maxInt64(1, 3))
}

func TestPodRequestMaybeCounted(t *testing.T) {
	mgr := &k8sWatchResourceManager{localNodeName: "node-a"}

	req, ok := mgr.podRequestMaybeCounted(nil)
	assert.False(t, ok)
	assert.Equal(t, podResourceRequest{}, req)

	running := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "250m", "256Mi")
	req, ok = mgr.podRequestMaybeCounted(running)
	assert.True(t, ok)
	assert.Equal(t, int64(250), req.cpuMilli)
	assert.Equal(t, int64(256<<20), req.memBytes)

	succeeded := running.DeepCopy()
	succeeded.Status.Phase = corev1.PodSucceeded
	req, ok = mgr.podRequestMaybeCounted(succeeded)
	assert.False(t, ok)
	assert.Equal(t, podResourceRequest{}, req)
}

func TestK8sWatchResourceManagerUpdateNodeTotal(t *testing.T) {
	mgr := &k8sWatchResourceManager{podRequests: map[string]podResourceRequest{}}
	node := &corev1.Node{
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    apiresource.MustParse("8"),
				corev1.ResourceMemory: apiresource.MustParse("32Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    apiresource.MustParse("7500m"),
				corev1.ResourceMemory: apiresource.MustParse("30Gi"),
			},
		},
	}

	mgr.updateNodeTotal(node)
	cpu, mem, _, _ := mgr.snapshot()
	assert.Equal(t, int64(7500), cpu)
	assert.Equal(t, int64(30<<30), mem)
}

func TestK8sWatchResourceManagerPodLifecycleAffectsAllocated(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		localNodeName: "node-a",
		podRequests:   map[string]podResourceRequest{},
	}

	pod := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "500m", "1Gi")
	mgr.onPodUpdate(pod)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(500), allocatedCPU)
	assert.Equal(t, int64(1<<30), allocatedMem)

	updated := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "900m", "2Gi")
	mgr.onPodUpdate(updated)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(900), allocatedCPU)
	assert.Equal(t, int64(2<<30), allocatedMem)

	mgr.onPodDelete(updated)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)
}

func TestK8sWatchResourceManagerTerminalAndUnboundPodsAreIgnored(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		localNodeName: "node-a",
		podRequests:   map[string]podResourceRequest{},
	}

	pending := newTestPod("default", "pod-a", "node-a", corev1.PodPending, "300m", "512Mi")
	mgr.onPodUpdate(pending)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(300), allocatedCPU)
	assert.Equal(t, int64(512<<20), allocatedMem)

	succeeded := pending.DeepCopy()
	succeeded.Status.Phase = corev1.PodSucceeded
	mgr.onPodUpdate(succeeded)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)

	otherNodePod := newTestPod("default", "pod-b", "node-b", corev1.PodRunning, "700m", "1Gi")
	mgr.onPodUpdate(otherNodePod)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)
}

func TestK8sWatchResourceManagerPodSnapshotUsesCurrentRequests(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		localNodeName: "node-a",
		allocatedCPU:  100,
		allocatedMem:  256 << 20,
		podRequests: map[string]podResourceRequest{
			"default/pod-a": {cpuMilli: 100, memBytes: 256 << 20},
		},
	}

	running := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "700m", "1Gi")
	mgr.onPodUpdate(running)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(700), allocatedCPU)
	assert.Equal(t, int64(1<<30), allocatedMem)
}

func TestK8sWatchResourceManagerWatchEventHandlers(t *testing.T) {
	mgr := &k8sWatchResourceManager{localNodeName: "node-a", podRequests: map[string]podResourceRequest{}}

	node := &corev1.Node{}
	node.ResourceVersion = "11"
	node.Status.Allocatable = corev1.ResourceList{
		corev1.ResourceCPU:    apiresource.MustParse("6"),
		corev1.ResourceMemory: apiresource.MustParse("24Gi"),
	}
	rv, err := mgr.handleNodeEvent(watch.Event{Type: watch.Modified, Object: node})
	assert.NoError(t, err)
	assert.Equal(t, "11", rv)
	cpu, mem, _, _ := mgr.snapshot()
	assert.Equal(t, int64(6000), cpu)
	assert.Equal(t, int64(24<<30), mem)

	rv, err = mgr.handleNodeEvent(watch.Event{Type: watch.Deleted, Object: node})
	assert.NoError(t, err)
	assert.Equal(t, "11", rv)
	cpu, mem, _, _ = mgr.snapshot()
	assert.Equal(t, int64(0), cpu)
	assert.Equal(t, int64(0), mem)

	errStatus := &metav1.Status{Code: 410, Message: "gone"}
	_, err = mgr.handleNodeEvent(watch.Event{Type: watch.Error, Object: errStatus})
	assert.Error(t, err)

	pod := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "300m", "256Mi")
	pod.ResourceVersion = "21"
	rv, err = mgr.handlePodEvent(watch.Event{Type: watch.Added, Object: pod})
	assert.NoError(t, err)
	assert.Equal(t, "21", rv)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(300), allocatedCPU)
	assert.Equal(t, int64(256<<20), allocatedMem)

	rv, err = mgr.handlePodEvent(watch.Event{Type: watch.Deleted, Object: pod})
	assert.NoError(t, err)
	assert.Equal(t, "21", rv)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)

	_, err = mgr.handlePodEvent(watch.Event{Type: watch.Error, Object: errStatus})
	assert.Error(t, err)
}

func TestK8sWatchResourceManagerGetAvailableResource(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		totalCPU:     4000,
		totalMem:     int64(10 << 30),
		allocatedCPU: 1500,
		allocatedMem: int64((3 << 30) + (512 << 20)),
		podRequests:  map[string]podResourceRequest{},
	}

	cpu, mem, err := mgr.GetAvailableResource()
	assert.NoError(t, err)
	assert.Equal(t, int64(2500), cpu)
	assert.Equal(t, int64((6<<30)+(512<<20)), mem)

	mgr.allocatedCPU = 5000
	mgr.allocatedMem = int64(12 << 30)
	cpu, mem, err = mgr.GetAvailableResource()
	assert.NoError(t, err)
	assert.Equal(t, int64(0), cpu)
	assert.Equal(t, int64(0), mem)
}

func newTestPod(namespace, name, nodeName string, phase corev1.PodPhase, cpuReq, memReq string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse(cpuReq),
							corev1.ResourceMemory: apiresource.MustParse(memReq),
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}
