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

// Package checkpointlocator decides which node may restore a checkpoint.
// It has two halves:
//
//   - a compatibility matrix that mirrors, field for field, the restore-side
//     verification in the Firecracker runtime handler (equality on every
//     recorded tuple field; unrecorded fields never gate; a checkpoint
//     without a tuple verifies against any node);
//   - a placement tree in the CubeSandbox restoreplace shape: the origin
//     node wins whenever it is registered, cross-node placement requires the
//     checkpoint to be eligible and a compatible candidate to exist, and an
//     unsatisfiable request fails closed instead of degrading.
//
// The package is deliberately self-contained: node records are plain JSON
// fetched from each node's checkpoint catalog endpoint (or supplied by any
// future registry backend), so no storage client is coupled here.
package checkpointlocator

import (
	"fmt"
	"sort"
)

// CheckpointCompat mirrors the compatibility tuple recorded in a Firecracker
// v2 checkpoint manifest. The fields match the runtime's restore-side
// verification exactly; anything the manifest left empty is not compared.
type CheckpointCompat struct {
	Arch        string `json:"arch,omitempty"`
	Firecracker string `json:"firecracker,omitempty"`
	Kernel      string `json:"kernel,omitempty"`
	Initrd      string `json:"initrd,omitempty"`
	KernelArgs  string `json:"kernel_args,omitempty"`
}

// RuntimeFace is one runtime handler's software stack as a node reports it.
// The digest fields are sha256 hex of the exact binaries the node restores
// with, so equality against a checkpoint's tuple means the node replays the
// artifact on the stack that produced it.
type RuntimeFace struct {
	Name string `json:"name"`
	CheckpointCompat
}

// NodeRecord is a node's registration: what runtimes it serves, where its
// catalog listens, and informational hardware facts. The informational
// fields are reported for operators and future tightening; they do not gate
// placement today.
type NodeRecord struct {
	ID            string        `json:"id"`
	Address       string        `json:"address,omitempty"`
	Runtimes      []RuntimeFace `json:"runtimes"`
	CPUVendor     string        `json:"cpu_vendor,omitempty"`
	CPUModel      string        `json:"cpu_model,omitempty"`
	KernelRelease string        `json:"kernel_release,omitempty"`
}

// Evaluation is the matrix outcome for one runtime face.
type Evaluation struct {
	Runtime    string   `json:"runtime"`
	Compatible bool     `json:"compatible"`
	Reasons    []string `json:"reasons,omitempty"`
}

// Evaluate applies the compatibility matrix: a checkpoint restores on a
// runtime face when every field the checkpoint recorded equals the face's
// value. A nil checkpoint tuple is compatible with everything, matching the
// restore path's treatment of pre-tuple artifacts.
func Evaluate(checkpoint *CheckpointCompat, face RuntimeFace) Evaluation {
	eval := Evaluation{Runtime: face.Name, Compatible: true}
	if checkpoint == nil {
		return eval
	}
	for _, field := range []struct{ name, want, have string }{
		{"arch", checkpoint.Arch, face.Arch},
		{"firecracker", checkpoint.Firecracker, face.Firecracker},
		{"kernel", checkpoint.Kernel, face.Kernel},
		{"initrd", checkpoint.Initrd, face.Initrd},
		{"kernel_args", checkpoint.KernelArgs, face.KernelArgs},
	} {
		if field.want != "" && field.want != field.have {
			eval.Compatible = false
			eval.Reasons = append(eval.Reasons,
				fmt.Sprintf("%s: checkpoint %q node %q", field.name, field.want, field.have))
		}
	}
	return eval
}

// EvaluateNode returns the per-runtime evaluations of a node for a
// checkpoint. A node with no matching runtime name is simply evaluated on
// what it reports; callers pick candidates by Compatible.
func EvaluateNode(checkpoint *CheckpointCompat, node NodeRecord) []Evaluation {
	evals := make([]Evaluation, 0, len(node.Runtimes))
	for _, face := range node.Runtimes {
		evals = append(evals, Evaluate(checkpoint, face))
	}
	return evals
}

// Input selects a placement for one checkpoint.
type Input struct {
	// CheckpointID names the artifact in errors and the result.
	CheckpointID string
	// Compat is the checkpoint's recorded tuple; nil means the artifact
	// predates tuples and verifies anywhere.
	Compat *CheckpointCompat
	// OriginNodeID is the node the checkpoint was created on. Placement
	// prefers it whenever it is registered, even when cross-node is allowed.
	OriginNodeID string
	// PinToOrigin forbids cross-node placement (for example, the sandbox has
	// host-local mounts). With the origin unavailable the request fails.
	PinToOrigin bool
	// Nodes is the registry snapshot to place against.
	Nodes []NodeRecord
}

// Placement is the decision outcome.
type Placement struct {
	NodeID    string `json:"node_id"`
	Address   string `json:"address,omitempty"`
	Runtime   string `json:"runtime"`
	CrossNode bool   `json:"cross_node"`
}

// Decide runs the placement tree: origin first; otherwise the earliest
// compatible candidate in stable node order; never a silent degradation.
func Decide(in Input) (Placement, error) {
	byID := make(map[string]NodeRecord, len(in.Nodes))
	for _, n := range in.Nodes {
		byID[n.ID] = n
	}

	// The origin wins whenever it is registered AND compatible. Origin
	// preference selects among nodes the restore can actually succeed on:
	// if the origin's stack drifted since the checkpoint was made (a binary
	// upgrade), its own restore-side verification would refuse the artifact,
	// and the tree must fall through to a compatible peer instead of
	// returning a placement that deterministically fails.
	if origin, ok := byID[in.OriginNodeID]; ok {
		for _, face := range origin.Runtimes {
			if eval := Evaluate(in.Compat, face); eval.Compatible {
				return Placement{
					NodeID:  origin.ID,
					Address: origin.Address,
					Runtime: face.Name,
				}, nil
			}
		}
	}

	if in.PinToOrigin {
		return Placement{}, fmt.Errorf(
			"checkpoint %s is pinned to origin %q, which is not registered",
			in.CheckpointID, in.OriginNodeID)
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids) // stable candidate order for reproducible decisions
	var whyNot []string
	for _, id := range ids {
		node := byID[id]
		for _, face := range node.Runtimes {
			eval := Evaluate(in.Compat, face)
			if eval.Compatible {
				return Placement{
					NodeID:    node.ID,
					Address:   node.Address,
					Runtime:   face.Name,
					CrossNode: true,
				}, nil
			}
			whyNot = append(whyNot, fmt.Sprintf("%s/%s: %v", node.ID, face.Name, eval.Reasons))
		}
		if len(node.Runtimes) == 0 {
			whyNot = append(whyNot, fmt.Sprintf("%s: no runtimes registered", node.ID))
		}
	}
	return Placement{}, fmt.Errorf(
		"checkpoint %s cannot restore cross-node (origin %q unavailable, no compatible node: %v)",
		in.CheckpointID, in.OriginNodeID, whyNot)
}

// NodeHolder pairs a node record with the content-addressed template ids it
// holds, so a template placement can require both presence and stack
// compatibility in one pass.
type NodeHolder struct {
	Record NodeRecord
	Holds  []string
}

// TemplateInput selects a placement for deriving from one template.
type TemplateInput struct {
	// TemplateID is the content address being derived from.
	TemplateID string
	// Compat is the template's recorded tuple; nil verifies anywhere.
	Compat *CheckpointCompat
	// Nodes pairs every registry node with the templates it holds.
	Nodes []NodeHolder
}

// DecideTemplate places a template derivation: the earliest node in stable
// order that both holds the template and passes the compatibility matrix.
// Templates have no origin affinity — every holder is equivalent — so the
// decision is exactly "compatible holder or fail closed".
func DecideTemplate(in TemplateInput) (Placement, error) {
	order := make([]string, 0, len(in.Nodes))
	byID := make(map[string]NodeHolder, len(in.Nodes))
	for _, holder := range in.Nodes {
		if _, dup := byID[holder.Record.ID]; dup {
			continue
		}
		byID[holder.Record.ID] = holder
		order = append(order, holder.Record.ID)
	}
	sort.Strings(order)

	var whyNot []string
	for _, id := range order {
		holder := byID[id]
		holds := false
		for _, tid := range holder.Holds {
			if tid == in.TemplateID {
				holds = true
				break
			}
		}
		if !holds {
			whyNot = append(whyNot, fmt.Sprintf("%s: does not hold %s", id, in.TemplateID))
			continue
		}
		for _, face := range holder.Record.Runtimes {
			eval := Evaluate(in.Compat, face)
			if eval.Compatible {
				return Placement{
					NodeID:  holder.Record.ID,
					Address: holder.Record.Address,
					Runtime: face.Name,
				}, nil
			}
			whyNot = append(whyNot, fmt.Sprintf("%s/%s: %v", id, face.Name, eval.Reasons))
		}
	}
	return Placement{}, fmt.Errorf(
		"template %s has no compatible holder (%v)", in.TemplateID, whyNot)
}
