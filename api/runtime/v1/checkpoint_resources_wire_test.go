package v1

import (
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestResourceCheckpointWirePreservesOriginalGenerationAndRevision(t *testing.T) {
	request := &CheckpointIfResourcesRequest{Checkpoint: &CheckpointRequest{ID: "original", CheckpointID: "operation"}, ExpectedGeneration: "physical-generation", ExpectedRevision: 7}
	data, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CheckpointIfResourcesRequest
	if err = proto.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ExpectedGeneration != request.ExpectedGeneration || decoded.ExpectedRevision != 7 || decoded.Checkpoint.ID != "original" {
		t.Fatal("original resource condition lost on wire")
	}
	reply := &CheckpointResponse{Success: true, SourceGeneration: "physical-generation", SourceResourceRevision: 7}
	data, err = proto.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	var result CheckpointResponse
	if err = proto.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.SourceGeneration != reply.SourceGeneration || result.SourceResourceRevision != 7 {
		t.Fatal("captured resource condition lost in reply")
	}
	if SandboxService_CheckpointIfResources_FullMethodName == SandboxService_CheckpointIfGeneration_FullMethodName {
		t.Fatal("resource condition must use a separate RPC")
	}
}
