package runtime

import (
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

// Requested mounts must replace same-destination base-spec mounts instead of
// duplicating them; duplicate destinations break runsc's restore spec
// validation (the chart ociConfig resolv.conf + managed-DNS double mount).
func TestSupersedeBaseMounts(t *testing.T) {
	base := []Mount{
		{Destination: "/etc/resolv.conf", Source: "/etc/resolv_akernel.conf"},
		{Destination: "/etc/hosts", Source: "/etc/base-hosts"},
	}
	requested := []*runtime.Mount{
		{Target: "/etc/resolv.conf", Type: "bind",
			Source: &runtime.Mount_HostPath{HostPath: "/sandbox-files/resolv.conf"}},
	}
	got := supersedeBaseMounts(base, requested)
	if len(got) != 1 || got[0].Destination != "/etc/hosts" {
		t.Fatalf("superseded base mounts = %+v, want only /etc/hosts", got)
	}
}

func TestSupersedeBaseMountsNoRequestsKeepsBase(t *testing.T) {
	base := []Mount{{Destination: "/a"}}
	if got := supersedeBaseMounts(base, nil); len(got) != 1 || got[0].Destination != "/a" {
		t.Fatalf("got %+v, want base untouched", got)
	}
}

func TestSupersedeBaseMountsNoOverlapKeepsBase(t *testing.T) {
	base := []Mount{{Destination: "/a"}}
	requested := []*runtime.Mount{{Target: "/b"}}
	got := supersedeBaseMounts(base, requested)
	if len(got) != 1 || got[0].Destination != "/a" {
		t.Fatalf("got %+v, want base untouched when destinations do not overlap", got)
	}
}
