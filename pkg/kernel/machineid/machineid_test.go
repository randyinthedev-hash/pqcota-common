package machineid_test

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/machineid"
)

// SelfAssign은 결정론적(같은 지문→같은 id)이고 우선순위를 지킨다.
func TestSelfAssign(t *testing.T) {
	fp := &commonv1.MachineIdentity{MachineId: "abc-123", Fqdn: "web-01"}
	id1, src1 := machineid.SelfAssign(fp)
	id2, _ := machineid.SelfAssign(fp)
	if id1 == "" || id1 != id2 {
		t.Fatalf("not deterministic: %q vs %q", id1, id2)
	}
	if src1 != "machine-id" { // fqdn보다 우선
		t.Errorf("wrong priority: %s (must be machine-id)", src1)
	}

	// cloud-instance-id가 최우선
	fp.CloudInstanceId = "i-0999"
	if _, src := machineid.SelfAssign(fp); src != "cloud-instance-id" {
		t.Errorf("cloud did not take priority: %s", src)
	}

	// 다른 머신 → 다른 id
	other, _ := machineid.SelfAssign(&commonv1.MachineIdentity{MachineId: "xyz-789"})
	base, _ := machineid.SelfAssign(&commonv1.MachineIdentity{MachineId: "abc-123"})
	if other == base {
		t.Error("different machine-ids produced the same id")
	}

	// 지문 없음 → 빈 값
	if id, _ := machineid.SelfAssign(&commonv1.MachineIdentity{}); id != "" {
		t.Errorf("with no fingerprint the id must be empty: %q", id)
	}

	// 네임스페이스 접두
	if len(id1) < 6 || id1[:5] != "node:" {
		t.Errorf("the node: prefix is missing: %q", id1)
	}
}
