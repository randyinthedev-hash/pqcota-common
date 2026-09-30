package registry_test

import (
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

func TestRemediate(t *testing.T) {
	cases := []struct {
		name      string
		regulated bool
		wantAct   registry.RemediationAction
		wantPrio  int
	}{
		{"X25519MLKEM768", false, registry.ActionNone, 0},            // 표준 → 불요
		{"X25519MLKEM768", true, registry.ActionNone, 1},             // 표준+규제 → FIPS provider 확인
		{"X25519Kyber768Draft00", false, registry.ActionUpgrade, 2},  // 초안 → 상향
		{"sntrup761x25519-sha512", false, registry.ActionReplace, 3}, // 실험 → 교체
		{"rainbowIclassic", false, registry.ActionReplace, 4},        // 파훼 → 즉시
	}
	for _, c := range cases {
		a, ok := registry.MatchPQC(c.name)
		if !ok {
			t.Fatalf("MatchPQC(%q) failed", c.name)
		}
		r := a.Remediate(c.regulated)
		if r.Action != c.wantAct || r.Priority != c.wantPrio {
			t.Errorf("Remediate(%q, reg=%v) = %s/p%d, want %s/p%d",
				c.name, c.regulated, r.Action, r.Priority, c.wantAct, c.wantPrio)
		}
	}
}

// 서명 알고리즘은 ML-DSA를 목표로, KEM은 ML-KEM을 목표로.
func TestRemediateTarget(t *testing.T) {
	kem, _ := registry.MatchPQC("Kyber768")
	if kem.Remediate(false).Target != "ML-KEM (FIPS 203)" {
		t.Errorf("wrong KEM target: %s", kem.Remediate(false).Target)
	}
	sig, _ := registry.MatchPQC("dilithium3")
	if sig.Remediate(false).Target != "ML-DSA (FIPS 204)" {
		t.Errorf("wrong signature target: %s", sig.Remediate(false).Target)
	}
}
