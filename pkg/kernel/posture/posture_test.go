package posture_test

import (
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

// Grade — PQC 그룹의 표준화 성숙도 축 (PQC vs 고전 위에 표준 vs 실험).
func TestGrade(t *testing.T) {
	cases := map[string]registry.PQCMaturity{
		"X25519MLKEM768":         registry.MaturityFIPS,         // 표준 하이브리드
		"sntrup761x25519-sha512": registry.MaturityExperimental, // OpenSSH
		"X25519Kyber768Draft00":  registry.MaturityDraft,        // 전신
		"x25519":                 "",                            // 고전 → N/A
		"":                       "",                            // 불명
	}
	for group, want := range cases {
		if got := posture.Grade(group); got != want {
			t.Errorf("Grade(%q) = %q, want %q", group, got, want)
		}
	}
	if posture.GradeLabel(registry.MaturityFIPS) != "fips-standard" || posture.GradeLabel("") != "" {
		t.Error("GradeLabel mapping is wrong")
	}
}

// Recommend — 엣지 전체 remediation 분기(PQC 성숙도 + 고전 + 미관측).
func TestRecommend(t *testing.T) {
	cases := []struct {
		group     string
		regulated bool
		wantAct   registry.RemediationAction
	}{
		{"X25519MLKEM768", false, registry.ActionNone},            // 표준 PQC
		{"X25519Kyber768Draft00", false, registry.ActionUpgrade},  // 초안 PQC
		{"sntrup761x25519-sha512", false, registry.ActionReplace}, // 실험 PQC
		{"x25519", false, registry.ActionMigrate},                 // 고전 → 마이그레이션
		{"", false, registry.ActionNone},                          // 미관측 → 보류
	}
	for _, c := range cases {
		if got := posture.Recommend(c.group, "", c.regulated).Action; got != c.wantAct {
			t.Errorf("Recommend(%q) = %s, want %s", c.group, got, c.wantAct)
		}
	}
	// 규제 자산의 고전 협상은 최우선(4).
	if p := posture.Recommend("ECDHE-RSA", "", true).Priority; p != 4 {
		t.Errorf("regulated + classical priority = %d, want 4", p)
	}
}

func TestClassify(t *testing.T) {
	pqc := discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID
	classical := discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL
	unknown := discoveryv1.QuantumPosture_QUANTUM_POSTURE_UNSPECIFIED

	cases := []struct {
		group string
		want  discoveryv1.QuantumPosture
	}{
		{"X25519MLKEM768", pqc},         // 하이브리드 🟢
		{"mlkem768", pqc},               // 순수 PQC 🟢
		{"sntrup761x25519-sha512", pqc}, // OpenSSH 하이브리드 🟢
		{"X25519", classical},           // 고전 🔴
		{"ECDHE-RSA", classical},        // 고전 🔴
		{"secp256r1", classical},        // 고전 🔴
		{"", unknown},                   // 미관측 ⚪ (고전으로 단정 금지)
		{"some-future-group", unknown},  // 미지 ⚪
	}
	for _, c := range cases {
		if got := posture.Classify(c.group, ""); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.group, got, c.want)
		}
	}
}

func TestSymbol(t *testing.T) {
	if posture.Symbol(discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID) != "🟢" {
		t.Error("PQC → 🟢")
	}
	if posture.Symbol(discoveryv1.QuantumPosture_QUANTUM_POSTURE_UNSPECIFIED) != "⚪" {
		t.Error("unknown must map to ⚪")
	}
}
