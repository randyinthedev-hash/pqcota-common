package registry_test

import (
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

func TestMatchPQC(t *testing.T) {
	cases := []struct {
		name       string
		wantFamily string
		wantMat    registry.PQCMaturity
		wantOK     bool
	}{
		{"X25519MLKEM768", "ML-KEM", registry.MaturityFIPS, true},                                 // 하이브리드 TLS 그룹(표준)
		{"ML-DSA-65", "ML-DSA", registry.MaturityFIPS, true},                                      // 서명 표준
		{"SLH-DSA-SHA2-128s", "SLH-DSA", registry.MaturityFIPS, true},                             // 표준
		{"X25519Kyber768Draft00", "Kyber", registry.MaturityDraft, true},                          // 전신(초안)
		{"sntrup761x25519-sha512@openssh.com", "NTRU-Prime", registry.MaturityExperimental, true}, // OpenSSH
		{"falcon512", "Falcon", registry.MaturityDraft, true},
		{"frodokem976aes", "FrodoKEM", registry.MaturityExperimental, true},
		{"rainbowIclassic", "Rainbow", registry.MaturityBroken, true},
		{"x25519", "", "", false},    // 고전 → 매칭 없음
		{"ECDHE-RSA", "", "", false}, // 고전
		{"", "", "", false},          // 빈 문자열
	}
	for _, c := range cases {
		a, ok := registry.MatchPQC(c.name)
		if ok != c.wantOK {
			t.Errorf("MatchPQC(%q) ok=%v, want %v", c.name, ok, c.wantOK)
			continue
		}
		if ok && (a.Family != c.wantFamily || a.Maturity != c.wantMat) {
			t.Errorf("MatchPQC(%q) = %s/%s, want %s/%s", c.name, a.Family, a.Maturity, c.wantFamily, c.wantMat)
		}
	}
}

// FIPSValidatable — 최종 표준만 true (규제 자산 라우팅 게이트).
func TestFIPSValidatable(t *testing.T) {
	mlkem, _ := registry.MatchPQC("MLKEM768")
	if !mlkem.FIPSValidatable() {
		t.Error("ML-KEM must be FIPS-validatable")
	}
	falcon, _ := registry.MatchPQC("falcon1024")
	if falcon.FIPSValidatable() {
		t.Error("Falcon (draft) must not be FIPS-validatable")
	}
	sntrup, _ := registry.MatchPQC("sntrup761")
	if sntrup.FIPSValidatable() {
		t.Error("sntrup (experimental) must not be FIPS-validatable")
	}
}

// Kind: KEM vs signature 구분.
func TestPQCKind(t *testing.T) {
	if a, _ := registry.MatchPQC("MLKEM768"); a.Kind != registry.KindKEM {
		t.Errorf("ML-KEM must be a KEM, got %s", a.Kind)
	}
	if a, _ := registry.MatchPQC("MLDSA65"); a.Kind != registry.KindSignature {
		t.Errorf("ML-DSA must be a signature, got %s", a.Kind)
	}
}
