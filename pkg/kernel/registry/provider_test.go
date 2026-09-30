package registry_test

import (
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

// TD-JVM-1 (testcases.md §2). provider 레지스트리 매핑.
func TestMatchProvider(t *testing.T) {
	sigs := registry.DefaultProviderSignatures

	t.Run("bcprov-jdk18on → ML-KEM/ML-DSA/SLH-DSA, fips=none", func(t *testing.T) {
		p, ok := registry.MatchProvider("bcprov-jdk18on-1.79.jar", sigs)
		if !ok {
			t.Fatal("expected match for bcprov-jdk18on")
		}
		for _, algo := range []string{"ML-KEM", "ML-DSA", "SLH-DSA"} {
			if !p.Covers(algo) {
				t.Errorf("expected coverage of %s", algo)
			}
		}
		if p.FipsValidation != "none" {
			t.Errorf("fips = %q, want none", p.FipsValidation)
		}
		if registry.SLHDSAGap(p) {
			t.Error("bcprov should NOT have SLH-DSA gap")
		}
	})

	t.Run("JDK-native (SunJCE) → tagged with the SLH-DSA gap", func(t *testing.T) {
		p, ok := registry.MatchProvider("SunJCE", sigs)
		if !ok {
			t.Fatal("expected match for SunJCE")
		}
		if !registry.SLHDSAGap(p) {
			t.Error("JDK-native must be flagged with SLH-DSA gap (acceptance principle §2.3)")
		}
		if p.Covers("SLH-DSA") {
			t.Error("JDK-native must not cover SLH-DSA")
		}
	})

	t.Run("an unregistered provider → no match", func(t *testing.T) {
		if _, ok := registry.MatchProvider("unknown-provider", sigs); ok {
			t.Error("unexpected match")
		}
	})
}
