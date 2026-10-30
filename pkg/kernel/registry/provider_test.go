// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package registry_test

import (
	"testing"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

// TD-JVM-1. provider 레지스트리 매핑.
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

	// JDK 기본 제공은 provider마다 서비스하는 알고리즘이 다르다(JDK 24 실측: SunJCE=ML-KEM, SUN=ML-DSA).
	// 기본 체인에서는 셋이 함께 있어 체인 전체의 답이 같아 보여도, provider 하나의 답은 따로 맞아야 한다.
	t.Run("JDK-native: SunJCE serves ML-KEM, SUN serves ML-DSA", func(t *testing.T) {
		cases := []struct {
			name, covers, notCovers string
		}{
			{"SunJCE", "ML-KEM", "ML-DSA"},
			{"SUN", "ML-DSA", "ML-KEM"},
		}
		for _, c := range cases {
			p, ok := registry.MatchProvider(c.name, sigs)
			if !ok {
				t.Fatalf("expected match for %s", c.name)
			}
			if p.Nature != "jdk-builtin" {
				t.Errorf("%s nature = %q, want jdk-builtin", c.name, p.Nature)
			}
			if !p.Covers(c.covers) || p.Covers(c.notCovers) {
				t.Errorf("%s should cover %s and not %s: %v", c.name, c.covers, c.notCovers, p.PQCAlgorithms)
			}
			if !registry.SLHDSAGap(p) {
				t.Errorf("%s must be flagged with the SLH-DSA gap (acceptance principle §2.3)", c.name)
			}
		}
	})

	t.Run("SunEC serves neither ML-KEM nor ML-DSA → no match", func(t *testing.T) {
		if p, ok := registry.MatchProvider("SunEC", sigs); ok {
			t.Errorf("SunEC matched %+v; it is the EC provider", p)
		}
	})

	t.Run("an unregistered provider → no match", func(t *testing.T) {
		if _, ok := registry.MatchProvider("unknown-provider", sigs); ok {
			t.Error("unexpected match")
		}
	})
}
