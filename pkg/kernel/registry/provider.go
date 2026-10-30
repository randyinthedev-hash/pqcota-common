// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package registry

import "strings"

// ProviderSignature — JCA provider 시그니처 → 능력 (아키텍처 §3.3, SD-2).
// provider_set(관측)을 이 레지스트리와 대조해 pqc_readiness·fips·알고리즘 커버리지를 파생한다.
type ProviderSignature struct {
	Match          string   // provider JAR/모듈 시그니처(부분 문자열 매칭)
	Aliases        []string // 런타임 provider명(getProviders()의 name, 정확 일치). 예 BC·BCFIPS
	Nature         string   // pure-java | fips-native | jdk-builtin | jni-bridge | internal
	PQCAlgorithms  []string // 커버 알고리즘. JDK 네이티브는 SLH-DSA 없음(수용 원칙 §2.3)
	FipsValidation string   // "140-3" | "none" | "jdk-dependent" | "module-dependent"
	LicenseClass   string   // permissive(BC 표준) | fips-contract(BC-FJA) | gpl | internal
}

// DefaultProviderSignatures — 초기 시드(수용 원칙 §2.3 표). Match=JAR/모듈명, Aliases=런타임 provider명.
var DefaultProviderSignatures = []ProviderSignature{
	{Match: "bcprov-jdk18on", Aliases: []string{"BC"}, Nature: "pure-java", PQCAlgorithms: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, FipsValidation: "none", LicenseClass: "permissive"},
	{Match: "bc-fips", Aliases: []string{"BCFIPS", "BC-FJA"}, Nature: "fips-native", PQCAlgorithms: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, FipsValidation: "140-3", LicenseClass: "fips-contract"},
	{Match: "openssl-jostle", Aliases: []string{"JOSTLE"}, Nature: "jni-bridge", PQCAlgorithms: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, FipsValidation: "module-dependent", LicenseClass: "permissive"},
	// JDK 네이티브: ML-KEM은 SunJCE, ML-DSA는 SUN이 서비스한다(JEP 496·497). SLH-DSA는 없다(수용 원칙 §2.3).
	// SunEC는 EC 계열이라 둘 다 서비스하지 않는다.
	//
	// **이름과 판으로는 있는지 알 수 없다.** JDK 24부터 들어왔지만 21에도 백포트됐다 — 실측(2026-10-30,
	// Temurin)에서 21.0.11·21.0.12에는 없고 21.0.13에는 있었는데, provider 판은 셋 다 "21"이다.
	// 그래서 코어는 jdk-builtin 항목을 **서비스를 관측했을 때만** 센다(normalize.jcaEnrichment).
	{Aliases: []string{"SunJCE"}, Nature: "jdk-builtin", PQCAlgorithms: []string{"ML-KEM"}, FipsValidation: "jdk-dependent", LicenseClass: "permissive"},
	{Aliases: []string{"SUN"}, Nature: "jdk-builtin", PQCAlgorithms: []string{"ML-DSA"}, FipsValidation: "jdk-dependent", LicenseClass: "permissive"},
}

// MatchProvider — provider 식별자를 레지스트리와 대조. JAR명은 Match 부분문자열,
// 런타임 provider명(getProviders()의 name)은 Aliases 정확 일치. 미매칭 시 ok=false.
func MatchProvider(name string, sigs []ProviderSignature) (ProviderSignature, bool) {
	for _, sig := range sigs {
		if sig.Match != "" && strings.Contains(name, sig.Match) {
			return sig, true
		}
		for _, a := range sig.Aliases {
			if name == a {
				return sig, true
			}
		}
	}
	return ProviderSignature{}, false
}

// Covers — provider가 특정 PQC 알고리즘을 커버하는지.
func (p ProviderSignature) Covers(algo string) bool {
	for _, a := range p.PQCAlgorithms {
		if a == algo {
			return true
		}
	}
	return false
}

// SLHDSAGap — SLH-DSA가 필요한데 provider가 커버하지 못하면 true (수용 원칙 §2.3).
// 이 경우 JDK 버전 무관하게 BC/jostle 의존으로 태깅해야 한다.
func SLHDSAGap(p ProviderSignature) bool {
	return !p.Covers("SLH-DSA")
}
