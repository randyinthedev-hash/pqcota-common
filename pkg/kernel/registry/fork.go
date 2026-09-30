// Package registry — 디스커버리 강화 단계가 쓰는 결정론적 시그니처 대조 데이터(수용 원칙 §2.3,
// 아키텍처 §3.3). 파생 규칙이므로
// 개선 시 원본에서 재계산되며 ruleset_version으로 고정된다(§1.2).
package registry

import (
	"regexp"
	"strings"
)

// ForkSignature — OpenSSL 계열 fork·version 판별 시그니처 (설계 §2.1, SD-3 IP).
// OpenSSL/BoringSSL/LibreSSL/AWS-LC가 같은 soname을 쓰는 문제(수용 원칙 §2.2)를
// 바이너리 문자열/심볼 시그니처로 가려낸다.
type ForkSignature struct {
	Fork     string   // "OpenSSL" | "BoringSSL" | "LibreSSL" | "AWS-LC"
	Contains []string // 이 중 하나라도 문자열에 나타나면 해당 fork로 판정
}

// DefaultForkSignatures — 초기 시드. OpenSSL을 마지막에 두어 fork 고유 마커를
// 먼저 매칭한다(BoringSSL/AWS-LC 바이너리도 "OpenSSL" 문자열을 포함할 수 있으므로).
// 커버 범위 확장은 디스커버리 설계 §8 열린 설계 질문(커뮤니티 기여 유인).
var DefaultForkSignatures = []ForkSignature{
	{Fork: "BoringSSL", Contains: []string{"BoringSSL"}},
	{Fork: "AWS-LC", Contains: []string{"AWS-LC", "aws-lc"}},
	{Fork: "LibreSSL", Contains: []string{"LibreSSL"}},
	{Fork: "OpenSSL", Contains: []string{"OpenSSL"}},
}

// ForkMatch — 매칭 결과. Matched=false면 Fork=""(unknown 명시, §2.5).
type ForkMatch struct {
	Fork    string
	Version string
	Matched bool
}

// bannerVersion — fork 이름 바로 뒤에 오는 버전만 추출한다("OpenSSL 3.0.15" → "3.0.15").
// 문자열 내 아무 숫자나 줍지 않도록(오탐 방지) needle 직후 패턴으로 국한.
func bannerVersion(s, needle string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(needle) + `[ /_-]?v?(\d+\.\d+(?:\.\d+[a-z]?)?)`)
	if m := re.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	return ""
}

// MatchFork — 바이너리에서 추출한 문자열/심볼 슬라이스에서 fork·version을 판별한다.
// 순수 함수 — ELF 추출(I/O)과 분리되어 실물 없이 단위 테스트 가능(설계 §2.1).
// 매칭 실패 시 Fork="", Matched=false (evidence_strength는 코어가 inferred-low로 부여).
func MatchFork(strs []string, sigs []ForkSignature) ForkMatch {
	for _, sig := range sigs {
		matched := false
		version := ""
		for _, needle := range sig.Contains {
			for _, s := range strs {
				if !strings.Contains(s, needle) {
					continue
				}
				matched = true
				// 버전은 fork 이름 바로 뒤(배너)에서만 취한다 — 아무 숫자나 줍지 않음.
				if version == "" {
					if v := bannerVersion(s, needle); v != "" {
						version = v
					}
				}
			}
		}
		if matched {
			return ForkMatch{Fork: sig.Fork, Version: version, Matched: true}
		}
	}
	return ForkMatch{Fork: "", Matched: false}
}
