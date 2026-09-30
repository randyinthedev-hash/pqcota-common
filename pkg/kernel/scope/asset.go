package scope

import (
	"encoding/csv"
	"fmt"
	"io"
	"path"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// 자산 스코프 (인벤토리 설계 §8) — 노드 게이트(§1.4)를 **자산 단위로** 넓힌 것.
//
// 노드를 등재해도 그 안에서 관측되는 것 전부가 관리 대상은 아니다. 시스템 기본 라이브러리,
// 패키지 매니저가 딸려 넣은 런타임, 일회성 프로세스 따위가 섞이면 인벤토리가 잡음에 묻혀
// 못 쓰게 된다. 무엇을 계속 볼지는 **사용자가 선언**하고, 도구는 그 선언을 집행한다(§1.1 —
// 판단은 마에스트로, 집행은 단원).
//
// ★ 제외는 "없음"이 아니다. 정책으로 뺀 자산을 표시 없이 사라지게 하면 인벤토리는 "그런 게
// 없다"고 거짓말한다 — §2.6이 금지하는 바로 그것이다. 그래서 Apply는 제외분을 **세어서
// 돌려주고**, 스냅샷·뷰가 "정책 제외 N건"으로 고지한다.

// AssetRule — 자산 한 부류를 가리키는 규칙. 빈 칸은 "*"(모두)와 같다.
// 패턴은 glob(path.Match) — `libcrypto.so.*`, `/usr/bin/python*`처럼 쓴다.
type AssetRule struct {
	Exclude bool   // false면 include(제외를 되돌리는 예외)
	Runtime string // openssl | jca | * — Finding.crypto_runtime
	Lib     string // 자산 이름 glob (openssl은 lib, jca는 provider 이름)
	AppKey  string // 쓰는 앱 glob. 하나라도 맞으면 매치
	Note    string // 왜 이 규칙을 뒀는지(사람용, 판정에 영향 없음)
}

// AssetPolicy — 자산 스코프 정책. 규칙이 없으면 **전부 관리 대상**이다(기본 포함).
//
// 판정 순서: 기본 포함 → 규칙을 **순서대로** 적용, **뒤 규칙이 우선한다**(매치되는 마지막 규칙이
// 결정). 그래서 include를 exclude "뒤에" 두면 "이 계열은 전부 빼되 이것만 예외"가 된다 — 무조건
// 우선이 아니라 순서 기반이다(include를 앞에 두면 뒤의 exclude가 우선한다).
//
// ★ 공유 .so 주의: 쓰는 앱이 여럿이라(§1.5) 한 앱만 겨냥해 exclude해도 그 .so를 함께 쓰는
// 다른 앱 자산까지 빠진다(matches가 app_key 하나만 맞아도 참). 운영 앱을 지키려면 그 앱을
// 되살리는 include를 exclude 뒤에 둔다.
type AssetPolicy struct {
	Rules []AssetRule
}

// Managed — 이 finding을 계속 관리(수집·적재)할 대상으로 볼지.
func (p *AssetPolicy) Managed(f *discoveryv1.Finding) bool {
	if p == nil || len(p.Rules) == 0 {
		return true
	}
	managed := true
	for _, r := range p.Rules {
		if !r.matches(f) {
			continue
		}
		managed = !r.Exclude // exclude면 false, include면 true(뒤 규칙이 우선한다)
	}
	return managed
}

// Apply — findings를 관리 대상만 남기고 거른다. 제외분은 **버리지 않고 세어서** 돌려준다
// (호출자가 "정책 제외 N건"으로 고지해야 한다 — 제외 ≠ 부재).
func (p *AssetPolicy) Apply(fs []*discoveryv1.Finding) (kept []*discoveryv1.Finding, excluded int) {
	if p == nil || len(p.Rules) == 0 {
		return fs, 0
	}
	for _, f := range fs {
		if p.Managed(f) {
			kept = append(kept, f)
		} else {
			excluded++
		}
	}
	return kept, excluded
}

func (r AssetRule) matches(f *discoveryv1.Finding) bool {
	if !globOK(r.Runtime, runtimeName(f.GetCryptoRuntime())) {
		return false
	}
	if !globOK(r.Lib, assetName(f)) {
		return false
	}
	if star(r.AppKey) {
		return true
	}
	for _, ak := range f.GetAppKeys() {
		if globOK(r.AppKey, ak) {
			return true
		}
	}
	return false
}

// assetName — 규칙이 가리키는 "자산 이름". openssl은 라이브러리 soname, jca는 provider 목록
// (하나라도 맞으면 매치되도록 호출부에서 합쳐 쓴다).
func assetName(f *discoveryv1.Finding) string {
	if o := f.GetOpenssl(); o != nil {
		return o.GetLib()
	}
	if j := f.GetJca(); j != nil {
		return strings.Join(j.GetProviderSet(), ",")
	}
	return ""
}

func runtimeName(r commonv1.CryptoRuntime) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "CRYPTO_RUNTIME_"))
}

func star(pattern string) bool { return pattern == "" || pattern == "*" }

// globOK — 빈 칸·"*"는 모두 매치. jca provider_set처럼 콤마로 합쳐진 값은 원소별로도 본다.
func globOK(pattern, value string) bool {
	if star(pattern) {
		return true
	}
	if ok, _ := path.Match(pattern, value); ok {
		return true
	}
	for _, part := range strings.Split(value, ",") {
		if ok, _ := path.Match(pattern, strings.TrimSpace(part)); ok {
			return true
		}
	}
	return false
}

// LoadAssetPolicy — CSV로 정책을 읽는다. 헤더: action,runtime,lib,app_key,note
//
//	exclude,openssl,libcrypto.so.*,/usr/bin/python*,python 런타임 — 관리 대상 아님
//	exclude,*,*,/usr/sbin/sshd,sshd는 OS 패치로 관리
//	include,openssl,libssl.so.3,*,결제 게이트웨이 — 위 제외의 예외
func LoadAssetPolicy(r io.Reader) (*AssetPolicy, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("asset scope CSV: %w", err)
	}
	p := &AssetPolicy{}
	for i, row := range rows {
		if len(row) == 0 || strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(row[0]))
		if i == 0 && action == "action" {
			continue // 헤더
		}
		var rule AssetRule
		switch action {
		case "exclude":
			rule.Exclude = true
		case "include":
		case "":
			continue
		default:
			return nil, fmt.Errorf("asset scope row %d: action must be exclude|include (got %q)", i+1, row[0])
		}
		get := func(n int) string {
			if n < len(row) {
				return strings.TrimSpace(row[n])
			}
			return ""
		}
		rule.Runtime, rule.Lib, rule.AppKey, rule.Note = get(1), get(2), get(3), get(4)
		p.Rules = append(p.Rules, rule)
	}
	return p, nil
}
