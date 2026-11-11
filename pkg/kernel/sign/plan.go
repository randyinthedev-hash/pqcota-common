// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	provisioningv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/provisioning/v1"
)

// CanonicalPlan — 확정 계획의 승인 서명 대상 바이트(결정론적). `approval_signatures` **자신만** 뺀다.
//
// 왜 나머지 전부인가: [Canonical]과 같은 이유다. 덮이지 않는 필드는 변조해도 검증이 통과한다.
// 계획에서는 그 말이 더 무겁다 — 승인자는 계획의 이름에 도장을 찍는 것이 아니라 **조치의 내용**을
// 보고 책임을 진다. `target_algorithm` 한 줄이나 `activation.restart` 한 줄만 갈아 끼워도 노드에서
// 벌어지는 일이 달라진다.
//
// **조치의 순서도 덮는다.** ObservedEdge를 정렬하는 것과 반대다: 관측은 집합이지만 조치는 순서가
// 곧 의미이기 때문이다(plan.proto — "순서 의미 있음"). 순서를 바꾸는 것은 계획을 바꾸는 것이다.
//
// **status도 덮는다.** 그래야 DRAFT에 받은 승인을 FINALIZED로 바꿔 달고 들어올 수 없다.
//
// ★ 계약에 필드를 더하면 **여기도 함께 갱신**해야 한다. 잊으면 그 필드가 서명 사각지대가 된다 —
// `TestCanonicalPlanCoversAllFields`가 필드 수를 지켜보다 실패시킨다. 범위를 바꾸면 **기존 승인
// 서명은 전부 무효**가 된다.
func CanonicalPlan(p *provisioningv1.FinalizedPlan) []byte {
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte(0) }

	w(p.GetId())
	w(p.GetStatus().String())
	w(p.GetScope())
	w(p.GetDerivedFromSnapshotId())
	w(p.GetRulesetVersion())
	w(p.GetFinalizedAt().AsTime().UTC().Format(time.RFC3339Nano))
	for _, a := range p.GetActions() {
		actionCanon(w, a)
	}
	return []byte(b.String())
}

// actionCanon — 조치 한 건의 정규화. 필드마다 NUL로 끊어 붙인다 — `config_artifact`가 여러 줄
// 텍스트라 구분자를 문자로 두면 내용과 섞인다.
func actionCanon(w func(string), a *provisioningv1.RemediationAction) {
	w(a.GetId())
	w(a.GetTargetNodeId())
	w(a.GetFindingId())
	w(a.GetCryptoRuntime().String())
	w(a.GetKind().String())
	w(a.GetAutomationLevel().String())
	w(a.GetTargetAlgorithm())
	w(a.GetProviderChoice())
	w(a.GetConfigArtifact())
	w(a.GetRollbackNote())
	w(strconv.Itoa(int(a.GetPriority())))
	w(a.GetProviderClass())

	h := a.GetActivation()
	w(h.GetPre())
	w(h.GetActivate())
	w(h.GetDeactivate())
	w(h.GetRestart())
	// 근거들 — **순서대로** 덮는다. 주 근거가 앞이라 순서가 뜻이다. 덮지 않으면 참조를 서명 뒤에
	// 바꿔 넣을 수 있어 「되짚을 수 있다」가 보장이 아니게 된다. 빈 목록도 자리 하나(길이 0)를
	// 차지하므로, 근거가 없던 옛 계획의 정규형은 이 필드가 생기기 전과 같지 않다 — 기존 승인이
	// 전부 무효가 되는 이유다(릴리스 노트 v0.9.0).
	//
	// 소스 근거(source_evidence)는 **같은 개수 자리**에 함께 적는다. 비어 있으면 그 자리는 지금처럼 숫자 하나라
	// 옛 계획의 정규형이 한 바이트도 바뀌지 않는다(plan_golden_test.go). 있으면 "N+M"으로 적고 런타임 근거 N개
	// 다음에 소스 근거 M개를 적는다. 그 자리에는 지금 strconv.Itoa의 숫자만 오므로 「+」가 든 값과 겹치지 않고,
	// 소스 근거는 필드 넷으로 고정이라 조치 하나가 여전히 스스로 끝을 안다 — 다음 조치의 id와 섞이지 않는다.
	// 표지 문자열을 조치 끝에 덧붙이지 않는 이유: NUL 말고는 어떤 문자열도 다음 조치의 id가 될 수 있다.
	// 소스 근거가 이 조치의 정규형 안에 있으므로, 다른 조치로 옮기면 바이트가 달라진다.
	//
	// 가이드(guide)가 있으면 같은 자리를 "N+M+1"로 한 번 더 넓히고(M은 0일 수 있다) 소스 근거 다음에 가이드 하나를
	// 적는다. 지금 그 자리에 오는 값은 "N"과 "N+M"뿐이라 겹치지 않는다. 가이드의 반복 필드는 개수를 앞에 적는다.
	count := strconv.Itoa(len(a.GetEvidenceSources()))
	g := a.GetGuide()
	switch {
	case g != nil:
		count += "+" + strconv.Itoa(len(a.GetSourceEvidence())) + "+1"
	case len(a.GetSourceEvidence()) > 0:
		count += "+" + strconv.Itoa(len(a.GetSourceEvidence()))
	}
	w(count)
	for _, e := range a.GetEvidenceSources() {
		w(e.GetFindingId())
		r := e.GetSnapshot()
		w(r.GetSourceNodeId())
		switch ref := r.GetReference().(type) {
		case *provisioningv1.SnapshotReference_SnapshotId:
			w("id")
			w(ref.SnapshotId)
		case *provisioningv1.SnapshotReference_Content:
			w("content")
			w(ref.Content.GetFormatVersion())
			w(ref.Content.GetDigest())
			w(ref.Content.GetRulesetVersion())
		default:
			w("none")
		}
	}
	for _, r := range a.GetSourceEvidence() {
		w(r.GetInterpretationId())
		w(r.GetItemId())
		w(r.GetLocationId())
		w(r.GetInputSha256())
	}
	if g != nil {
		w(g.GetGuideId())
		w(g.GetRevision())
		w(g.GetBodySha256())
		w(g.GetManifestSha256())
		w(g.GetPurpose())
		w(strconv.Itoa(len(g.GetConditions())))
		for _, c := range g.GetConditions() {
			w(c)
		}
		w(g.GetRationale())
		w(strconv.Itoa(len(g.GetEvidenceSourceIndexes())))
		for _, i := range g.GetEvidenceSourceIndexes() {
			w(strconv.FormatUint(uint64(i), 10))
		}
		w(strconv.Itoa(len(g.GetSourceEvidenceIndexes())))
		for _, i := range g.GetSourceEvidenceIndexes() {
			w(strconv.FormatUint(uint64(i), 10))
		}
	}
}

// SignApproval — priv(base64)로 계획을 승인 서명한다. 반환값을 `approval_signatures`에 덧붙인다.
//
// 꼴은 `"<승인자>:ed25519:<base64>"`다. 승인자 id를 **서명 문자열 안에** 두는 이유는 검증할 때
// 그 사람의 키로만 확인하기 위해서다([VerifyApprovals]). id가 밖에 있으면 서명과 이름이 따로
// 놀아, 이름만 바꿔 다는 것을 막을 수 없다.
func SignApproval(privB64, approver string, p *provisioningv1.FinalizedPlan) (string, error) {
	approver = strings.TrimSpace(approver)
	if approver == "" || strings.Contains(approver, ":") {
		return "", fmt.Errorf("the approver id must be non-empty and must not contain ':' (got %q)", approver)
	}
	sk, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("decoding the private key: %w", err)
	}
	if len(sk) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("the private key is %d bytes, which is not an ed25519 private key (%d)", len(sk), ed25519.PrivateKeySize)
	}
	// 정규형이 모호한 계획에는 서명하지 않는다 — 그 서명은 다른 계획에서도 통과한다([CheckPlanText]).
	if err := CheckPlanText(p); err != nil {
		return "", err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(sk), CanonicalPlan(p))
	return approver + ":" + Prefix + base64.StdEncoding.EncodeToString(sig), nil
}

// RejectedApproval — 서명 꼴이긴 한데 확인에 실패한 승인 하나. 왜 실패했는지 함께 든다 —
// 사유를 말하지 않고 거절하면 승인자가 무엇을 고쳐야 하는지 알 수 없다.
type RejectedApproval struct {
	Approver string
	Reason   string
}

func (r RejectedApproval) String() string { return r.Approver + " (" + r.Reason + ")" }

// ApprovalCheck — 승인 서명을 셋으로 가른 결과.
//
// **통과·거부 둘로 가르지 않는다.** 확인하지 못한 것과 틀린 것은 다르고, 둘을 같은 칸에 두면
// "확인하지 않음"이 "확인함"처럼 보인다(§2.6 — 제외는 부재가 아니다). 적재 쪽이 서명거부와
// 미검증을 따로 세는 것과 같은 이유다.
type ApprovalCheck struct {
	Approved     []string           // 등록된 그 승인자의 키로 확인된 서명. 승인자 id
	Rejected     []RejectedApproval // 서명 꼴인데 확인에 실패한 것
	Unverifiable []string           // 서명 꼴이 아닌 것. 이름표일 뿐 아무것도 증명하지 않는다
}

// VerifyApprovals — 승인 서명이 **누구의 것인지**까지 확인한다(§3.3③ finalize 전제).
//
// keys는 승인자 id → base64 공개키. [VerifyFrom]과 같은 이유로 키 **목록**이 아니라 **묶음**을
// 받는다: 목록을 받으면 어느 키로든 통과한 서명이 아무 승인자 이름이나 달고 들어올 수 있고,
// 그러면 서명은 "누군가 승인했다"까지만 답한다. 승인은 책임의 소재라 그 답으로는 부족하다.
//
// 등록된 키가 없는 승인자는 거절한다 — 모르는 사람의 승인을 받지 않는다.
//
// GATE: 배선 필수
func VerifyApprovals(keys map[string]string, p *provisioningv1.FinalizedPlan) ApprovalCheck {
	var out ApprovalCheck
	// 정규형이 모호한 계획에서는 어떤 서명도 이 계획의 승인이라고 말할 수 없다. 서명이 맞더라도 다른
	// 계획에 한 것일 수 있다. 그래서 승인 항목을 모두 거부로 돌리고, 승인됨은 하나도 남기지 않는다.
	if err := CheckPlanText(p); err != nil {
		for _, raw := range p.GetApprovalSignatures() {
			approver := strings.TrimSpace(raw)
			if a, _, ok := splitApproval(approver); ok {
				approver = a
			}
			out.Rejected = append(out.Rejected, RejectedApproval{approver, err.Error()})
		}
		if len(out.Rejected) == 0 {
			out.Rejected = append(out.Rejected, RejectedApproval{"(none)", err.Error()})
		}
		return out
	}
	msg := CanonicalPlan(p)
	for _, raw := range p.GetApprovalSignatures() {
		s := strings.TrimSpace(raw)
		approver, sig, ok := splitApproval(s)
		if !ok {
			out.Unverifiable = append(out.Unverifiable, s)
			continue
		}
		pub, registered := keys[approver]
		switch {
		case !registered:
			out.Rejected = append(out.Rejected, RejectedApproval{approver, "no key is registered for this approver"})
		case !verifySig(pub, msg, sig):
			out.Rejected = append(out.Rejected, RejectedApproval{approver, "the signature does not match this plan"})
		default:
			out.Approved = append(out.Approved, approver)
		}
	}
	return out
}

// splitApproval — `"<승인자>:ed25519:<base64>"`를 가른다. 그 꼴이 아니면 ok=false.
func splitApproval(s string) (approver, sig string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	approver, rest := s[:i], s[i+1:]
	if !strings.HasPrefix(rest, Prefix) {
		return "", "", false
	}
	return approver, rest, true
}

func verifySig(pubB64 string, msg []byte, sig string) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, Prefix))
	if err != nil {
		return false
	}
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), msg, raw)
}

// ParseKeyMap — `"<id>=<base64 공개키>"`를 콤마로 이은 환경변수 값을 묶음으로 읽는다.
//
// **이 꼴을 쓰는 이유**가 곧 PQCOTA_VERIFY_KEY의 교훈이다. 그쪽은 키만 나열해서 어느 키가
// 누구 것인지 말하지 않고, 그래서 collector에 묶을 수 없어 [VerifyFrom]의 배선이 아직 보류다.
// 승인 쪽은 처음부터 id를 함께 받는다.
func ParseKeyMap(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		id, key, found := strings.Cut(pair, "=")
		id, key = strings.TrimSpace(id), strings.TrimSpace(key)
		if !found || id == "" || key == "" {
			return nil, fmt.Errorf("%q is not in <id>=<base64 public key> form", pair)
		}
		if _, dup := out[id]; dup {
			// 같은 id에 키가 둘이면 어느 것이 그 사람의 키인지 말할 수 없다. 알리지 않고 덮어쓰면
			// 어느 쪽이 남았는지 모른 채 검증이 돈다.
			return nil, fmt.Errorf("%q appears twice — one id must have one key", id)
		}
		out[id] = key
	}
	return out, nil
}
