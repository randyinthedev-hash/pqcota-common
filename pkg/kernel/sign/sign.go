// Package sign — collector 리포트 서명·검증 (규정서 §2.6 — provenance).
// ed25519로 CollectionResult를 서명하고, 중앙 적재가 등록된 공개키로 검증한다.
// 전송 보안(mTLS/SSH)이 없는 경로(T1 self-service·에어갭)에서 페이로드 신뢰의 앵커가 된다.
package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// Prefix — 서명 문자열 접두어. envelope.signature = "ed25519:<base64>".
const Prefix = "ed25519:"

// Generate — 새 ed25519 키쌍(base64). priv로 서명(collector), pub로 검증(중앙).
func Generate() (pub, priv string, err error) {
	pk, sk, err := ed25519.GenerateKey(nil) // nil → crypto/rand
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pk), base64.StdEncoding.EncodeToString(sk), nil
}

// Canonical — CollectionResult의 서명 대상 바이트(결정론적). **collector가 주장한 내용 전부**를
// 덮는다 — 서명 필드(envelope.signature) 자신만 뺀다.
//
// 왜 전부인가: 덮이지 않는 필드는 **변조해도 검증이 통과**한다. 특히 `completeness`가 빠지면
// 갭 선언을 떼어내 "원리상 관측하지 못했다"를 "없다"로 바꾸는 변조가 통과하는데(§2.6 정직성의 심장),
// `raw_capture`가 빠지면 §1.2 재계산의 원본이 무보장이 된다. 좁게 덮는 서명은 "서명했다"는
// 말을 실제보다 강하게 들리게 만든다.
//
// ★ 계약(contracts)에 필드를 더하면 **여기도 함께 갱신**해야 한다. 잊으면 그 필드가 서명
// 사각지대가 된다 — `TestCanonicalCoversAllFields`가 필드 수를 지켜보다 실패시킨다.
// 범위를 바꾸면 **기존 서명은 전부 무효**가 되므로, 릴리스 후에는 마이그레이션이 필요하다.
func Canonical(res *discoveryv1.CollectionResult) []byte {
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte(0) }
	wb := func(p []byte) { b.Write(p); b.WriteByte(0) }

	env := res.GetEnvelope()
	w(env.GetCollectorId())
	w(env.GetCollectorVersion())
	w(env.GetDetectionMethod().String()) // evidence_strength 파생의 근거 — 바뀌면 판정이 바뀐다
	w(env.GetCollectedAt().AsTime().UTC().Format(time.RFC3339Nano))
	w(env.GetTargetNodeId()) // 스코프 앵커(§1.4)
	w(env.GetScopeMasterRef())
	w(env.GetCollectorLicense())
	w(machineCanon(env.GetMachine())) // 머신 지문 — node_id 잇기·중복 검출의 근거

	w(res.GetRawFormat())
	w(res.GetCyclonedxSpecVersion())
	wb(res.GetCbomCyclonedx())
	wb(res.GetRawCapture()) // §1.2 재계산의 원본
	w(completenessCanon(res.GetCompleteness()))

	edges := make([]string, 0, len(res.GetObservedEdges()))
	for _, e := range res.GetObservedEdges() {
		edges = append(edges, edgeCanon(e))
	}
	sort.Strings(edges) // 순서 무관 — 같은 관측 집합이면 같은 바이트
	b.WriteString(strings.Join(edges, "\n"))
	return []byte(b.String())
}

// completenessCanon — 완전성 맵의 정규화 형태. 계층 목록은 정렬해 순서 흔들림을 없앤다.
func completenessCanon(c *commonv1.Completeness) string {
	if c == nil {
		return ""
	}
	return layersCanon(c.GetLayersCovered()) + "|" + layersCanon(c.GetLayersMissing()) + "|" + c.GetNote()
}

func layersCanon(ls []commonv1.CollectionLayer) string {
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.String())
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func machineCanon(m *commonv1.MachineIdentity) string {
	if m == nil {
		return ""
	}
	ips := append([]string(nil), m.GetIps()...)
	sort.Strings(ips)
	return strings.Join([]string{
		m.GetMachineId(), m.GetHardwareUuid(), m.GetCloudInstanceId(), m.GetFqdn(),
		strings.Join(ips, ","), m.GetSelfAssignedId(), m.GetDerivedFrom(),
	}, "|")
}

func edgeCanon(e *discoveryv1.ObservedEdge) string {
	return fmt.Sprintf("%s>%s@%s:%d/%s/%s/%s/%s/%s/%d/%s/%s/%s/%s",
		e.GetSrcNodeId(), e.GetDstNodeId(), e.GetDstAddr(), e.GetPort(),
		e.GetProtocol(), e.GetRole(), e.GetNegotiatedGroup(), e.GetCipher(),
		e.GetDetectionMethod(), e.GetObservedCount(),
		e.GetFirstSeen().AsTime().UTC().Format(time.RFC3339Nano),
		e.GetLastSeen().AsTime().UTC().Format(time.RFC3339Nano),
		e.GetAppKey(), e.GetAppKeyKind())
}

// Sign — priv(base64)로 결과에 서명. 반환값을 envelope.signature에 넣는다.
func Sign(privB64 string, res *discoveryv1.CollectionResult) (string, error) {
	sk, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(sk), Canonical(res))
	return Prefix + base64.StdEncoding.EncodeToString(sig), nil
}

// Verify — pub(base64) 목록 중 하나로 envelope.signature가 유효하면 true.
// 등록된 공개키 provenance와 일치할 때만 통과(§2.6 "등록 provenance와 일치해야").
// VerifyFrom — **collector에 묶인 키로만** 검증한다.
//
// [Verify]는 넘긴 키를 전부 시도하고 어느 키가 맞았는지 묻지 않는다. 여러 조직·여러 collector의
// 키를 한 목록으로 넘기면, 어떤 키로든 통과한 결과가 **아무 collector 이름이나 달고** 들어올 수
// 있다. 서명은 "누가 냈나"를 답해야 하는데 그 목록은 "누군가는 냈다"까지만 답한다.
//
// keys는 collector_id → base64 공개키. 그 collector에 등록된 키가 없으면 거절한다 — 모르는
// collector의 주장을 받지 않는다.
//
// GATE: 보류 — PQCOTA_VERIFY_KEY가 키 목록이라 collector에 묶을 수 없다. 환경변수 형식을 바꿔야
// 한다(검토 중인 설계 §8).
func VerifyFrom(keys map[string]string, res *discoveryv1.CollectionResult) bool {
	pub, ok := keys[res.GetEnvelope().GetCollectorId()]
	if !ok {
		return false
	}
	return Verify([]string{pub}, res)
}

func Verify(pubB64s []string, res *discoveryv1.CollectionResult) bool {
	s := res.GetEnvelope().GetSignature()
	if !strings.HasPrefix(s, Prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
	if err != nil {
		return false
	}
	msg := Canonical(res)
	for _, pb := range pubB64s {
		pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pb))
		if err != nil || len(pk) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pk), msg, raw) {
			return true
		}
	}
	return false
}
