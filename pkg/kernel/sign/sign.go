// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package sign — collector 리포트 서명·검증 (규정서 §2.6 — provenance).
// ed25519로 CollectionResult를 서명하고, 중앙 적재가 등록된 공개키로 검증한다.
// 전송 보안(mTLS/SSH)이 없는 경로(T1 self-service·에어갭)에서 페이로드 신뢰의 앵커가 된다.
package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
	sk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return "", errors.New("the private key is not base64")
	}
	if len(sk) != ed25519.PrivateKeySize {
		// ed25519.Sign은 길이가 틀린 키에 panic한다. 공개키를 잘못 넣은 경우가 흔하다(32바이트).
		return "", fmt.Errorf("the private key is %d bytes, an ed25519 private key is %d", len(sk), ed25519.PrivateKeySize)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(sk), Canonical(res))
	return Prefix + base64.StdEncoding.EncodeToString(sig), nil
}

// SignAll — 결과마다 서명해 envelope.signature에 넣는다. 하나라도 서명하지 못하면 멈추고 오류를 돌려준다 —
// 키를 줬는데 서명 없는 결과가 나가면, ID 결합 모드의 적재기에서 이유를 모른 채 거부된다.
func SignAll(privB64 string, results []*discoveryv1.CollectionResult) error {
	for _, r := range results {
		if r.GetEnvelope() == nil {
			return errors.New("a result has no envelope to carry the signature")
		}
		sig, err := Sign(privB64, r)
		if err != nil {
			return err
		}
		r.Envelope.Signature = sig
	}
	return nil
}

// VerifyFrom — **collector에 묶인 키로만** 검증한다. ID마다 키 하나인 옛 꼴이다. 키 교체 때 옛 키와 새 키를
// 함께 둘 수 없어 [VerifyBound]를 더했고, 이것은 그것을 부르는 얇은 함수로 남긴다(호환성 정책).
func VerifyFrom(keys map[string]string, res *discoveryv1.CollectionResult) bool {
	bound := make(map[string][]string, len(keys))
	for id, k := range keys {
		bound[id] = []string{k}
	}
	return VerifyBound(bound, res) == nil
}

// VerifyBound — 결과의 `collector_id`에 **등록된 키로만** 서명을 검증한다. 통과하면 nil, 아니면 거부 사유다.
//
// [Verify]는 넘긴 키를 전부 시도하고 어느 키가 맞았는지 묻지 않는다. 여러 collector의 키를 한 목록으로 넘기면,
// 어떤 키로든 통과한 결과가 **아무 collector 이름이나 달고** 들어올 수 있다. 서명은 "누가 냈나"를 답해야 하는데
// 그 목록은 "누군가는 냈다"까지만 답한다.
//
// keys는 collector_id → 허용하는 base64 공개키들. 한 ID에 키가 여럿이면 교체 중이다(어느 것이든 통과).
// 등록된 키가 없는 ID는 거부한다. 다른 ID의 키로 맞으면 **그래도 거부하고** 사유에 그 사실만 덧붙인다.
// 운영자가 원인을 알게 할 뿐, 판정을 바꾸지 않는다. 다른 목록으로 다시 시도하지 않는다.
//
// 같은 키를 여러 ID에 등록하면 그 ID들은 이 함수로 구별되지 않는다. 그 키를 가진 쪽은 그 ID 어느 것으로도
// 통과한다. 수집기마다 따로 신원을 보려면 ID마다 다른 키를 쓴다.
//
// GATE: 배선 필수
func VerifyBound(keys map[string][]string, res *discoveryv1.CollectionResult) error {
	id := res.GetEnvelope().GetCollectorId()
	if !strings.HasPrefix(res.GetEnvelope().GetSignature(), Prefix) {
		return ErrNoSignature
	}
	own := keys[id]
	if len(own) == 0 {
		return fmt.Errorf("collector %q has no registered key", id)
	}
	if _, ok := MatchingKey(own, res); ok {
		return nil
	}
	msg := fmt.Sprintf("signature does not match the keys registered for %s", id)
	var others []string
	for other, ks := range keys {
		if other == id {
			continue
		}
		if _, ok := MatchingKey(ks, res); ok {
			others = append(others, other)
		}
	}
	if len(others) > 0 {
		sort.Strings(others)
		msg += "; it matches a key registered for " + strings.Join(others, ", ")
	}
	return errors.New(msg)
}

// ErrNoSignature — 결과에 서명이 없다.
var ErrNoSignature = errors.New("no signature")

// MatchingKey — 목록에서 서명이 맞는 첫 키. 어느 키가 서명했는지 보여 줄 때 쓴다(전환 점검).
func MatchingKey(pubB64s []string, res *discoveryv1.CollectionResult) (string, bool) {
	for _, pb := range pubB64s {
		if Verify([]string{pb}, res) {
			return strings.TrimSpace(pb), true
		}
	}
	return "", false
}

// Fingerprint — 공개 키의 지문(디코딩한 키 바이트의 SHA-256 앞 12자, 16진). 키 값을 그대로 찍지 않고
// 키를 가리킬 때 쓴다.
func Fingerprint(pubB64 string) string {
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return "invalid"
	}
	return fmt.Sprintf("%x", sha256.Sum256(pk))[:12]
}

// ParseCollectorKeys — PQCOTA_VERIFY_KEY 값을 읽는다. 모드는 값의 꼴로 정한다.
//
//   - 모든 항목이 `<collector-id>:<base64 공개키>` → **ID 결합 모드**. bound에 ID마다 허용 키들이 온다.
//     같은 ID를 여러 번 적을 수 있다(교체). 같은 키를 여러 ID에 적을 수 있다(그 ID들은 서로 구별되지 않는다).
//   - 어느 항목에도 콜론이 없다 → **기존 목록 모드**. legacy에 키들이 온다(지금과 같이 검사하지 않는다).
//   - 둘이 섞이면 오류다. 결합 모드의 값에 기존 목록이 남아 있을 수 없게 하려는 것이다.
//
// 결합 모드의 오류: 빈 ID·빈 키, base64가 아니거나 32바이트가 아닌 키, 같은 ID에 같은 키 두 번.
// 오류 메시지는 몇 번째 항목인지 말하고 키 값을 담지 않는다.
//
// 구분자가 콜론인 것은 base64에 콜론이 없어서다(`=`는 끝 채움 문자라 쓸 수 없다). ID는 마지막 콜론 앞이다.
func ParseCollectorKeys(s string) (bound map[string][]string, legacy []string, err error) {
	var items []string
	for _, it := range strings.Split(s, ",") {
		if it = strings.TrimSpace(it); it != "" {
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		return nil, nil, nil
	}
	withColon := 0
	for _, it := range items {
		if strings.Contains(it, ":") {
			withColon++
		}
	}
	switch {
	case withColon == 0:
		return nil, items, nil
	case withColon != len(items):
		return nil, nil, fmt.Errorf("%d of %d entries are <collector-id>:<key> and the rest are bare keys — use one form; in the bound form every key names its collector ID", withColon, len(items))
	}
	bound = map[string][]string{}
	for n, it := range items {
		i := strings.LastIndex(it, ":")
		id, key := strings.TrimSpace(it[:i]), strings.TrimSpace(it[i+1:])
		pos := n + 1
		if id == "" {
			return nil, nil, fmt.Errorf("entry %d: the collector ID is empty", pos)
		}
		if key == "" {
			return nil, nil, fmt.Errorf("entry %d (%s): the key is empty", pos, id)
		}
		pk, e := base64.StdEncoding.DecodeString(key)
		if e != nil {
			return nil, nil, fmt.Errorf("entry %d (%s): the key is not base64", pos, id)
		}
		if len(pk) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("entry %d (%s): the key is %d bytes, an ed25519 public key is %d", pos, id, len(pk), ed25519.PublicKeySize)
		}
		for _, have := range bound[id] {
			if have == key {
				return nil, nil, fmt.Errorf("entry %d (%s): the same key is listed twice for this ID", pos, id)
			}
		}
		bound[id] = append(bound[id], key)
	}
	return bound, nil, nil
}

// Verify — pub(base64) 목록 중 하나로 envelope.signature가 유효하면 true. **어느 키인지 묻지 않는다**(기존 목록
// 모드). 수집기 ID에 묶어 검증하려면 [VerifyBound].
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
