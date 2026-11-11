// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	provisioningv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/provisioning/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"google.golang.org/protobuf/proto"
)

// 소스 근거(source_evidence)가 없는 계획의 정규형은 **그 필드가 생기기 전과 한 바이트도 다르지 않다.**
// 아래 값은 source_evidence를 넣기 전의 코드(v0.10.7 정규형)로 뽑은 것이다. 이 값이 바뀌면 기존 승인이
// 전부 무효가 된다 — 고치지 말고 정규형을 되돌린다.

func goldenPlans() map[string]*provisioningv1.FinalizedPlan {
	// 계획 단위 호환 경로만 쓰는 옛 꼴 — 근거 목록이 빈 조치 둘.
	legacy := plan()
	for _, a := range legacy.Actions {
		a.EvidenceSources = nil
	}
	// 실제 스냅샷 id 참조 + 내용 지문 참조, 근거 둘.
	two := plan()
	two.Actions[0].EvidenceSources = append(two.Actions[0].EvidenceSources, &provisioningv1.ActionEvidenceSource{
		FindingId: "f-2",
		Snapshot: &provisioningv1.SnapshotReference{SourceNodeId: "web-02",
			Reference: &provisioningv1.SnapshotReference_SnapshotId{SnapshotId: "snap-9"}},
	})
	// 참조 꼴이 없는 근거(none).
	none := proto.Clone(plan()).(*provisioningv1.FinalizedPlan)
	none.Actions[0].EvidenceSources[0].Snapshot = &provisioningv1.SnapshotReference{SourceNodeId: "x"}
	return map[string]*provisioningv1.FinalizedPlan{"current": plan(), "legacy": legacy, "two-sources": two, "no-reference": none}
}

// 정규형의 SHA-256(소문자 16진수).
var goldenCanonical = map[string]string{
	"current":      "895e61ca7165979ed6fc2b44cfd6840a084223096d4fc23149bb5038b97aaf2c",
	"legacy":       "7d04917bb068fb494b904a04e780c48c0dc5e1ccae75555bf7900e57f9997607",
	"two-sources":  "efcb19d85de3267878b6b5fedcb3024f9b65fbbd880c3dec435f84dfa42f6252",
	"no-reference": "bf582af8df857487d7646921310aea18a377867871e31d9438f75febd1072edb",
}

// 고정 키(시드 0..31)로 "current"에 한 승인 서명. ed25519는 결정론적이라 같은 바이트면 같은 서명이다.
const goldenApproval = "alice:ed25519:5qSZLO3gY3MpJlPwviuHkNb90cR+rUe7vG+DVpi/ltYpLgPHAmjbwdds+oCd8jYWIy+uq8oDklel3bM09o+HAw=="

func goldenKey() (privB64, pubB64 string) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	sk := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(sk), base64.StdEncoding.EncodeToString(sk.Public().(ed25519.PublicKey))
}

func TestCanonicalPlanBytesAreUnchanged(t *testing.T) {
	for name, p := range goldenPlans() {
		sum := sha256.Sum256(sign.CanonicalPlan(p))
		if got := hex.EncodeToString(sum[:]); got != goldenCanonical[name] {
			t.Errorf("%s: canonical sha256 %s, want %s — the canonical form of a plan without source evidence changed, which invalidates existing approvals", name, got, goldenCanonical[name])
		}
	}
	priv, pub := goldenKey()
	p := plan()
	sig, err := sign.SignApproval(priv, "alice", p)
	if err != nil {
		t.Fatal(err)
	}
	if sig != goldenApproval {
		t.Errorf("approval %s, want %s", sig, goldenApproval)
	}
	// 옛 코드가 만든 승인이 지금 코드에서 통과한다.
	p.ApprovalSignatures = []string{goldenApproval}
	if c := sign.VerifyApprovals(map[string]string{"alice": pub}, p); len(c.Approved) != 1 {
		t.Errorf("an approval made before source evidence existed no longer verifies: %+v", c)
	}
}
