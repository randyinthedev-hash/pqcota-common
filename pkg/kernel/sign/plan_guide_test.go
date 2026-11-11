// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	provisioningv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/provisioning/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"google.golang.org/protobuf/proto"
)

func guideSel(srcIdx ...uint32) *provisioningv1.GuideSelection {
	return &provisioningv1.GuideSelection{
		GuideId: "pqcota-guide/jca-doc-key-transport-mlkem", Revision: "1",
		BodySha256: strings.Repeat("e", 64), ManifestSha256: strings.Repeat("f", 64),
		Purpose: "document-key-transport", Conditions: []string{"JCA", "JDK 21"}, Rationale: "wraps document keys with RSA-OAEP",
		EvidenceSourceIndexes: []uint32{0}, SourceEvidenceIndexes: srcIdx,
	}
}

// guidePlan — sourcePlan에 가이드 둘: a1(런타임 0번 + 소스 1번으로 고름), a3(소스 근거만, 소스 0번).
func guidePlan() *provisioningv1.FinalizedPlan {
	p := sourcePlan()
	p.Actions[0].Guide = guideSel(1)
	g := guideSel(0)
	g.EvidenceSourceIndexes = nil
	p.Actions[2].Guide = g
	return p
}

func TestGuideTamperBreaksApproval(t *testing.T) {
	pub, priv, _ := sign.Generate()
	g := func(p *provisioningv1.FinalizedPlan) *provisioningv1.GuideSelection { return p.Actions[0].Guide }
	for _, c := range []struct {
		name   string
		mutate func(*provisioningv1.FinalizedPlan)
	}{
		{"guide id", func(p *provisioningv1.FinalizedPlan) { g(p).GuideId = "pqcota-guide/other" }},
		{"revision", func(p *provisioningv1.FinalizedPlan) { g(p).Revision = "2" }},
		{"body hash", func(p *provisioningv1.FinalizedPlan) { g(p).BodySha256 = strings.Repeat("0", 64) }},
		{"manifest hash", func(p *provisioningv1.FinalizedPlan) { g(p).ManifestSha256 = strings.Repeat("0", 64) }},
		{"purpose", func(p *provisioningv1.FinalizedPlan) { g(p).Purpose = "tls-key-exchange" }},
		{"condition value", func(p *provisioningv1.FinalizedPlan) { g(p).Conditions[1] = "JDK 17" }},
		{"condition order", func(p *provisioningv1.FinalizedPlan) { c := g(p).Conditions; c[0], c[1] = c[1], c[0] }},
		{"condition added", func(p *provisioningv1.FinalizedPlan) { g(p).Conditions = append(g(p).Conditions, "BC 1.85") }},
		{"condition removed", func(p *provisioningv1.FinalizedPlan) { g(p).Conditions = g(p).Conditions[:1] }},
		{"rationale", func(p *provisioningv1.FinalizedPlan) { g(p).Rationale = "" }},
		{"runtime index changed", func(p *provisioningv1.FinalizedPlan) { g(p).EvidenceSourceIndexes = []uint32{1} }},
		{"runtime index removed", func(p *provisioningv1.FinalizedPlan) { g(p).EvidenceSourceIndexes = nil }},
		{"source index changed", func(p *provisioningv1.FinalizedPlan) { g(p).SourceEvidenceIndexes = []uint32{0} }},
		{"source index added", func(p *provisioningv1.FinalizedPlan) { g(p).SourceEvidenceIndexes = []uint32{0, 1} }},
		// 런타임 순번과 소스 순번 사이의 이동 — 같은 숫자가 다른 목록을 가리킨다.
		{"index moved between lists", func(p *provisioningv1.FinalizedPlan) {
			g(p).EvidenceSourceIndexes, g(p).SourceEvidenceIndexes = nil, []uint32{0, 1}
		}},
		{"guide removed", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].Guide = nil }},
		{"guide added", func(p *provisioningv1.FinalizedPlan) { p.Actions[1].Guide = guideSel() }},
		{"guide moved to another action", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[1].Guide, p.Actions[0].Guide = p.Actions[0].Guide, nil
		}},
		{"guides swapped", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0].Guide, p.Actions[2].Guide = p.Actions[2].Guide, p.Actions[0].Guide
		}},
		// 가이드가 고른 근거 자체의 값.
		{"chosen source evidence location", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].SourceEvidence[1].LocationId = "loc-9" }},
		{"chosen runtime evidence finding", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].EvidenceSources[0].FindingId = "f-9" }},
	} {
		p := guidePlan()
		sig, err := sign.SignApproval(priv, "alice", p)
		if err != nil {
			t.Fatal(err)
		}
		p.ApprovalSignatures = []string{sig}
		if chk := sign.VerifyApprovals(map[string]string{"alice": pub}, p); len(chk.Approved) != 1 {
			t.Fatalf("%s: verification must hold right after signing: %+v", c.name, chk)
		}
		c.mutate(p)
		if chk := sign.VerifyApprovals(map[string]string{"alice": pub}, p); len(chk.Approved) != 0 {
			t.Errorf("%s: the approval still verified — the guide is a signing blind spot", c.name)
		}
	}
}

// 가이드를 버린 소비자를 흉내 낸다. 이 시험이 보이는 것은 **승인 서명을 실제로 검증하는 소비자**의 거부뿐이다 —
// 서명을 확인하지 않는 경로(--allow-unverified-approvals, 검증을 남에게 맡기는 소비자)에는 해당하지 않는다(가이드 계약 §4.3).
func TestVerifyingConsumerThatDropsTheGuideRejects(t *testing.T) {
	pub, priv, _ := sign.Generate()
	p := guidePlan()
	sig, _ := sign.SignApproval(priv, "alice", p)
	stripped := proto.Clone(p).(*provisioningv1.FinalizedPlan)
	for _, a := range stripped.Actions {
		a.Guide = nil
	}
	stripped.ApprovalSignatures = []string{sig}
	if chk := sign.VerifyApprovals(map[string]string{"alice": pub}, stripped); len(chk.Approved) != 0 {
		t.Fatal("an approval over a guide verified on the plan with the guide dropped")
	}
}

// 개수 자리: N+M과 N+M+1이 겹치지 않는다. 비다시피 한 가이드도 「가이드 없음」과 다른 정규형이다.
func TestGuideCountSlotDoesNotOverlap(t *testing.T) {
	without := sourcePlan()
	with := sourcePlan()
	with.Actions[0].Guide = &provisioningv1.GuideSelection{}
	if bytes.Equal(sign.CanonicalPlan(without), sign.CanonicalPlan(with)) {
		t.Fatal("an empty guide and no guide share a canonical form")
	}
	// 가이드 블록이 다음 조치의 시작으로 읽히지 않는다 — 가이드 있는 a1 다음 a2 와, 가이드 없는 a1 다음 가이드 값으로 시작하는 조치.
	a := plan()
	a.Actions = a.Actions[:1]
	a.Actions[0].Guide = guideSel()
	b := plan()
	b.Actions = b.Actions[:1]
	b.Actions = append(b.Actions, &provisioningv1.RemediationAction{Id: "pqcota-guide/jca-doc-key-transport-mlkem", TargetNodeId: "1"})
	if bytes.HasPrefix(sign.CanonicalPlan(b), sign.CanonicalPlan(a)) || bytes.Equal(sign.CanonicalPlan(a), sign.CanonicalPlan(b)) {
		t.Fatal("a guide block can be read as the start of the next action")
	}
}

func TestGuideNULIsRefused(t *testing.T) {
	for _, set := range []func(*provisioningv1.GuideSelection){
		func(g *provisioningv1.GuideSelection) { g.GuideId = "x\x00" },
		func(g *provisioningv1.GuideSelection) { g.Purpose = "\x00" },
		func(g *provisioningv1.GuideSelection) { g.Conditions[0] = "J\x00CA" },
		func(g *provisioningv1.GuideSelection) { g.Rationale = "a\x00b" },
		func(g *provisioningv1.GuideSelection) { g.ManifestSha256 = "\x00" },
	} {
		p := guidePlan()
		set(p.Actions[0].Guide)
		if err := sign.CheckPlanText(p); !errors.Is(err, sign.ErrNUL) {
			t.Errorf("NUL in the guide not refused: %v", err)
		}
	}
}
