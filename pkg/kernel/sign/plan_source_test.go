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

var (
	sha1st = strings.Repeat("a", 64)
	sha2nd = strings.Repeat("b", 64)
)

// sourcePlan — a1은 런타임 근거와 소스 근거 둘(하나는 위치까지), a3은 소스 근거만 있는 APP_RECONFIG.
func sourcePlan() *provisioningv1.FinalizedPlan {
	p := plan()
	p.Actions[0].SourceEvidence = []*provisioningv1.SourceEvidenceReference{
		{InterpretationId: "int-1", ItemId: "item-1", LocationId: "loc-1", InputSha256: sha1st},
		{InterpretationId: "int-1", ItemId: "item-2", InputSha256: sha1st},
	}
	p.Actions = append(p.Actions, &provisioningv1.RemediationAction{
		Id: "a3", TargetNodeId: "web-01",
		Kind:           provisioningv1.RemediationKind_REMEDIATION_KIND_APP_RECONFIG,
		SourceEvidence: []*provisioningv1.SourceEvidenceReference{{InterpretationId: "int-2", ItemId: "item-9", InputSha256: sha2nd}},
	})
	return p
}

func TestSourceEvidenceTamperBreaksApproval(t *testing.T) {
	pub, priv, _ := sign.Generate()
	src := func(p *provisioningv1.FinalizedPlan) []*provisioningv1.SourceEvidenceReference {
		return p.Actions[0].SourceEvidence
	}
	for _, c := range []struct {
		name   string
		mutate func(*provisioningv1.FinalizedPlan)
	}{
		{"interpretation", func(p *provisioningv1.FinalizedPlan) { src(p)[0].InterpretationId = "int-9" }},
		{"item", func(p *provisioningv1.FinalizedPlan) { src(p)[0].ItemId = "item-9" }},
		{"location changed", func(p *provisioningv1.FinalizedPlan) { src(p)[0].LocationId = "loc-2" }},
		{"location to whole item", func(p *provisioningv1.FinalizedPlan) { src(p)[0].LocationId = "" }},
		{"whole item to location", func(p *provisioningv1.FinalizedPlan) { src(p)[1].LocationId = "loc-1" }},
		{"input hash", func(p *provisioningv1.FinalizedPlan) { src(p)[0].InputSha256 = sha2nd }},
		{"order", func(p *provisioningv1.FinalizedPlan) { s := src(p); s[0], s[1] = s[1], s[0] }},
		{"removed", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].SourceEvidence = src(p)[:1] }},
		{"all removed", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].SourceEvidence = nil }},
		{"added", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0].SourceEvidence = append(src(p), &provisioningv1.SourceEvidenceReference{InterpretationId: "int-1", ItemId: "item-3", InputSha256: sha1st})
		}},
		// 같은 계획 안에서 다른 조치로 옮긴다 — 근거가 어느 조치의 것인지까지 덮인다.
		{"moved to another action", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[1].SourceEvidence = []*provisioningv1.SourceEvidenceReference{src(p)[1]}
			p.Actions[0].SourceEvidence = src(p)[:1]
		}},
		{"source-only action's reference moved", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[1].SourceEvidence, p.Actions[2].SourceEvidence = p.Actions[2].SourceEvidence, nil
		}},
	} {
		p := sourcePlan()
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
			t.Errorf("%s: the approval still verified — source evidence is a signing blind spot", c.name)
		}
	}
}

// 모르는 필드를 버리는 소비자를 흉내 낸다: 소스 근거를 떼어 낸 메시지로는 서명이 맞지 않는다.
// 그 소비자가 「서명을 확인했다」고 해도 버린 소스 근거까지 확인한 것이 아니므로, 맞지 않는 것이 옳다.
func TestDroppingSourceEvidenceBreaksApproval(t *testing.T) {
	pub, priv, _ := sign.Generate()
	p := sourcePlan()
	sig, _ := sign.SignApproval(priv, "alice", p)
	stripped := proto.Clone(p).(*provisioningv1.FinalizedPlan)
	for _, a := range stripped.Actions {
		a.SourceEvidence = nil
	}
	stripped.ApprovalSignatures = []string{sig}
	if chk := sign.VerifyApprovals(map[string]string{"alice": pub}, stripped); len(chk.Approved) != 0 {
		t.Fatal("an approval over source evidence verified on a plan with the source evidence dropped")
	}
}

// 개수 경계 — 런타임 근거 하나(id 참조)의 정규형 문자열 넷과 같은 값을 가진 소스 근거 하나는 다른 정규형이다.
func TestRuntimeAndSourceCountsDoNotOverlap(t *testing.T) {
	runtime := plan()
	runtime.Actions = runtime.Actions[:1]
	runtime.Actions[0].EvidenceSources = []*provisioningv1.ActionEvidenceSource{{FindingId: "f-1",
		Snapshot: &provisioningv1.SnapshotReference{SourceNodeId: "n", Reference: &provisioningv1.SnapshotReference_SnapshotId{SnapshotId: "s"}}}}
	source := proto.Clone(runtime).(*provisioningv1.FinalizedPlan)
	source.Actions[0].EvidenceSources = nil
	source.Actions[0].SourceEvidence = []*provisioningv1.SourceEvidenceReference{{InterpretationId: "f-1", ItemId: "n", LocationId: "id", InputSha256: "s"}}
	if bytes.Equal(sign.CanonicalPlan(runtime), sign.CanonicalPlan(source)) {
		t.Fatal("a runtime evidence and a source reference with the same strings share a canonical form")
	}
}

// 이어 붙여 같은 바이트를 노리는 쌍: 「소스 근거 있는 조치」와 「소스 근거 없는 조치 + 그 값들로 시작하는 다음 조치」.
func TestSourceEvidenceCannotPoseAsTheNextAction(t *testing.T) {
	with := plan()
	with.Actions = with.Actions[:1]
	with.Actions[0].SourceEvidence = []*provisioningv1.SourceEvidenceReference{{InterpretationId: "a2", ItemId: "db-01", LocationId: "", InputSha256: "CRYPTO_RUNTIME_UNSPECIFIED"}}
	without := plan()
	without.Actions = without.Actions[:1]
	without.Actions = append(without.Actions, &provisioningv1.RemediationAction{Id: "a2", TargetNodeId: "db-01"})
	if bytes.HasPrefix(sign.CanonicalPlan(without), sign.CanonicalPlan(with)) || bytes.Equal(sign.CanonicalPlan(with), sign.CanonicalPlan(without)) {
		t.Fatal("source evidence can be read as the start of the next action")
	}
	pub, priv, _ := sign.Generate()
	sig, _ := sign.SignApproval(priv, "alice", with)
	without.ApprovalSignatures = []string{sig}
	if chk := sign.VerifyApprovals(map[string]string{"alice": pub}, without); len(chk.Approved) != 0 {
		t.Fatal("the approval of one plan verified on the other")
	}
}

// 소스 근거의 문자열도 NUL을 거부한다(CheckPlanText가 리플렉션으로 따라 본다).
func TestSourceEvidenceNULIsRefused(t *testing.T) {
	for _, set := range []func(*provisioningv1.SourceEvidenceReference){
		func(r *provisioningv1.SourceEvidenceReference) { r.InterpretationId = "int\x001" },
		func(r *provisioningv1.SourceEvidenceReference) { r.ItemId = "i\x00" },
		func(r *provisioningv1.SourceEvidenceReference) { r.LocationId = "\x00" },
		func(r *provisioningv1.SourceEvidenceReference) { r.InputSha256 = "a\x00b" },
	} {
		p := sourcePlan()
		set(p.Actions[0].SourceEvidence[0])
		if err := sign.CheckPlanText(p); !errors.Is(err, sign.ErrNUL) {
			t.Errorf("NUL in source evidence not refused: %v", err)
		}
	}
}
