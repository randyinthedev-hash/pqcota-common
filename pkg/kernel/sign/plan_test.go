package sign_test

import (
	"strings"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	provisioningv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/provisioning/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 승인 서명은 "누군가 승인했다"가 아니라 **"누가 승인했다"**를 답해야 한다. 그래서 검증은
// 승인자 id에 묶인 키로만 한다. 아래 테스트들이 그 경계를 고정한다.

func plan() *provisioningv1.FinalizedPlan {
	return &provisioningv1.FinalizedPlan{
		Id:                    "plan-1",
		Status:                provisioningv1.PlanStatus_PLAN_STATUS_FINALIZED,
		Scope:                 "ring-0",
		DerivedFromSnapshotId: "snap-1",
		RulesetVersion:        "ruleset-1",
		FinalizedAt:           timestamppb.New(time.Unix(1700000000, 0).UTC()),
		Actions: []*provisioningv1.RemediationAction{{
			Id: "a1", TargetNodeId: "web-01", FindingId: "f-1",
			CryptoRuntime:   commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL,
			Kind:            provisioningv1.RemediationKind_REMEDIATION_KIND_CONFIG_ONLY,
			AutomationLevel: provisioningv1.DeployAutomationLevel_DEPLOY_AUTOMATION_LEVEL_L2_STAGE_INSTALL,
			TargetAlgorithm: "ML-KEM (FIPS 203)", ProviderChoice: "oqsprovider",
			ConfigArtifact: "Groups = X25519MLKEM768:x25519\n", RollbackNote: "delete the fragment",
			Priority: 3, ProviderClass: "com.acme.jce.AcmeProvider",
			Activation: &provisioningv1.ActivationHooks{
				Pre: "stop", Activate: "link", Deactivate: "unlink", Restart: "start",
			},
			EvidenceSources: []*provisioningv1.ActionEvidenceSource{{
				FindingId: "f-1",
				Snapshot: &provisioningv1.SnapshotReference{SourceNodeId: "web-01.corp",
					Reference: &provisioningv1.SnapshotReference_Content{Content: &provisioningv1.SnapshotContentReference{
						FormatVersion: "pqcota-snapshot-content/v1", Digest: "ab", RulesetVersion: "pqcota-enrich/v2"}}},
			}},
		}, {
			Id: "a2", TargetNodeId: "db-01",
			Kind: provisioningv1.RemediationKind_REMEDIATION_KIND_PROVIDER_INJECT,
		}},
	}
}

func TestSignAndVerifyApproval(t *testing.T) {
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p := plan()
	sig, err := sign.SignApproval(priv, "alice", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sig, "alice:"+sign.Prefix) {
		t.Fatalf("the approval must carry the approver and the scheme: %s", sig)
	}
	p.ApprovalSignatures = append(p.ApprovalSignatures, sig)

	chk := sign.VerifyApprovals(map[string]string{"alice": pub}, p)
	if len(chk.Approved) != 1 || chk.Approved[0] != "alice" {
		t.Fatalf("alice's approval must verify: %+v", chk)
	}
	if len(chk.Rejected) != 0 || len(chk.Unverifiable) != 0 {
		t.Errorf("nothing else should be reported: %+v", chk)
	}

	// ★ 서명은 되는데 **이름이 다른 사람의 키**로는 통과하면 안 된다. 통과하면 서명이
	// "누가"를 답하지 못하고 "누군가"까지만 답하게 된다.
	otherPub, _, _ := sign.Generate()
	chk = sign.VerifyApprovals(map[string]string{"alice": otherPub}, p)
	if len(chk.Approved) != 0 || len(chk.Rejected) != 1 {
		t.Errorf("a different key registered for alice must be rejected: %+v", chk)
	}

	// 승인자 id에 ':'가 들어가면 서명 문자열을 가를 수 없다.
	if _, err := sign.SignApproval(priv, "a:b", p); err == nil {
		t.Error("an approver id containing ':' must be refused")
	}
	if _, err := sign.SignApproval(priv, "  ", p); err == nil {
		t.Error("an empty approver id must be refused")
	}
}

// 모르는 승인자의 승인은 받지 않는다 — 등록된 키가 없으면 그 사람이 누구인지 말할 수 없다.
func TestApprovalRejectsUnknownApprover(t *testing.T) {
	_, priv, _ := sign.Generate()
	p := plan()
	sig, _ := sign.SignApproval(priv, "mallory", p)
	p.ApprovalSignatures = []string{sig}

	chk := sign.VerifyApprovals(map[string]string{"alice": "irrelevant"}, p)
	if len(chk.Approved) != 0 {
		t.Fatalf("an unregistered approver must not be approved: %+v", chk)
	}
	if len(chk.Rejected) != 1 || !strings.Contains(chk.Rejected[0].Reason, "no key is registered") {
		t.Errorf("the reason must say no key is registered: %+v", chk.Rejected)
	}
}

// 서명 꼴이 아닌 항목은 이름표일 뿐이다. **거부와 같은 칸에 두지 않는다** — 틀린 것이 아니라
// 확인할 수 없는 것이고, 둘을 섞으면 확인하지 않은 것이 확인한 것처럼 보인다.
func TestApprovalLabelIsUnverifiable(t *testing.T) {
	p := plan()
	p.ApprovalSignatures = []string{"reviewer:demo", "just-a-name"}

	chk := sign.VerifyApprovals(map[string]string{"alice": "x"}, p)
	if len(chk.Unverifiable) != 2 {
		t.Fatalf("both labels must land in Unverifiable: %+v", chk)
	}
	if len(chk.Approved) != 0 || len(chk.Rejected) != 0 {
		t.Errorf("a label is neither approved nor rejected: %+v", chk)
	}
}

// ★ 서명이 실제로 무엇을 덮는지 고정한다. 덮이지 않는 필드는 **바꿔도 승인이 통과**하므로,
// 승인자가 본 것과 배포되는 것이 달라진다.
func TestTamperBreaksApproval(t *testing.T) {
	pub, priv, _ := sign.Generate()

	for _, c := range []struct {
		name   string
		mutate func(*provisioningv1.FinalizedPlan)
	}{
		{"plan id", func(p *provisioningv1.FinalizedPlan) { p.Id = "other" }},
		{"status", func(p *provisioningv1.FinalizedPlan) { p.Status = provisioningv1.PlanStatus_PLAN_STATUS_DRAFT }},
		{"scope", func(p *provisioningv1.FinalizedPlan) { p.Scope = "ring-9" }},
		{"snapshot id", func(p *provisioningv1.FinalizedPlan) { p.DerivedFromSnapshotId = "snap-2" }},
		{"ruleset", func(p *provisioningv1.FinalizedPlan) { p.RulesetVersion = "ruleset-2" }},
		{"finalized at", func(p *provisioningv1.FinalizedPlan) { p.FinalizedAt = timestamppb.New(time.Unix(1, 0)) }},
		{"action node", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].TargetNodeId = "elsewhere" }},
		{"evidence finding", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].EvidenceSources[0].FindingId = "f-9" }},
		{"evidence source node", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].EvidenceSources[0].Snapshot.SourceNodeId = "x" }},
		{"evidence digest", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0].EvidenceSources[0].Snapshot.GetContent().Digest = "cd"
		}},
		{"evidence kind", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0].EvidenceSources[0].Snapshot.Reference = &provisioningv1.SnapshotReference_SnapshotId{SnapshotId: "ab"}
		}},
		{"evidence removed", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].EvidenceSources = nil }},
		{"evidence added", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[1].EvidenceSources = append(p.Actions[1].EvidenceSources, &provisioningv1.ActionEvidenceSource{FindingId: "f-2"})
		}},
		{"action kind", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0].Kind = provisioningv1.RemediationKind_REMEDIATION_KIND_DECOMMISSION
		}},
		{"target algorithm", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].TargetAlgorithm = "RSA" }},
		{"provider choice", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].ProviderChoice = "evil" }},
		{"provider class", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].ProviderClass = "com.evil.P" }},
		{"config artifact", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].ConfigArtifact = "Groups = x25519\n" }},
		{"rollback note", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].RollbackNote = "" }},
		{"priority", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].Priority = 0 }},
		{"automation level", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0].AutomationLevel = provisioningv1.DeployAutomationLevel_DEPLOY_AUTOMATION_LEVEL_L3_FULL_AUTO
		}},
		{"activation restart", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].Activation.Restart = "rm -rf /" }},
		{"finding id", func(p *provisioningv1.FinalizedPlan) { p.Actions[0].FindingId = "f-2" }},
		{"crypto runtime", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0].CryptoRuntime = commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA
		}},
		// 조치는 집합이 아니라 **차례**다 — 순서를 바꾸는 것은 계획을 바꾸는 것이다.
		{"action order", func(p *provisioningv1.FinalizedPlan) {
			p.Actions[0], p.Actions[1] = p.Actions[1], p.Actions[0]
		}},
		{"an added action", func(p *provisioningv1.FinalizedPlan) {
			p.Actions = append(p.Actions, &provisioningv1.RemediationAction{Id: "a3", TargetNodeId: "x"})
		}},
	} {
		p := plan()
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
			t.Errorf("%s changed and the approval still verified — that field is a signing blind spot", c.name)
		}
	}

	// 승인 서명 자신을 더하는 것은 깨뜨리지 않는다 — 서명 대상에서 자기 자신은 빠지기 때문이다.
	p := plan()
	sig, _ := sign.SignApproval(priv, "alice", p)
	p.ApprovalSignatures = []string{sig}
	pub2, priv2, _ := sign.Generate()
	sig2, _ := sign.SignApproval(priv2, "bob", p)
	p.ApprovalSignatures = append(p.ApprovalSignatures, sig2)
	if chk := sign.VerifyApprovals(map[string]string{"alice": pub, "bob": pub2}, p); len(chk.Approved) != 2 {
		t.Errorf("a second approval must not invalidate the first: %+v", chk)
	}
}

// ★ 필드 수 가드 — 계약에 필드가 늘면 여기서 실패한다. CanonicalPlan을 함께 갱신하라는 신호다.
func TestCanonicalPlanCoversAllFields(t *testing.T) {
	want := map[string]int{
		"FinalizedPlan":            8,  // 그중 approval_signatures는 서명 대상에서 제외(자기 자신)
		"RemediationAction":        14, // id, node, finding, runtime, kind, level, target, provider, artifact, note, priority, class, activation, evidence_sources
		"ActivationHooks":          4,  // pre, activate, deactivate, restart
		"ActionEvidenceSource":     2,  // finding_id, snapshot
		"SnapshotReference":        3,  // source_node_id, snapshot_id | content
		"SnapshotContentReference": 3,  // format_version, digest, ruleset_version
	}
	got := map[string]int{
		"FinalizedPlan":            (&provisioningv1.FinalizedPlan{}).ProtoReflect().Descriptor().Fields().Len(),
		"RemediationAction":        (&provisioningv1.RemediationAction{}).ProtoReflect().Descriptor().Fields().Len(),
		"ActivationHooks":          (&provisioningv1.ActivationHooks{}).ProtoReflect().Descriptor().Fields().Len(),
		"ActionEvidenceSource":     (&provisioningv1.ActionEvidenceSource{}).ProtoReflect().Descriptor().Fields().Len(),
		"SnapshotReference":        (&provisioningv1.SnapshotReference{}).ProtoReflect().Descriptor().Fields().Len(),
		"SnapshotContentReference": (&provisioningv1.SnapshotContentReference{}).ProtoReflect().Descriptor().Fields().Len(),
	}
	for msg, n := range want {
		if got[msg] != n {
			t.Errorf("the field count of %s changed from %d to %d.\n"+
				"  when the contract changes, sign.CanonicalPlan must change with it — otherwise the new field becomes a signing blind spot.\n"+
				"  once updated, fix this expectation to %d as well and add a case to TestTamperBreaksApproval.\n"+
				"  note: changing the scope of CanonicalPlan invalidates every existing approval.", msg, n, got[msg], got[msg])
		}
	}
}

// 같은 계획이면 같은 바이트가 나와야 한다 — 아니면 승인이 우연히 깨진다(§1.2 결정론).
func TestCanonicalPlanIsDeterministic(t *testing.T) {
	a, b := plan(), plan()
	if string(sign.CanonicalPlan(a)) != string(sign.CanonicalPlan(b)) {
		t.Error("the same plan produced different canonical bytes")
	}
	clone := proto.Clone(a).(*provisioningv1.FinalizedPlan)
	clone.ApprovalSignatures = []string{"alice:ed25519:whatever"}
	if string(sign.CanonicalPlan(a)) != string(sign.CanonicalPlan(clone)) {
		t.Error("approval_signatures must not be part of the canonical bytes")
	}
}

func TestParseKeyMap(t *testing.T) {
	m, err := sign.ParseKeyMap(" alice=AAA , bob=BBB ")
	if err != nil {
		t.Fatal(err)
	}
	if m["alice"] != "AAA" || m["bob"] != "BBB" {
		t.Errorf("the pairs were not read: %v", m)
	}
	if m, err := sign.ParseKeyMap(""); err != nil || m != nil {
		t.Errorf("an empty value must give an empty map with no error: %v %v", m, err)
	}
	if _, err := sign.ParseKeyMap("alice"); err == nil {
		t.Error("a value with no '=' must be refused — a bare key cannot say whose it is")
	}
	// 같은 id에 키가 둘이면 어느 쪽이 그 사람의 키인지 말할 수 없다.
	if _, err := sign.ParseKeyMap("alice=AAA,alice=BBB"); err == nil {
		t.Error("a duplicate id must be refused")
	}
}
