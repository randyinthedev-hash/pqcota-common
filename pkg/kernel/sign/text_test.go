// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	provisioningv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/provisioning/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// v0.10.6의 CanonicalPlan·SignApproval로 plan()과 고정 키(시드 1..32)에서 얻은 값이다(2026-11-10).
// NUL이 없는 기존 계획은 정규형 바이트도 서명 검증 결과도 그대로여야 한다.
const (
	frozenCanonSHA256 = "895e61ca7165979ed6fc2b44cfd6840a084223096d4fc23149bb5038b97aaf2c"
	frozenPub         = "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ="
	frozenSig         = "alice:ed25519:JGxmKTGovBa2B7m5+DrJ6Ip7/903SCgOctd7Oyk+dXe1xMO/5CYPJOggXQ0xhfWy20OM1GtB3TJRktkBO7BsBw=="
)

func TestNULFreePlanKeepsItsCanonicalFormAndApproval(t *testing.T) {
	if got := fmt.Sprintf("%x", sha256.Sum256(sign.CanonicalPlan(plan()))); got != frozenCanonSHA256 {
		t.Fatalf("NUL이 없는 계획의 정규형이 바뀌었다 — 기존 승인이 모두 무효가 된다\n got  %s\n want %s", got, frozenCanonSHA256)
	}
	p := plan()
	p.ApprovalSignatures = []string{frozenSig}
	chk := sign.VerifyApprovals(map[string]string{"alice": frozenPub}, p)
	if len(chk.Approved) != 1 || len(chk.Rejected) != 0 {
		t.Fatalf("v0.10.6이 만든 승인이 검증되지 않는다: %+v", chk)
	}
}

// signRaw — SignApproval을 거치지 않고 정규형에 바로 서명한다. 검증 쪽이 스스로 거부하는지 보려면
// 서명 쪽 검사를 우회한 서명이 있어야 한다(옛 판이 만든 서명이나 손으로 만든 서명과 같다).
func signRaw(t *testing.T, p *provisioningv1.FinalizedPlan) (pub, sig string) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pk),
		"alice:" + sign.Prefix + base64.StdEncoding.EncodeToString(ed25519.Sign(sk, sign.CanonicalPlan(p)))
}

// site — NUL을 넣을 문자열 자리 하나.
type site struct {
	path  string
	apply func(*provisioningv1.FinalizedPlan)
}

// stringSites — 계획 메시지에서 닿는 모든 문자열 자리를 찾는다(중첩·반복·oneof 포함). 비어 있는 메시지와
// 목록은 만들어서 들어간다. 필드를 손으로 나열하지 않으므로 새 문자열 필드도 이 시험에 들어온다. 다만 정규형에
// 문자열이 아닌 꼴(bytes 등)이 들어가거나 정규형의 짜임이 바뀌면, 이 시험만으로는 모자라니 함께 보강한다.
func stringSites(md protoreflect.MessageDescriptor, path string, get func(protoreflect.Message) protoreflect.Message, depth int) []site {
	if depth > 6 {
		return nil
	}
	var out []site
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := path + "." + string(fd.Name())
		switch {
		case fd.Kind() == protoreflect.StringKind && fd.IsList():
			out = append(out, site{name + "[]", func(p *provisioningv1.FinalizedPlan) {
				get(p.ProtoReflect()).Mutable(fd).List().Append(protoreflect.ValueOfString("x\x00y"))
			}})
		case fd.Kind() == protoreflect.StringKind:
			out = append(out, site{name, func(p *provisioningv1.FinalizedPlan) {
				get(p.ProtoReflect()).Set(fd, protoreflect.ValueOfString("x\x00y"))
			}})
		case fd.Kind() == protoreflect.MessageKind && fd.IsList():
			sub := func(r protoreflect.Message) protoreflect.Message {
				l := get(r).Mutable(fd).List()
				if l.Len() == 0 {
					l.Append(l.NewElement())
				}
				return l.Get(0).Message()
			}
			out = append(out, stringSites(fd.Message(), name+"[0]", sub, depth+1)...)
		case fd.Kind() == protoreflect.MessageKind && !fd.IsMap():
			sub := func(r protoreflect.Message) protoreflect.Message { return get(r).Mutable(fd).Message() }
			out = append(out, stringSites(fd.Message(), name, sub, depth+1)...)
		}
	}
	return out
}

// 모든 문자열 자리마다 NUL을 넣으면 서명 생성과 검증이 둘 다 거부한다. 검증이 거부할 때 승인됨은 남지 않는다.
func TestNULInAnyStringIsRefusedBySigningAndVerifying(t *testing.T) {
	sites := stringSites((&provisioningv1.FinalizedPlan{}).ProtoReflect().Descriptor(), "plan",
		func(m protoreflect.Message) protoreflect.Message { return m }, 0)
	// 정규형이 쓰는 문자열 자리는 계획 4·조치 8·훅 4·근거 6(oneof 포함)으로 22이고, 정규형 밖의
	// approval_signatures가 더해진다. 그보다 적게 찾았다면 훑기가 틀렸다.
	if len(sites) < 23 {
		t.Fatalf("문자열 자리를 %d개만 찾았다: %v", len(sites), sites)
	}
	_, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		p := proto.Clone(plan()).(*provisioningv1.FinalizedPlan)
		s.apply(p)
		if _, err := sign.SignApproval(priv, "alice", p); !errors.Is(err, sign.ErrNUL) {
			t.Errorf("%s: NUL이 있는데 서명했다(err=%v)", s.path, err)
		}
		pub, sig := signRaw(t, p)
		p.ApprovalSignatures = append(p.ApprovalSignatures, sig)
		chk := sign.VerifyApprovals(map[string]string{"alice": pub}, p)
		if len(chk.Approved) != 0 || len(chk.Rejected) == 0 {
			t.Errorf("%s: NUL이 있는데 검증이 승인을 남겼다: %+v", s.path, chk)
		}
	}
}

// 재현한 쌍(pqcota-test-reports 2026-nul-canon): 정규형이 같아 A의 서명이 B에서 통과했다. 이제 둘 다 거부한다.
func TestNULCollisionPairIsRefused(t *testing.T) {
	a := proto.Clone(plan()).(*provisioningv1.FinalizedPlan)
	a.Actions[0].ProviderChoice, a.Actions[0].ConfigArtifact = "BC\x00X", "Y"
	b := proto.Clone(plan()).(*provisioningv1.FinalizedPlan)
	b.Actions[0].ProviderChoice, b.Actions[0].ConfigArtifact = "BC", "X\x00Y"
	if !bytes.Equal(sign.CanonicalPlan(a), sign.CanonicalPlan(b)) {
		t.Fatal("시험의 전제가 깨졌다: 두 계획의 정규형이 같아야 한다")
	}
	pub, sig := signRaw(t, a)
	for name, p := range map[string]*provisioningv1.FinalizedPlan{"A": a, "B": b} {
		p.ApprovalSignatures = []string{sig}
		if chk := sign.VerifyApprovals(map[string]string{"alice": pub}, p); len(chk.Approved) != 0 {
			t.Errorf("%s: A에 한 서명이 승인으로 남았다: %+v", name, chk)
		}
		if err := sign.CheckPlanText(p); !errors.Is(err, sign.ErrNUL) {
			t.Errorf("%s: CheckPlanText가 NUL을 거부하지 않았다: %v", name, err)
		}
	}
}
