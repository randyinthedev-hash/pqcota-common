package sign_test

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
)

func result(node, cbom string) *discoveryv1.CollectionResult {
	return &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: node},
		CbomCyclonedx: []byte(cbom),
		RawFormat:     "test/v1",
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	res := result("web-01", `{"a":1}`)
	sig, err := sign.Sign(priv, res)
	if err != nil {
		t.Fatal(err)
	}
	res.Envelope.Signature = sig

	if !sign.Verify([]string{pub}, res) {
		t.Error("a valid signature failed verification")
	}

	// 변조(CBOM 변경) → 검증 실패.
	res.CbomCyclonedx = []byte(`{"a":2}`)
	if sign.Verify([]string{pub}, res) {
		t.Error("a tampered result passed verification — integrity failed")
	}

	// 다른 키 → 실패.
	res.CbomCyclonedx = []byte(`{"a":1}`)
	otherPub, _, _ := sign.Generate()
	if sign.Verify([]string{otherPub}, res) {
		t.Error("it passed verification with a different public key")
	}

	// 서명 없음 → 실패.
	res.Envelope.Signature = ""
	if sign.Verify([]string{pub}, res) {
		t.Error("an unsigned result passed verification")
	}
}

// TestVerifyFromBindsKeysToCollectors — 서명이 "누가 냈나"를 답하게 만든다.
//
// Verify는 넘긴 키를 전부 시도하므로, 여러 collector의 키를 한 목록으로 주면 어느 키로든 통과한
// 결과가 **아무 collector 이름이나 달고** 들어올 수 있다. VerifyFrom은 그 이름에 등록된 키로만 본다.
func TestVerifyFromBindsKeysToCollectors(t *testing.T) {
	pubA, privA, _ := sign.Generate()
	pubB, _, _ := sign.Generate()

	// A의 키로 서명해 놓고 collector 이름만 B로 바꾼다.
	res := &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{
		CollectorId: "collector-b", TargetNodeId: "web-01",
	}}
	sig, err := sign.Sign(privA, res)
	if err != nil {
		t.Fatal(err)
	}
	res.Envelope.Signature = sig

	keys := map[string]string{"collector-a": pubA, "collector-b": pubB}

	if !sign.Verify([]string{pubA, pubB}, res) {
		t.Fatal("premise check: verification against the list passes — which is why VerifyFrom is needed")
	}
	if sign.VerifyFrom(keys, res) {
		t.Fatal("something signed with A's key passed under the name collector-b")
	}

	// 이름을 바로잡으면 통과한다.
	res.Envelope.CollectorId = "collector-a"
	res.Envelope.Signature, _ = sign.Sign(privA, res)
	if !sign.VerifyFrom(keys, res) {
		t.Fatal("its own name with its own key was rejected")
	}
	// 등록되지 않은 collector는 받지 않는다.
	res.Envelope.CollectorId = "collector-unknown"
	res.Envelope.Signature, _ = sign.Sign(privA, res)
	if sign.VerifyFrom(keys, res) {
		t.Fatal("a claim from an unknown collector was accepted")
	}
}
