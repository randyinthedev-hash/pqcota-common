// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
)

func signedAs(t *testing.T, id, priv string) *discoveryv1.CollectionResult {
	t.Helper()
	res := &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{CollectorId: id, TargetNodeId: "web-01"}}
	sig, err := sign.Sign(priv, res)
	if err != nil {
		t.Fatal(err)
	}
	res.Envelope.Signature = sig
	return res
}

// 같은 키 K로 서명해도, 결과에 적힌 ID에 K가 등록돼 있어야 통과한다. 다른 ID의 키로 맞으면 그 사실을 사유에
// 덧붙이되 거부한다. 다른 목록으로 다시 시도하지 않는다.
func TestVerifyBound(t *testing.T) {
	k, kPriv, _ := sign.Generate()
	k2, k2Priv, _ := sign.Generate()
	keys := map[string][]string{"openssl-collector": {k}, "network-collector": {k2}}

	if err := sign.VerifyBound(keys, signedAs(t, "openssl-collector", kPriv)); err != nil {
		t.Fatalf("its own ID with its own key was rejected: %v", err)
	}
	err := sign.VerifyBound(keys, signedAs(t, "network-collector", kPriv))
	if err == nil {
		t.Fatal("a result signed with openssl-collector's key passed as network-collector")
	}
	if !strings.Contains(err.Error(), "does not match the keys registered for network-collector") ||
		!strings.Contains(err.Error(), "matches a key registered for openssl-collector") {
		t.Errorf("reason: %v", err)
	}
	if err := sign.VerifyBound(keys, signedAs(t, "jvm-collector", kPriv)); err == nil || !strings.Contains(err.Error(), "has no registered key") {
		t.Errorf("an unregistered ID: %v", err)
	}
	unsigned := signedAs(t, "openssl-collector", kPriv)
	unsigned.Envelope.Signature = ""
	if err := sign.VerifyBound(keys, unsigned); !errors.Is(err, sign.ErrNoSignature) {
		t.Errorf("an unsigned result: %v", err)
	}
	// 교체: 같은 ID에 옛 키와 새 키가 함께 있으면 둘 다 통과한다.
	rot := map[string][]string{"openssl-collector": {k, k2}}
	for _, p := range []string{kPriv, k2Priv} {
		if err := sign.VerifyBound(rot, signedAs(t, "openssl-collector", p)); err != nil {
			t.Errorf("rotation: %v", err)
		}
	}
	// 공유: 같은 키를 두 ID에 적으면 그 두 ID는 구별되지 않는다(그 키로 어느 쪽이든 통과한다).
	shared := map[string][]string{"openssl-collector": {k}, "network-collector": {k}}
	if err := sign.VerifyBound(shared, signedAs(t, "network-collector", kPriv)); err != nil {
		t.Errorf("a shared key: %v", err)
	}
	if err := sign.VerifyBound(shared, signedAs(t, "jvm-collector", kPriv)); err == nil {
		t.Error("a shared key passed for an ID that does not list it")
	}
}

func TestParseCollectorKeys(t *testing.T) {
	k, _, _ := sign.Generate()
	k2, _, _ := sign.Generate()

	bound, legacy, err := sign.ParseCollectorKeys(" openssl-collector:" + k + ", network-collector:" + k + ",network-collector:" + k2 + " ")
	if err != nil || legacy != nil {
		t.Fatalf("bound form: %v %v", legacy, err)
	}
	if len(bound["openssl-collector"]) != 1 || len(bound["network-collector"]) != 2 {
		t.Errorf("bound: %v", bound)
	}
	bound, legacy, err = sign.ParseCollectorKeys(k + "," + k2)
	if err != nil || bound != nil || len(legacy) != 2 {
		t.Errorf("legacy form: %v %v %v", bound, legacy, err)
	}
	if b, l, err := sign.ParseCollectorKeys(" , "); b != nil || l != nil || err != nil {
		t.Errorf("empty: %v %v %v", b, l, err)
	}

	short := base64.StdEncoding.EncodeToString([]byte("short"))
	for name, v := range map[string]string{
		"mixed":     "openssl-collector:" + k + "," + k2,
		"empty id":  ":" + k,
		"empty key": "openssl-collector:",
		"base64":    "openssl-collector:not*base64",
		"length":    "openssl-collector:" + short,
		"duplicate": "openssl-collector:" + k + ",openssl-collector:" + k,
	} {
		_, _, err := sign.ParseCollectorKeys(v)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), k) || strings.Contains(err.Error(), k2) || strings.Contains(err.Error(), short) {
			t.Errorf("%s: the message prints the key: %v", name, err)
		}
	}
}

func TestFingerprint(t *testing.T) {
	k, _, _ := sign.Generate()
	if f := sign.Fingerprint(k); len(f) != 12 {
		t.Errorf("fingerprint: %q", f)
	}
	if sign.Fingerprint(" "+k) != sign.Fingerprint(k) {
		t.Error("spaces change the fingerprint")
	}
}

// 키를 잘못 넣으면(공개키, 짧은 값) panic이 아니라 오류다. SignAll은 결과마다 서명한다.
func TestSignAllAndBadKeys(t *testing.T) {
	pub, priv, _ := sign.Generate()
	rs := []*discoveryv1.CollectionResult{
		{Envelope: &commonv1.Envelope{CollectorId: "jvm-collector", TargetNodeId: "a"}},
		{Envelope: &commonv1.Envelope{CollectorId: "jvm-collector", TargetNodeId: "b"}},
	}
	if err := sign.SignAll(priv, rs); err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if err := sign.VerifyBound(map[string][]string{"jvm-collector": {pub}}, r); err != nil {
			t.Errorf("%s: %v", r.Envelope.TargetNodeId, err)
		}
	}
	for _, bad := range []string{pub, "not base64!", ""} {
		if err := sign.SignAll(bad, rs[:1]); err == nil {
			t.Errorf("signed with %q", bad)
		}
	}
}
