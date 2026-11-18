// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
)

func signedFor(t *testing.T, id, node, priv string) *discoveryv1.CollectionResult {
	t.Helper()
	res := &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{CollectorId: id, TargetNodeId: node}}
	sig, err := sign.Sign(priv, res)
	if err != nil {
		t.Fatal(err)
	}
	res.Envelope.Signature = sig
	return res
}

func mustParse(t *testing.T, s string) *sign.NodeKeys {
	t.Helper()
	k, err := sign.ParseNodeKeyFile([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// 노드 web-01에만 등록한 키 K: web-01의 결과는 통과하고, 같은 K로 web-02를 적어 서명한 결과는 거부된다.
// 사유는 web-02의 키와 맞지 않고 web-01의 키와 맞는다는 것이다. 등록 안 된 노드·서명 없음도 거부된다.
func TestVerifyNodeBound(t *testing.T) {
	k1, p1, _ := sign.Generate()
	k2, _, _ := sign.Generate()
	keys := mustParse(t, fmt.Sprintf("web-01 openssl-collector,network-collector %s\nweb-02 openssl-collector %s\n", k1, k2))

	if err := sign.VerifyNodeBound(keys, signedFor(t, "openssl-collector", "web-01", p1)); err != nil {
		t.Fatalf("own node, own key: %v", err)
	}
	if err := sign.VerifyNodeBound(keys, signedFor(t, "network-collector", "web-01", p1)); err != nil {
		t.Fatalf("another collector listed on the same line: %v", err)
	}
	err := sign.VerifyNodeBound(keys, signedFor(t, "openssl-collector", "web-02", p1))
	if err == nil || !strings.Contains(err.Error(), "does not match the keys registered for openssl-collector on web-02") ||
		!strings.Contains(err.Error(), "matches a key registered for network-collector on web-01, openssl-collector on web-01") {
		t.Fatalf("web-01's key naming web-02: %v", err)
	}
	if err := sign.VerifyNodeBound(keys, signedFor(t, "openssl-collector", "web-03", p1)); err == nil ||
		!strings.Contains(err.Error(), `no key is registered for collector "openssl-collector" on node "web-03"`) {
		t.Fatalf("unlisted node: %v", err)
	}
	if err := sign.VerifyNodeBound(keys, signedFor(t, "jvm-collector", "web-01", p1)); err == nil {
		t.Fatal("a collector not on the line passed")
	}
	u := signedFor(t, "openssl-collector", "web-01", p1)
	u.Envelope.Signature = ""
	if err := sign.VerifyNodeBound(keys, u); !errors.Is(err, sign.ErrNoSignature) {
		t.Fatalf("unsigned: %v", err)
	}
	if e, ok := keys.Match(signedFor(t, "openssl-collector", "web-02", p1)); !ok || e.Line != 1 {
		t.Fatalf("match: %+v %v", e, ok)
	}
}

// `*` 줄은 어느 노드에나 맞는다. 교체(같은 노드·수집기에 줄 둘)는 둘 다 통과한다. 같은 키를 두 노드에 적으면
// 두 노드가 구별되지 않는다(대조). self-id(node:…)도 노드로 적을 수 있다.
func TestNodeKeysAnyRotationShared(t *testing.T) {
	kc, pc, _ := sign.Generate()
	ko, po, _ := sign.Generate()
	kn, pn, _ := sign.Generate()
	ks, ps, _ := sign.Generate()
	keys := mustParse(t, fmt.Sprintf(`# central tools
*  attribution-importer,declaration-importer  %s
web-01 openssl-collector %s
web-01 openssl-collector %s   # new key during rotation
web-02 openssl-collector %s
web-03 openssl-collector %s
node:3f9a1c openssl-collector %s
`, kc, ko, kn, ks, ks, ko))
	for _, n := range []string{"web-01", "web-02", "anything"} {
		if err := sign.VerifyNodeBound(keys, signedFor(t, "attribution-importer", n, pc)); err != nil {
			t.Fatalf("* entry on %s: %v", n, err)
		}
	}
	if err := sign.VerifyNodeBound(keys, signedFor(t, "openssl-collector", "web-01", pc)); err == nil {
		t.Fatal("a central key passed for a node collector")
	}
	for _, p := range []string{po, pn} {
		if err := sign.VerifyNodeBound(keys, signedFor(t, "openssl-collector", "web-01", p)); err != nil {
			t.Fatalf("rotation: %v", err)
		}
	}
	for _, n := range []string{"web-02", "web-03"} {
		if err := sign.VerifyNodeBound(keys, signedFor(t, "openssl-collector", n, ps)); err != nil {
			t.Fatalf("shared key on %s: %v", n, err)
		}
	}
	if err := sign.VerifyNodeBound(keys, signedFor(t, "openssl-collector", "node:3f9a1c", po)); err != nil {
		t.Fatalf("self-id node: %v", err)
	}
}

// 설정 오류는 줄 번호를 말하고 키 값을 내지 않는다.
func TestParseNodeKeyFileErrors(t *testing.T) {
	k, _, _ := sign.Generate()
	short := "AAAA"
	for name, c := range map[string]struct{ in, want string }{
		"two fields":   {"web-01 " + k, "line 1: want 3 fields"},
		"four fields":  {"web-01 openssl-collector " + k + " extra", "want 3 fields"},
		"empty id":     {"web-01 openssl-collector,, " + k, "empty collector ID"},
		"not base64":   {"web-01 openssl-collector not!base64", "not base64"},
		"length":       {"web-01 openssl-collector " + short, "the key is 3 bytes"},
		"host://local": {"host://local openssl-collector " + k, "host://local means"},
		"duplicate":    {"web-01 openssl-collector " + k + "\n\nweb-01 jvm-collector,openssl-collector " + k, "line 3 (web-01, openssl-collector): the same key is listed again (first on line 1)"},
		"empty":        {"# nothing\n\n", "no entries"},
	} {
		_, err := sign.ParseNodeKeyFile([]byte(c.in))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), k) {
			t.Errorf("%s: the message prints the key", name)
		}
	}
	// 같은 키를 다른 노드에, 다른 수집기에 적는 것은 오류가 아니다.
	if _, err := sign.ParseNodeKeyFile([]byte("web-01 openssl-collector " + k + "\nweb-02 openssl-collector " + k)); err != nil {
		t.Fatal(err)
	}
}
