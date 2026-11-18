// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// AnyNode — 키 파일에서 어느 노드에나 맞는 줄의 노드 칸. 여러 노드를 한 번에 서명하는 중앙 도구(선언)용이다.
const AnyNode = "*"

// UnknownNode — 수집기가 노드를 모를 때 적는 이름. 모든 머신이 이 이름을 쓸 수 있으므로 키 파일에 적을 수 없다.
const UnknownNode = "host://local"

// NodeKey — 키 파일의 한 줄. 이 키는 Node(또는 AnyNode)에서 Collectors 가운데 하나로 서명한 결과에만 맞는다.
type NodeKey struct {
	Line       int
	Node       string
	Collectors []string
	Key        string // base64 공개 키
}

// NodeKeys — 키 파일을 읽은 것. 한 번 파싱한 뒤 바뀌지 않는다(한 실행 내내 같은 판정).
type NodeKeys struct {
	entries []NodeKey
}

// ParseNodeKeyFile — 키 파일의 바이트를 읽는다. 줄마다 공백으로 나눈 세 칸: 노드 ID, 수집기 ID 목록(콤마),
// base64 ed25519 공개 키. `#`부터 줄 끝까지는 주석이다. 오류 메시지는 줄 번호만 말하고 키 값을 내지 않는다.
//
// 막는 것: 칸 수, 빈 수집기 ID, base64 아님, 길이, 노드 칸의 host://local, 같은 (노드, 수집기, 키)의 반복, 줄이 하나도 없음.
// 경고할 일(같은 키를 여러 노드에, 노드에서 도는 수집기에 `*`)은 판정하지 않는다 — 쓰는 쪽이 [NodeKeys.Entries]로 본다.
//
// GATE: 배선 필수 — pqcota-ingest의 PQCOTA_VERIFY_KEY_FILE.
func ParseNodeKeyFile(data []byte) (*NodeKeys, error) {
	type seenKey struct{ node, collector, key string }
	seen := map[seenKey]int{}
	k := &NodeKeys{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := i + 1
		if j := strings.IndexByte(raw, '#'); j >= 0 {
			raw = raw[:j]
		}
		f := strings.Fields(raw)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("line %d: want 3 fields (node ID, collector IDs, public key), got %d", line, len(f))
		}
		node, key := f[0], f[2]
		if node == UnknownNode {
			return nil, fmt.Errorf("line %d: %s means the collector did not know its node — every machine can use that name, so it cannot be bound to a key", line, UnknownNode)
		}
		var cols []string
		for _, c := range strings.Split(f[1], ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				return nil, fmt.Errorf("line %d (%s): an empty collector ID in the list", line, node)
			}
			cols = append(cols, c)
		}
		pk, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): the key is not base64", line, node)
		}
		if len(pk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("line %d (%s): the key is %d bytes, an ed25519 public key is %d", line, node, len(pk), ed25519.PublicKeySize)
		}
		for _, c := range cols {
			sk := seenKey{node, c, key}
			if first, ok := seen[sk]; ok {
				return nil, fmt.Errorf("line %d (%s, %s): the same key is listed again (first on line %d)", line, node, c, first)
			}
			seen[sk] = line
		}
		k.entries = append(k.entries, NodeKey{Line: line, Node: node, Collectors: cols, Key: key})
	}
	if len(k.entries) == 0 {
		return nil, errors.New("the key file has no entries")
	}
	return k, nil
}

// Entries — 파싱한 줄들(복사본).
func (k *NodeKeys) Entries() []NodeKey {
	out := make([]NodeKey, len(k.entries))
	for i, e := range k.entries {
		e.Collectors = append([]string(nil), e.Collectors...)
		out[i] = e
	}
	return out
}

func (e NodeKey) covers(collector string) bool {
	for _, c := range e.Collectors {
		if c == collector {
			return true
		}
	}
	return false
}

// For — (수집기, 노드)에 맞는 줄. 노드가 같은 줄과 노드 칸이 `*`인 줄. 줄 순서대로.
func (k *NodeKeys) For(collector, node string) []NodeKey {
	var out []NodeKey
	for _, e := range k.entries {
		if e.covers(collector) && (e.Node == node || e.Node == AnyNode) {
			out = append(out, e)
		}
	}
	return out
}

// Match — 결과의 서명이 맞는 줄. 그 결과의 (수집기, 노드)에 맞는 줄을 먼저 본다. 점검 표(-verify-keys)가 어느 줄의
// 키가 서명했는지 보이려고 쓴다. 판정은 [VerifyNodeBound]가 한다.
func (k *NodeKeys) Match(res *discoveryv1.CollectionResult) (NodeKey, bool) {
	env := res.GetEnvelope()
	for _, e := range k.For(env.GetCollectorId(), env.GetTargetNodeId()) {
		if Verify([]string{e.Key}, res) {
			return e, true
		}
	}
	for _, e := range k.entries {
		if Verify([]string{e.Key}, res) {
			return e, true
		}
	}
	return NodeKey{}, false
}

// VerifyNodeBound — 결과에 적힌 (수집기 ID, target_node_id)에 등록된 키로만 서명을 확인한다. 노드 칸이 `*`인
// 줄은 어느 노드에나 맞는다. 서명이 없거나, 맞는 줄이 없거나, 맞는 줄의 키와 맞지 않으면 오류다. 다른 줄의
// 키로 다시 시도하지 않는다. 맞지 않을 때 다른 줄의 키와 맞으면 그 줄을 사유에 붙인다(키가 어디서 왔는지 보이게).
//
// 서명이 노드를 덮으므로(Canonical의 target_node_id) 노드 이름을 바꾼 결과는 그 노드의 키로 다시 서명해야 한다.
// 본문이 가리키는 노드(엣지의 src_node_id)는 여기서 보지 않는다 — 적재기가 따로 본다.
//
// GATE: 배선 필수 — pqcota-ingest의 PQCOTA_VERIFY_KEY_FILE.
func VerifyNodeBound(k *NodeKeys, res *discoveryv1.CollectionResult) error {
	env := res.GetEnvelope()
	id, node := env.GetCollectorId(), env.GetTargetNodeId()
	if !strings.HasPrefix(env.GetSignature(), Prefix) {
		return ErrNoSignature
	}
	own := k.For(id, node)
	if len(own) == 0 {
		return fmt.Errorf("no key is registered for collector %q on node %q", id, node)
	}
	for _, e := range own {
		if Verify([]string{e.Key}, res) {
			return nil
		}
	}
	msg := fmt.Sprintf("signature does not match the keys registered for %s on %s", id, node)
	seen := map[string]bool{}
	var others []string
	for _, e := range k.entries {
		if !Verify([]string{e.Key}, res) {
			continue
		}
		for _, c := range e.Collectors {
			s := c + " on " + e.Node
			if !seen[s] {
				seen[s] = true
				others = append(others, s)
			}
		}
	}
	if len(others) > 0 {
		sort.Strings(others)
		msg += "; it matches a key registered for " + strings.Join(others, ", ")
	}
	return errors.New(msg)
}
