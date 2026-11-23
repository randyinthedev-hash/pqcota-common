// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-keygen — collector 리포트 서명용 ed25519 키쌍을 생성한다(§2.6).
// 개인키는 노드 스캐너(PQCOTA_SIGN_KEY)에, 공개키는 중앙 적재(PQCOTA_VERIFY_KEY)에 등록한다.
// 같은 형식의 키쌍을 계획 승인 서명에도 쓴다(pqcota-approve의 PQCOTA_APPROVAL_KEY, pqcota-provision의
// PQCOTA_APPROVAL_KEYS). 두 단계가 함께 쓰므로 discovery가 아니라 공통에 둔다.
//
// usage: pqcota-keygen [-collector <id>[,<id>…]] [-node <node-id>]
//
//	-collector : 이 키로 서명할 수집기 ID(콤마로 여럿). 주면 검증 줄을 ID 결합 꼴(`<id>:<pub>`)로 낸다. 안 주면 공개키만
//	             낸다(지금까지와 같은 줄이라 그 줄을 읽는 스크립트가 깨지지 않는다). ID는 적재기에 적을 때 붙인다.
//	-node      : 이 키를 나눠 줄 노드 ID. 주면 키 파일(PQCOTA_VERIFY_KEY_FILE)의 한 줄도 낸다. -collector가 필요하다.
//	             노드에 묶기 전, 지금의 검증 목록에 새 공개 키를 먼저 더할 때 쓰도록 결합 꼴 줄도 함께 낸다.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/version"
)

func main() {
	version.ExitIfRequested(os.Args[1:]) // 단독 --version·-version만 처리한다. 섞인 호출은 아래 규칙대로
	collector := flag.String("collector", "", "collector ID(s) this key signs for, comma-separated — prints PQCOTA_VERIFY_KEY as <id>:<pub>")
	node := flag.String("node", "", "node ID this key is given to — also prints the line for the key file (PQCOTA_VERIFY_KEY_FILE); needs -collector")
	flag.Parse()
	var ids []string
	for _, c := range strings.Split(*collector, ",") {
		if c = strings.TrimSpace(c); c != "" {
			ids = append(ids, c)
		}
	}
	if *node != "" && len(ids) == 0 {
		fmt.Fprintln(os.Stderr, "keygen: -node needs -collector (the collector IDs this node key signs for)")
		os.Exit(2)
	}
	if *node == sign.UnknownNode || strings.ContainsAny(*node, " \t#") {
		fmt.Fprintf(os.Stderr, "keygen: %q cannot be a node in the key file\n", *node)
		os.Exit(2)
	}
	pub, priv, err := sign.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	fmt.Printf("# sign on the node scanner: export PQCOTA_SIGN_KEY=<priv>\n")
	fmt.Printf("PQCOTA_SIGN_KEY=%s\n\n", priv)
	if len(ids) > 0 {
		entries := make([]string, len(ids))
		for i, id := range ids {
			entries[i] = id + ":" + pub
		}
		fmt.Printf("# verify at central ingest, bound to the collector ID (comma-separated for several): export PQCOTA_VERIFY_KEY=<collector-id>:<pub>\n")
		fmt.Printf("PQCOTA_VERIFY_KEY=%s\n", strings.Join(entries, ","))
		if *node != "" {
			fmt.Printf("\n# the line for the key file (PQCOTA_VERIFY_KEY_FILE), bound to the node: <node-id> <collector-ids> <pub>\n")
			fmt.Printf("%s %s %s\n", *node, strings.Join(ids, ","), pub)
		}
		return
	}
	fmt.Printf("# verify at central ingest, bound to the collector ID (comma-separated for several): export PQCOTA_VERIFY_KEY=<collector-id>:<pub>\n")
	fmt.Printf("# (a bare <pub> list is the legacy form — it does not tell which collector a key belongs to)\n")
	fmt.Printf("PQCOTA_VERIFY_KEY=%s\n", pub)
}
