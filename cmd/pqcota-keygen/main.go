// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-keygen — collector 리포트 서명용 ed25519 키쌍을 생성한다(§2.6).
// 개인키는 노드 스캐너(PQCOTA_SIGN_KEY)에, 공개키는 중앙 적재(PQCOTA_VERIFY_KEY)에 등록한다.
// 같은 형식의 키쌍을 계획 승인 서명에도 쓴다(pqcota-approve의 PQCOTA_APPROVAL_KEY, pqcota-provision의
// PQCOTA_APPROVAL_KEYS). 두 단계가 함께 쓰므로 discovery가 아니라 공통에 둔다.
//
// usage: pqcota-keygen [-collector <id>]
//
//	-collector : 이 키로 서명할 수집기 ID. 주면 검증 줄을 ID 결합 꼴(`<id>:<pub>`)로 낸다. 안 주면 공개키만
//	             낸다(지금까지와 같은 줄이라 그 줄을 읽는 스크립트가 깨지지 않는다). ID는 적재기에 적을 때 붙인다.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
)

func main() {
	collector := flag.String("collector", "", "collector ID this key signs for — prints PQCOTA_VERIFY_KEY as <id>:<pub>")
	flag.Parse()
	pub, priv, err := sign.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	fmt.Printf("# sign on the node scanner: export PQCOTA_SIGN_KEY=<priv>\n")
	fmt.Printf("PQCOTA_SIGN_KEY=%s\n\n", priv)
	if *collector != "" {
		fmt.Printf("# verify at central ingest, bound to the collector ID (comma-separated for several): export PQCOTA_VERIFY_KEY=<collector-id>:<pub>\n")
		fmt.Printf("PQCOTA_VERIFY_KEY=%s:%s\n", *collector, pub)
		return
	}
	fmt.Printf("# verify at central ingest, bound to the collector ID (comma-separated for several): export PQCOTA_VERIFY_KEY=<collector-id>:<pub>\n")
	fmt.Printf("# (a bare <pub> list is the legacy form — it does not tell which collector a key belongs to)\n")
	fmt.Printf("PQCOTA_VERIFY_KEY=%s\n", pub)
}
