[English](README.md) · 한국어

# cmd/: 단계 하나에 속하지 않는 명령

여기 있는 명령 하나는 둘 이상의 단계가 함께 쓰므로, 어느 단계에도 넣지 않고 공유 모듈에 둡니다.

**모든 명령은 `--version`(또는 `-version`) 하나만 주면 판을 한 줄로 냅니다.** 예를 들면 `pqcota-keygen v0.19.0 (go1.26.11 linux/amd64)`이고, 다른 일은 하지 않습니다. 릴리스가 아닌 빌드는 `not a release build`라고 적습니다. 소스 커밋은 이 줄이 아니라 릴리스 manifest에 있습니다. 다른 인자와 함께 주면 `--version`도 여느 인자처럼 읽힙니다.

### `pqcota-keygen`

```
pqcota-keygen [-collector <id>[,<id>…]] [-node <node-id>]
```

**ed25519 키 쌍**을 만들어 표준 출력으로 내보냅니다. 같은 종류의 키 쌍이 서로 다른 두 가지에 서명하므로, 출력은 줄마다 그 값이 갈 자리를 이름으로 밝힙니다.

| 출력되는 것 | 놓는 곳 | 쓰는 쪽 |
|---|---|---|
| `PQCOTA_SIGN_KEY`(개인 키) | 수집기가 실행되는 노드 | 수집기 결과에 서명합니다. [pqcota-discovery cmd · 권한 · 환경변수](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.md#privileges--environment-variables)(영문) |
| `PQCOTA_VERIFY_KEY`(공개 키) | `pqcota-ingest`가 실행되는 중앙 | 수집기 서명을 검증합니다. `<collector-id>:<공개 키>`로 적으면 그 수집기의 결과에서만 통과합니다. `-collector <id>`를 주면 이 형식으로 출력합니다. 여럿이면 쉼표로 구분합니다. [키를 수집기 ID에 묶기](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/environment-variables.ko.md#키를-수집기-id에-묶기) |
| 키 파일의 한 줄(공개 키) | `PQCOTA_VERIFY_KEY_FILE`로 주는 중앙의 키 파일 | `-node <노드 ID> -collector <ID 목록>`을 주면 `<노드 ID> <수집기 ID 목록> <공개 키>` 줄도 출력합니다. 이 키를 그 노드의 수집기에만 나눠 주면 다른 노드의 결과에는 서명할 수 없습니다. [키를 노드에 묶기](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/environment-variables.ko.md#키를-노드에-묶기) |

**계획 승인**에는 같은 두 값을 승인 명령이 읽는 이름으로 씁니다. 개인 키는 [`pqcota-approve`](https://github.com/randyinthedev-hash/pqcota-provisioning/blob/main/cmd/README.md#pqcota-approve)(영문)가 읽는 `PQCOTA_APPROVAL_KEY`로, `<approver>=<public key>`는 [`pqcota-provision`](https://github.com/randyinthedev-hash/pqcota-provisioning/blob/main/cmd/README.md#pqcota-provision)(영문)이 읽는 `PQCOTA_APPROVAL_KEYS`로 씁니다. 역할마다 키 쌍을 따로 쓰세요. 수집기 결과에 서명하는 키가 계획도 승인해서는 안 됩니다.

**개인 키는 표준 출력으로 나옵니다.** 파일로 리디렉션하면 그 파일이 남고, 셸에 붙여 넣으면 히스토리에 남습니다.

**수집기 결과 서명은 선택입니다.** 키가 없어도 막히는 것은 없고, 대신 중앙이 *"unverified signatures: N"*이라고 보고합니다. 서명이 틀렸다는 뜻이 아니라 **한 번도 검증하지 않았다**는 뜻입니다. 검증할 키가 없을 때 적재를 아예 거부하려면 `PQCOTA_REQUIRE_SIGNATURE=1`을 설정합니다. 승인은 기본으로 확인합니다. `pqcota-provision`은 등록된 키로 확인되지 않는 승인을 거부합니다. 키가 하나도 등록되지 않았을 때만 `--allow-unverified-approvals`로 경고와 함께 계속할 수 있습니다.
