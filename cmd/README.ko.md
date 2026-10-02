[English](README.md) · 한국어

# cmd/: 단계 하나에 속하지 않는 명령

여기 있는 명령 하나는 둘 이상의 단계가 함께 쓰므로, 어느 단계에도 넣지 않고 공유 모듈에 둡니다.

### `pqcota-keygen`

```
pqcota-keygen
```

인자는 없습니다. **ed25519 키 쌍**을 만들어 표준 출력으로 내보냅니다. 같은 종류의 키 쌍이 서로 다른 두 가지에 서명하므로, 출력은 줄마다 그 값이 갈 자리를 이름으로 밝힙니다.

| 출력되는 것 | 놓는 곳 | 쓰는 쪽 |
|---|---|---|
| `PQCOTA_SIGN_KEY`(개인 키) | 수집기가 실행되는 노드 | 수집기 결과에 서명합니다. [pqcota-discovery cmd · 권한 · 환경변수](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.md#privileges--environment-variables)(영문) |
| `PQCOTA_VERIFY_KEY`(공개 키) | `pqcota-ingest`가 실행되는 중앙 | 수집기 서명을 검증합니다. 키가 여럿이면 쉼표로 구분합니다 |

**계획 승인**에는 같은 두 값을 승인 명령이 읽는 이름으로 씁니다. 개인 키는 [`pqcota-approve`](https://github.com/randyinthedev-hash/pqcota-provisioning/blob/main/cmd/README.md#pqcota-approve)(영문)가 읽는 `PQCOTA_APPROVAL_KEY`로, `<approver>=<public key>`는 [`pqcota-provision`](https://github.com/randyinthedev-hash/pqcota-provisioning/blob/main/cmd/README.md#pqcota-provision)(영문)이 읽는 `PQCOTA_APPROVAL_KEYS`로 씁니다. 역할마다 키 쌍을 따로 쓰세요. 수집기 결과에 서명하는 키가 계획도 승인해서는 안 됩니다.

**개인 키는 표준 출력으로 나옵니다.** 파일로 리디렉션하면 그 파일이 남고, 셸에 붙여 넣으면 히스토리에 남습니다.

**수집기 결과 서명은 선택입니다.** 키가 없어도 막히는 것은 없고, 대신 중앙이 *"unverified signatures: N"*이라고 보고합니다. 서명이 틀렸다는 뜻이 아니라 **한 번도 검증하지 않았다**는 뜻입니다. 검증할 키가 없을 때 적재를 아예 거부하려면 `PQCOTA_REQUIRE_SIGNATURE=1`을 설정합니다. 반면 승인은 선택이 아닙니다. `pqcota-provision`은 검증할 수 없는 계획을 거부하며, 명령줄에 `--allow-unverified-approvals`를 적었을 때만 예외입니다.
