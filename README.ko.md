[English](README.md) · 한국어

# pqcota-common

pqcota 플랫폼의 공유 계약과 공유 코드입니다.

단계를 건너는 모든 메시지의 단일 정보원(SSOT)인 protobuf 계약, 그 계약에서 생성한 Go 코드, 모든 단계가 함께 쓰는 어휘와 도우미 코드가 들어 있습니다. [pqcota](https://github.com/randyinthedev-hash/pqcota)를 이루는 리포지터리 다섯 개 중 하나입니다. 다섯 개는 `pqcota-common`, `pqcota-inventory`, `pqcota-discovery`, `pqcota-provisioning`, 그리고 통합 리포지터리 `pqcota`(데모, 예제, 릴리스 번들, 기여 안내)입니다.

## 들어 있는 것

| 경로 | 내용 |
|---|---|
| `contracts/` | protobuf 계약 `pqcota.{common,discovery,inventory,provisioning}.v1`입니다. [contracts/README.ko.md](contracts/README.ko.md)와 [data-model.ko.md](contracts/data-model.ko.md)부터 읽으세요 |
| `gen/` | 계약에서 생성한 Go 코드이며 **커밋되어 있으므로** 소비하는 쪽은 `go get`만 하면 됩니다 |
| `pkg/kernel/` | 공유 로직입니다: `registry`, `posture`, `scope`, `machineid`, `sign`, `completeness` |
| `pkg/org/` | 스토어(store)를 조직 단위로 나누는 코드입니다 |
| `cmd/` | `pqcota-keygen`입니다. 수집기 서명과 계획 승인이 모두 쓰는 ed25519 키 생성기입니다([cmd/README.ko.md](cmd/README.ko.md)) |

## 의존하는 것

이 패밀리 안에는 없습니다. 다른 pqcota 모듈이 모두 이 모듈에 의존하므로, 이 모듈은 그중 어느 것도 import하지 않습니다.

## 빌드와 테스트

```bash
make            # every check of this repository
go test ./...   # unit tests only
```

`make generate`는 `contracts/`에서 `gen/`을 다시 생성합니다(`buf`, `protoc-gen-go`, `protoc-gen-go-grpc`가 필요하며, `make tools`가 두 플러그인을 설치합니다). `make lint`와 `make breaking`은 계약을 점검하고, `make breaking`은 가장 최근 릴리스 태그와 비교합니다.

`pqcota-common`에는 형제 의존성이 없으므로 `go.mod`에 `replace` 지시문이 없습니다. 나머지 네 리포지터리는 각자의 `go.mod`를 통해 `../pqcota-common`에서 이 모듈을 읽으므로, 리포지터리를 나란히 클론하세요. [빌드 안내](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/build.ko.md#소스-받기)를 보세요.

## 기여 · 보안 · 라이선스

기여와 보안 신고 방법은 [pqcota 리포지터리](https://github.com/randyinthedev-hash/pqcota)에 설명되어 있습니다. 라이선스는 [Apache-2.0](https://github.com/randyinthedev-hash/pqcota/blob/main/LICENSE)(영문)입니다.
