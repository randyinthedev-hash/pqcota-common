[English](README.md) · 한국어

# pqcota/contracts: 계약 SSOT(단일 정보원)


이 디렉터리에는 PQC 이관 플랫폼의 모든 구성 요소가 의존하는 **계약 하나**가 있습니다.

보조 문서:
- [**데이터 모델 스키마**](data-model.ko.md): 모든 메시지와 열거형의 목적, 주요 필드, 관계도입니다(사람이 읽는 참조 문서). 아래 파일 목록보다 먼저 읽으면 전체 그림이 한눈에 잡힙니다.

## 파일

네임스페이스는 **제품 단계 셋과 공유 어휘 하나**로 나뉩니다(`pkg/`와 대칭입니다). 네임스페이스만 보면 그 계약이 어느 단계에 속하는지 알 수 있습니다.

| 파일 | 패키지 | 정의하는 것 |
|---|---|---|
| `proto/pqcota/common/v1/common.proto` | `pqcota.common.v1` | 공유 어휘: Envelope, 완전성, 통제 어휘 열거형(모든 단계를 가로지릅니다) |
| `proto/pqcota/discovery/v1/cbom.proto` | `pqcota.discovery.v1` | 파생된 Finding · OpensslAxes · JcaAxes |
| `proto/pqcota/discovery/v1/collector.proto` | `pqcota.discovery.v1` | 수집기 접수 gRPC 서비스 · CollectionResult |
| `proto/pqcota/discovery/v1/edge.proto` | `pqcota.discovery.v1` | 통신 연결 간선 관측 · ObservedEdge · QuantumPosture |
| `proto/pqcota/discovery/v1/asset.proto` | `pqcota.discovery.v1` | 자산 계층 · Application · ProcessMatch · LiveProcess (Machine→App→Process) |
| `proto/pqcota/inventory/v1/decision.proto` | `pqcota.inventory.v1` | 검토 판정 · Decision · DecisionStatus · DecisionConclusion |
| `proto/pqcota/inventory/v1/machine.proto` | `pqcota.inventory.v1` | 사람이 읽는 머신 프로필 · MachineProfile · Environment (표시 이름, 환경, 역할, 소유자, 태그) |
| `proto/pqcota/provisioning/v1/plan.proto` | `pqcota.provisioning.v1` | 확정된 계획 · FinalizedPlan · RemediationAction · RemediationKind · DeployAutomationLevel |
| `proto/pqcota/provisioning/v1/rollback.proto` | `pqcota.provisioning.v1` | 전환물 생성 이력과 되돌림 · ProvisioningRecord · CryptoState (변경 전/후) |

> `common`은 pkg/kernel에 대응하는 계약 쪽입니다. 어느 한 단계에도 속하지 않는 공유 어휘(CryptoRuntime, DetectionMethod, Envelope, Completeness 등)만 담습니다. 생성되는 Go 패키지: `gen/pqcota/{common,discovery,inventory,provisioning}/v1` → `commonv1`, `discoveryv1`, `inventoryv1`, `provisioningv1`. `Decision`과 `FinalizedPlan`의 **스키마는 SSOT**입니다(소비하는 엔진이 같은 어휘를 쓰도록 하기 위해서입니다).

## 소비하는 쪽의 사용법

**생성 코드(`gen/`)는 커밋되어 있습니다.** 계약이 정말로 SSOT이려면 그 코드가 소비되는 자리에 있어야 합니다. 소비하는 쪽에 `buf`와 protoc 플러그인을 설치하라고 요구하면 계약이 아니라 빌드 절차를 공유하는 셈입니다.

```go
import (
	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)
```

> **이 리포지터리를 `pqcota`에서 분리하면서 모듈 경로가 바뀌었습니다.** 계약과 `gen/`은 예전에
> `github.com/randyinthedev-hash/pqcota`의 `gen/...` 패키지였습니다. 지금은 모듈
> `github.com/randyinthedev-hash/pqcota-common`에 있으므로, 소비하는 쪽은 import를
> `github.com/randyinthedev-hash/pqcota/gen/...`에서 `github.com/randyinthedev-hash/pqcota-common/gen/...`로 옮기고,
> `pqcota` 대신 `pqcota-common`을 require해야 합니다.

생성 코드는 손으로 고치지 않습니다. proto를 고친 뒤 `make generate`를 실행합니다. CI가 변경마다 둘이 어긋나지 않았는지 점검합니다.

## 핵심 설계 결정 (시작하기 전에 읽으세요)

### 1. 책임 경계: 수집기는 보강하지 않는다

```
Collector    →  steps 1–2 : raw capture + conversion to standard CycloneDX + Envelope
Normalization →  steps 3–6 : enrich → validate → resolve identity → persist → derive Finding[]
```

- 수집기 출력(`CollectionResult`)에는 **`Finding`이 없습니다.** 표준 CycloneDX와 Envelope만 돌려줍니다.
- **해석이 필요한 보강**(`evidence_strength`, `pqc_readiness`, 포크 판정)은 **코어만 합니다.**
  이유: 보강 규칙(매핑 표)이 개선되면 결과를 **원본에서 다시 계산**해야 하는데, 보강이 수집기마다 흩어져 있으면 다시 계산할 수 없고 규칙도 서로 어긋납니다. 보강은 한 곳에 둡니다.
- 그래서 `Finding.derived_from_snapshot_id`와 `ruleset_version`은 필수입니다. 파생 결과가 어느 원본과 어느 규칙에서 나왔는지 언제나 추적하고 재현할 수 있습니다(감사 무결성).

### 2. `unknown`은 일급 값이다

모든 열거형의 `*_UNSPECIFIED = 0`은 "판단할 수 없음 = 알 수 없음"을 뜻합니다.
채우지 못한 필드는 빈 칸이나 누락이 아니라 **명시적인 0 값**으로 둡니다.
이것을 아무 표시 없이 "없음"으로 취급하지 마세요. "정말로 없는 것"과 "원리상 관측할 수 없는 것"은 `Completeness.layers_missing`으로 구분합니다.

### 3. provider 서명 레지스트리가 보강을 이끈다

`JcaAxes.provider_set`(등록 순서 포함)은 수집기가 관측한 **원본**입니다.
코어의 보강 단계는 이것을 provider 서명 레지스트리와 비교해 `pqc_readiness`, `fips_validation`, 알고리즘 지원 범위를 **도출합니다**(BouncyCastle / BC-FJA / JDK 기본 제공 / openssl-jostle / 자체 개발 구분).
- **SLH-DSA는 JDK에 기본으로 들어 있지 않습니다.** 이것이 필요한 자산은 JDK 버전과 관계없이 BC나 jostle에 의존하는 것으로 태그합니다.
- `fips_validation` 요구는 Deploy 단계에서 **FIPS 검증을 받은 provider를 쓰라는 권장 사항**(FIPS 라우팅)으로 드러납니다. 도구는 계획이 고른 provider를 막지 않습니다. 검증 인증서는 빌드마다 따로 있고, 파일만으로는 알 수 없기 때문입니다.
- 레지스트리는 파생 규칙이므로 `ruleset_version`으로 고정합니다. 개선되면 원본에서 다시 계산합니다.

### 4. `deploy_automation_level`은 계획의 속성이지 Discovery의 속성이 아니다

`DeployAutomationLevel`(L1/L2/L3)은 통제 어휘로 여기에 등록되어 있지만 **수집기는 채우지 않습니다.**
검토자가 자산마다 정하는 계획/자산 속성(MANUAL)이며, 계획 엔티티에 실립니다(워크플로는 계획 쪽에 있습니다).
Discovery의 `Finding`에는 이 필드가 없습니다. 단계를 혼동하지 않도록 일부러 분리한 것입니다.

### 5. gRPC 경계는 GPL 전염 차단벽이다([라이선스 안내](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/licensing.ko.md))

`Collector` 서비스 경계는 라이선스 격리 경계이기도 합니다.
GPL 수집기(예를 들어 CipherIQ의 `cbom-generator`)는 **별도 프로세스**로 실행되고
**표준 출력으로 CycloneDX만 주고받습니다.** 코어는 그것을 라이브러리로 링크하지 않습니다.
`CollectorCapabilities.license`는 그 영향을 사용자에게 드러냅니다([라이선스 안내](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/licensing.ko.md)).

### 6. 계획 스키마는 공개 계약이다

`plan.proto`(`FinalizedPlan`, `RemediationAction`, `RemediationKind`)는 SSOT이므로 **OSS**입니다. 전환물 생성기(`pkg/provisioning`)와 실행 채널은 같은 어휘를 써야 합니다.
- **`Executable()` 게이트**("확정된 계획만 실행의 근거다")는 공유 계약 규칙이므로 OSS `pkg/provisioning`에 있습니다.
- 계획의 **작성과 검토 확정**, 그리고 **플릿 오케스트레이션**은 범위 밖입니다.
- 분류(`RemediationKind`)를 설정 조각으로 바꾸는 일은 결정론적 파생이므로 OSS 생성기가 맡습니다.
> `DeployAutomationLevel`과 계획 엔티티가 계획의 관심사라는 말은 *워크플로를 누가 소유하는가*를 뜻하며, *스키마가 어디에 있는가*를 뜻하지 않습니다.

## CycloneDX `properties` 확장 키 규약

도구 고유의 보강 정보는 표준 CycloneDX `properties`에 `pqcota:` 네임스페이스로 실립니다.
코어 파이프라인이 이 키를 읽어 타입이 있는 `Finding`에 대응시킵니다.

| property 키 | 값 | 대응하는 Finding 필드 |
|---|---|---|
| `pqcota:crypto_runtime` | `openssl` \| `jca` \| `cng` | `crypto_runtime` |
| `pqcota:detection_method` | `source`\|`artifact`\|`symbol-analysis`\|`runtime-introspection`\|`dynamic-trace` | `detection_method`: **어떻게 보았는가**. 증거 강도가 여기서 도출됩니다(실물을 직접 본 것이 추론보다 낫습니다) |
| `pqcota:usage_context` | `server`\|`client`\|`at-rest`\|`signing` | `usage_context` |
| `pqcota:openssl.fork` | `OpenSSL`\|`BoringSSL`\|… | `openssl.fork` |
| `pqcota:openssl.binding_mode` | `dynamic`\|`static`\|`dlopen`\|`vendored` | `openssl.binding_mode` |
| `pqcota:jca.provider_set` | 등록 순서대로 CSV | `jca.provider_set` |
| `pqcota:jca.registration_mode` | `static`\|`dynamic`\|`explicit` | `jca.registration_mode` |
| `pqcota:cng.provider_set` | 등록 순서대로 CSV | `cng.provider_set`: Windows CNG. **관측한 그대로**(정렬하지 않습니다). 그 순서가 우선순위인지는 CNG에서 확인되지 않았습니다 |
| `pqcota:cng.algorithms` | `name:kind[:provider\|provider]`의 CSV (예: `ML-DSA:signature:Microsoft Primitive Provider`) | `cng.algorithms`: 종류를 알 수 없으면 값이 **비고**, provider를 물어볼 수 없었으면 **세 번째 필드를 생략합니다**. CNG 이름에는 쉼표, 콜론, `\|`가 들어 있지 않습니다(측정함) |
| `pqcota:app_keys` | 앱 키의 CSV (공유 .so에는 여럿이 있습니다) | `app_keys`(repeated): 자산 귀속 |

> `evidence_strength`와 `pqc_readiness`는 **여기에 넣지 않습니다.** 코어가 도출하는 값입니다(위 결정 1).

> **외부 수집기를 위한 안내: `pqcota:detection_method`를 반드시 실어야 합니다.** 코어는 `detection_method`에서
> `evidence_strength`를 결정론적으로 도출합니다. 이 키가 없으면 코어는 증거 강도를 지어내지 않고
> 정직하게 `UNSPECIFIED`로 떨어뜨립니다(알 수 없음이 일급이고 추측하지 않습니다). 이것은
> **잊은 데 대한 벌칙이 아니라 정해진 결과입니다.** 표준 CycloneDX만 내보내는 수집기(CBOMkit 등)는
> `cryptoProperties`를 이 키들로 옮기는 가져오기 어댑터를 거쳐야 강도가 살아남습니다. 그 대응을 거치지 않고
> 들어온 자산은 강도가 알 수 없음으로 남습니다.

## 버전 규칙과 호환성 규칙

- 패키지는 `pqcota.{common,discovery,inventory,provisioning}.v1`입니다. **호환을 깨는 변경은 새 `v2`입니다.** `v1` 필드 번호를 다시 쓰거나 의미를 바꾸지 마세요.
- 필드를 없앨 때는 그 번호를 `reserved`로 표시합니다. 열거형 값을 더하는 것은 하위 호환입니다(항상 맨 끝에 붙입니다).
- 이 계약은 이 리포지터리(Apache-2.0)에 속합니다. 정본 CBOM 스키마와 프로필은 공개입니다([라이선스 안내, 5절](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/licensing.ko.md#5-카피레프트-격리-무엇이-지키는가)).

## 계약을 바꿀 때: 파급 확인

proto를 고치는 것으로 끝나지 않습니다. **코드에는 계약에서 파생된 것이 둘 있습니다. 첫째는 테스트가 지키고, 둘째는 아무것도 지키지 않으므로 잊으면 빌드는 통과하는데 동작만 깨집니다.**

| 함께 볼 것 | 언제 | 잊으면 |
|---|---|---|
| [`sign.Canonical`](../pkg/kernel/sign) | `CollectionResult`, `Envelope`, `MachineIdentity`, `Completeness`, `ObservedEdge`에 **필드를 더할 때** | 새 필드가 **서명의 사각지대**가 됩니다. 그 필드를 위조해도 검증이 통과합니다.<br>범위를 넓히면 **기존 서명이 모두 무효가 되므로**, 릴리스 뒤에는 이전(migration)이 필요합니다 |
| [`history.ContentHashV1`](https://github.com/randyinthedev-hash/pqcota-inventory/tree/main/pkg/inventory/history)(스냅샷 지문) | `Finding`, `ObservedEdge`, `Completeness`에 **실질 내용 필드를 더할 때** | 그 필드의 변경이 "변경 없음"으로 합쳐져 **아무 표시 없이 이력에서 사라집니다.** **고정된 v1을 고치지 마세요.** 반영해야 하는 필드는 새 지문 형식 버전이 필요하며, 저장, 조회, 하류 소비자와 함께 설계해야 합니다 |

**첫째는 테스트가 지켜봅니다.** 필드 수가 바뀌면 `TestCanonicalCoversAllFields`가 실패하고(계획은 `TestCanonicalPlanCoversAllFields`) 무엇을 해야 하는지 알려 줍니다. 기대값을 고쳐서 실패를 넘기지 마세요. 사각지대는 정확히 그렇게 만들어집니다. **둘째는 지켜보는 테스트가 없으므로** 지문을 손으로 확인하세요. 단계별 안내는 [계약 변경하기](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/change-a-contract.ko.md)에 있습니다.

**파생 규칙을 바꿨다면** `ruleset_version`을 올리세요. 파생 값은 저장된 값이 아니라 규칙의 함수이므로, 수집기 원본 결과를 **보관해 두었다면** 과거 판정을 그 원본에서 **다시 계산할 수 있습니다.** 인벤토리 스냅샷에는 원본 결과가 없고, 과거를 대신 다시 계산해 주는 명령도 없습니다.

**순서에 의미가 있는 필드**에 주의하세요. `JcaAxes.provider_set`의 등록 순서는 우선순위 협상을 결정하므로 정렬하거나 정규화하지 않습니다.

## 코드 생성

```bash
# gen/ is committed — regenerate it and put it in the same commit only when the contract changes
make generate                              # = cd contracts && buf generate
cd contracts && buf lint                   # or make lint

# compatibility checks run **from the repo root** — .git is there and the protos are under contracts/, so a subdir is needed
buf breaking contracts --against '.git#branch=main,subdir=contracts'
buf breaking contracts --against '.git#ref=HEAD~1,subdir=contracts'   # against the previous commit
```
