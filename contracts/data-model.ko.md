[English](data-model.md) · 한국어

# 데이터 모델 스키마 (계약 SSOT 참조)


계약 파일과 네임스페이스 목록, CycloneDX property 대응은 [contracts/README](README.ko.md)를 보세요.

## 0. 규약

- **네임스페이스 = 단계**: `pqcota.common.v1`(공유) · `pqcota.discovery.v1` · `pqcota.inventory.v1` · `pqcota.provisioning.v1`. 생성되는 Go 패키지는 `commonv1`, `discoveryv1`, `inventoryv1`, `provisioningv1`입니다.
- **protojson 표현**: 필드는 **camelCase**(`target_node_id`→`targetNodeId`), `bytes`는 **base64 문자열**(`cbom_cyclonedx`), 열거형은 **이름 문자열**(`"DETECTION_METHOD_RUNTIME_INTROSPECTION"`), `Timestamp`는 RFC3339입니다.
- **enum 0 = `*_UNSPECIFIED` = "알 수 없음"**. "없음"이 아니라 "판단할 수 없음"을 뜻하며, 완전성 맵과 함께 "정말로 없는 것"과 "원리상 관측할 수 없는 것"을 구분합니다.
- **하위 호환**: 필드 번호를 다시 쓰지 않고, 없앤 필드는 `reserved`로 표시하고, 열거형 값은 맨 끝에만 붙이고, 호환을 깨는 변경은 새 `v2`로 합니다.

## 1. 모델을 관통하는 원칙 네 가지

필드가 지금처럼 나뉜 이유를 설명합니다.

1. **출처 레인 분리**: 데이터가 어디서 왔는지에 따라 레인을 나눕니다. 서로 섞지 않습니다.
   - **관측(Observed)**: 수집기가 실제로 본 것입니다. `CollectionResult`, `ObservedEdge`, `MachineIdentity`.
   - **선언(Declared)**: CMDB나 사용자가 채운 것입니다. `MachineProfile`, 범위 마스터, 선언된 연결 간선.
   - **파생(Derived)**: 코어가 관측에서 **다시 계산하는** 뷰입니다. `Finding`, `evidence_strength`, `QuantumPosture`. **수집기 출력에는 없습니다.** 원본(raw)에서 언제든 다시 만들 수 있습니다(재현성).
   - **행위(Action)**: 도구가 한 일을 추가만 하는 기록입니다. `ProvisioningRecord`, `Decision`.
2. **식별 모델**: 세 겹입니다. **권위** = `node_id`(범위 마스터 / CMDB이며, 안정적이고 전역에서 유일합니다). **상관** = `MachineIdentity` 지문(machine-id, hw-uuid, cloud-id, fqdn으로 node_id를 검증하고, CMDB가 없으면 자체 ID를 도출합니다). **위치 지정자** = IP(ID가 아니며, 네트워크 관측을 노드로 풀어낼 때만 씁니다).
3. **파생 뷰의 재현성**: 파생 결과는 `raw_capture`(불변의 원본)에서 보강 규칙으로 만듭니다. 그래서 파생 메시지는 `derived_from_snapshot_id`와 `ruleset_version`(어느 원본과 어느 규칙에서 재현할 수 있는지)을 싣습니다.
4. **비밀은 절대 저장하지 않습니다**: 접근 비밀(SSH 키, 비밀번호, 계정)은 **어떤 스키마에도 필드가 없습니다.** `MachineEndpoint`가 대표적인 경우입니다. 이 타입에는 비밀을 담을 수 없으므로 컴파일 시점에 보장됩니다.

---

## 2. `common.v1`: 공유 어휘 (단계를 가로지름)

### 통제 어휘(열거형): 모든 단계가 공유
| 열거형 | 의미 | 값 (0=UNSPECIFIED 제외) |
|---|---|---|
| `CryptoRuntime` | 암호 런타임. 발견 항목이나 자산이 속한 런타임입니다. 모든 발견 항목, 자산, 조치의 일급 분기입니다 | `OPENSSL` · `JCA` · `WIN_CNG` |
| `DetectionMethod` | 탐지 방법. 수집기가 보고하며 증거를 도출하는 근거입니다 | `SOURCE`·`ARTIFACT`·`SYMBOL_ANALYSIS`·`RUNTIME_INTROSPECTION`·`DYNAMIC_TRACE` |
| `EvidenceStrength` | 증거 강도. **detection_method에서 도출됩니다**(코어만 채웁니다) | `CONFIRMED`·`INFERRED_HIGH`·`INFERRED_LOW` |
| `UsageContext` | 사용 맥락 | `SERVER`·`CLIENT`·`AT_REST`·`SIGNING` |
| `CollectionLayer` | 수집 계층(완전성 맵의 단위) | `SOURCE`·`ARTIFACT`·`PROCESS`·`NETWORK`·`JVM_INTROSPECTION` |
| `OpensslBindingMode` | OpenSSL 바인딩 | `DYNAMIC`·`STATIC`·`DLOPEN`·`VENDORED` |
| `JcaRegistrationMode` | JCA provider 등록 | `STATIC`·`DYNAMIC`·`EXPLICIT` |

### 메시지
| 메시지 | 목적 | 주요 필드 |
|---|---|---|
| **`Envelope`** | 모든 수집 출력에 붙는 출처 정보 | `collector_id`·`detection_method`·`target_node_id`(권위 있는 닻)·`scope_master_ref`·`signature`(ed25519)·`collector_license`·`machine`(지문) |
| **`MachineIdentity`** | 머신 상관과 자체 ID 지문. 수집기가 채웁니다 | `machine_id`·`hardware_uuid`·`cloud_instance_id`·`fqdn`·`ips`(위치 지정자)·`self_assigned_id`(CMDB가 없으면 결정론적으로 도출합니다)·`derived_from` |
| **`Completeness`** | 계층별 수집 범위 | `layers_covered`·`layers_missing`(갭이며 자동으로 "없음"으로 취급하지 않습니다)·`note` |

---

## 3. `discovery.v1`: 관측과 파생

### `collector.proto`: 접수 계약 (수집기가 **돌려주는** 것)
코어는 "노드를 주면 정본 CBOM을 돌려받는다"는 추상에만 의존합니다. 이 gRPC 경계는 GPL 전염 차단벽이기도 합니다(라이선스 안내).

| 메시지 | 목적 | 주요 필드 |
|---|---|---|
| `CollectorCapabilities` | 능력 선언(`Describe`) | `crypto_runtimes`·`layers`·`detection_methods`·`license`·`invasive`(침습적이면 PROPOSE 게이트) |
| `CollectRequest` | 수집 요청 | `target_node_ids`(범위 게이트를 통과한 것만)·`options` |
| **`CollectionResult`** | 정본 CBOM 봉투 하나 | `envelope` · `raw_capture`(불변의 원본) + `raw_format` · **`cbom_cyclonedx`**(base64 표준 CycloneDX 본문) + `cyclonedx_spec_version` · `completeness` · `observed_edges` |

> 수집기 = 파이프라인의 1–2단계(원본 수집 + CycloneDX 변환) + Envelope입니다. **파생된 `Finding`은 만들지 않습니다.**

### `cbom.proto`: 파생된 `Finding` (정규화 파이프라인의 3–6단계가 **만듭니다**)
코어 정규화 파이프라인이 `cbom_cyclonedx` 본문에서 도출하는, 타입이 있는 뷰입니다. **다시 계산할 수 있습니다**.

| 메시지 | 목적 | 주요 필드 |
|---|---|---|
| `OpensslAxes` | OpenSSL 분기 축 | `lib`·`version`·`fork`(OpenSSL/BoringSSL/…)·`binding_mode` |
| `JcaAxes` | JCA 분기 축 | `jdk_vendor`·`jdk_version`·`provider_set`(**순서에 의미가 있습니다**: 우선순위 협상)·`registration_mode` |
| `CngAxes` | Windows CNG 분기 축 | `provider_set`(KSP/SSP, **관측한 순서대로**) · `algorithms`(이름, 분류, 그것을 제공하는 provider) |
| **`Finding`** | 암호 자산 하나(파생 뷰) | `id`(정본 해시)·`crypto_runtime`·`usage_context`·`algorithm` · `detection_method` + **`evidence_strength`**(파생) · `oneof {openssl\|jca}` · `pqc_readiness`·`fips_validation`·`remediation_class` · `derived_from_snapshot_id` + `ruleset_version`(재현) · **`app_keys`**(자산 귀속, 공유 .so에는 여럿이 있습니다) |

### `asset.proto`: 자산 계층 (Machine → Application → Process)
| 메시지/열거형 | 목적 | 주요 필드 |
|---|---|---|
| `ApplicationKind` | 안정적인 키의 출처 | `SYSTEMD_UNIT`(권장)·`EXE_PATH`·`DECLARED` |
| **`Application`** | 대상 앱(전환물 생성의 일급 단위). `(node_id, app_key)`로 전역에서 식별합니다 | `node_id`·`app_key`·`name`·`kind`·`match` |
| `ProcessMatch` | 앱을 실행 중인 프로세스에 대응시키는 규칙(PID는 저장하지 않습니다) | `systemd_unit`(cgroup, 정확히 일치) > `exe_path` > `cmdline_regex` |
| `LiveProcess` | 런타임에 풀어낸 결과(휘발성, 조회 전용) | `pid`·`cmdline`·`started_at` |
| `ProcessResolution` | 앱의 실행 중인 프로세스 스냅샷 | `node_id`·`app_key`·`processes`·`resolved_at`(곧바로 낡습니다) |

> **프로세스는 저장하지 않습니다.** PID는 휘발성입니다. 전환물 생성 직전에 `ProcessMatch`로 **그때그때 풀어냅니다.**

### `edge.proto`: 통신 연결 간선 (노드 사이의 관계)
| 메시지/열거형 | 목적 | 주요 필드 |
|---|---|---|
| `NetworkProtocol` | 관측한 프로토콜 | `TLS`·`SSH`·`QUIC`(핸드셰이크가 암호화되어 있어 대개 알 수 없음) |
| `EdgeRole` | src의 방향 | `CLIENT`·`SERVER` |
| `QuantumPosture` | 양자내성 상태. **파생 뷰**이며 코어가 `negotiated_group`에서 분류합니다 | 🟢`PQC_HYBRID`·🔴`CLASSICAL`·⚪`UNSPECIFIED` |
| **`ObservedEdge`** | 관측한 통신 연결 간선 하나 | `src_node_id`·`dst_node_id`(풀어내지 못하면 비우고 `dst_addr`을 채웁니다)·`protocol`·`role`·**`negotiated_group`**(상태의 입력)·`cipher`·`observed_count`·`first/last_seen` |

---

## 4. `inventory.v1`: 메타데이터와 판정

### `machine.proto`: 머신 메타데이터 (사람이 읽는 정보이며 식별과 **분리됩니다**)
| 메시지/열거형 | 목적 | 주요 필드 |
|---|---|---|
| `Environment` | 배포 환경(시각적 축) | `PRODUCTION`·`STAGING`·`DEVELOPMENT`·`TEST` |
| `ProfileSource` | 프로필의 출처 | `CMDB`·`REVIEWER`·`OBSERVED` |
| **`MachineProfile`** | 사람이 머신을 구별하려고 읽는 메타데이터(선언이나 검토자가 채웁니다) | `node_id`(닻)·`display_name`·`environment`·`role`·`owner`·`location`·`labels`(map)·`source` |
| **`MachineEndpoint`** | 관측 중 다시 연결하기 위한 **재사용 가능한 연결 메타데이터** | `node_id`·`name`·`ip`·`port` ★**비밀 필드 없음**(키, 계정, 비밀번호는 사용자 파일에만 있습니다) |

### `decision.proto`: 검토 판정 (스키마만 있고 판정 엔진은 없습니다)
`FinalizedPlan`(전환물 생성)에 대응하는 인벤토리 쪽입니다. 판정이 확정되면 확정된 계획으로 이어집니다.

| 메시지/열거형 | 목적 | 주요 필드 |
|---|---|---|
| `DecisionStatus` | 판정의 수명 주기 | `DRAFT`·`IN_REVIEW`·`FINALIZED` |
| `DecisionConclusion` | 검토자의 결론(특히 UNOBSERVED 항목에 대한 것) | `EXISTS`·`STALE`·`EXCLUDED`·`APPROVED` |
| **`ReconState`** | 선언과 관측을 대조한 결과(어휘만 있고 **엔진은 이 리포지터리에 없습니다**) | `CONFIRMED`(선언 ∩ 관측) · `UNDECLARED`(관측만 있음 = 그림자) · `UNOBSERVED`(선언만 있음: 자동으로는 판정하지 않습니다) |
| **`Decision`** | 판정 하나 | `subject`(연결 간선이나 정책 ID)·`conclusion`·`status`·`reviewer`·`signature`·`basis_hash`(근거가 바뀌면 무효가 됩니다)·`derived_from_snapshot_id` |

---

## 5. `provisioning.v1`: 생성과 되돌림

### `plan.proto`: 확정된 계획 (전환물 생성이 실행되는 유일한 근거)
| 메시지/열거형 | 목적 | 주요 필드 |
|---|---|---|
| `DeployAutomationLevel` | 배포를 단계적으로 위임하는 수준. 자산마다 정합니다 | `L1_STAGE_ONLY`·`L2_STAGE_INSTALL`(운영 환경 기본값)·`L3_FULL_AUTO`(활성화와 재시작까지이며 계획의 `activation` 훅) |
| `PlanStatus` | 계획의 수명 주기 | `DRAFT`·`IN_REVIEW`·**`FINALIZED`**(실행의 근거) |
| `RemediationKind` | 조치의 종류 → 코어 생성기의 분기 | `CONFIG_ONLY`·`PROVIDER_INJECT`·`FORK_REPLACE`·`PROXY_FRONT`·`REBUILD`·`JDK_UPGRADE`·`APP_RECONFIG`·`DECOMMISSION` |
| **`RemediationAction`** | 자산 하나에 대한 조치 | `target_node_id`·`finding_id`·`crypto_runtime`·`kind`·`automation_level`·`target_algorithm`·`provider_choice`·`provider_class`(명시적인 FQCN이며, 없으면 알려진 이름만 확실합니다)·**`config_artifact`**(코어 생성기가 렌더링합니다)·**`activation`**(L3 훅)·`rollback_note`·`priority` |
| **`ActivationHooks`** | L3에서 실행하도록 **사용자가 쓴 명령**(활성화는 환경마다 달라서 도구가 추측하지 않습니다) | `pre`·`activate`·`deactivate`·`restart`: 생성기가 의미 있는 순서로 배치합니다. 정방향은 `pre→stage→activate→restart`, 되돌림은 `pre→deactivate→remove→restart`입니다 |
| **`FinalizedPlan`** | 확정된 계획(스키마만 있고 작성이나 확정 엔진은 없습니다) | `id`·`status`·`scope`·`actions`·`approval_signatures`(확정의 전제 조건)·`derived_from_snapshot_id`·`ruleset_version` |

### `rollback.proto`: 전환물 생성 이력과 되돌림 (스키마는 OSS이며, 이 리포지터리가 되돌림 플레이북도 생성합니다)
| 메시지/열거형 | 목적 | 주요 필드 |
|---|---|---|
| **`CryptoState`** | 어느 시점의 암호 상태(변경 전/후가 공유합니다) | `modules`(예: `libcrypto.so.3@3.0.13`)·`config_digest`·`provider_chain`·`config_snapshot_ref`(되돌림을 위한 원문 참조) |
| `ProvisioningStatus` | 진행 상태(단계 경계가 되돌림 지점입니다) | `STAGED`(L1)·`INSTALLED`(L2)·`ACTIVATED`(L3: 활성화와 재시작 완료)·`ROLLED_BACK`·`FAILED` |
| **`ProvisioningRecord`** | 전환물 생성 행위 하나의 추가 전용 기록 | `node_id`·**`app_keys`**(영향받은 앱, 공유 .so에는 여럿이 있습니다)·`action_id`·`plan_id`·**`before`**(되돌림의 기준선)·`after`·`status`·`note`·`at` |

---

## 6. 관계도: 메시지가 이어지는 방식

```
[Collector]  ──returns──▶  CollectionResult { Envelope(+MachineIdentity) · raw_capture · cbom_cyclonedx · ObservedEdge[] · Completeness }
                                     │  (scope gate · ed25519 verification)
                                     ▼
[Normalize]  ──derives──▶  Finding[] (evidence_strength·app_keys) ─┐   ObservedEdge + QuantumPosture (derived)
                                     │                            │
                          app_keys attribution                    │
                                     ▼                            ▼
                             Application (node_id, app_key)   [central inventory view]
                                     │                            ▲  ▸MachineEndpoint · MachineProfile (the metadata lane)
                         ProcessMatch │ (live)                    │
                                     ▼                            │
                              LiveProcess (volatile)         [review] Decision ══(finalize)══╗
                                                                                             ║
                                                                                             ▼
[Provisioning]  FinalizedPlan { RemediationAction[] } ──FINALIZED gate──▶ playbooks (L1/L2/L3)
                                     │                                                  +
                                     ▼                                         ProvisioningRecord
                          before = CryptoState(the Findings)  ────────────▶  { before/after · app_keys · status }  (append-only rollback basis)
```

**레인으로 다시 보면**: 관측(`CollectionResult`, `ObservedEdge`) → 파생(`Finding`, `QuantumPosture`) → 선언/메타데이터(`MachineProfile`, `Decision`) → 행위(`ProvisioningRecord`). `node_id`는 모든 레인을 꿰는 닻이고, `app_key(s)`는 암호 자산을 앱에 귀속시키며 관측에서 전환물 생성까지 이어집니다.

> **`app_key`가 항상 채워지지는 않습니다.** `Finding`과 `ProvisioningRecord`는 관측한 프로세스에서 곧바로 나오므로
> 항상 귀속됩니다. **`ObservedEdge`도 앱에 닿지만, 조회하는 시점에 소켓이 아직
> 열려 있을 때만입니다.** 수동 와이어 관측에는 PID가 없으므로, `app_key`를 채우려면
> 소켓 inode를 `/proc/*/fd`와 대조해야 합니다.
>
> 그래서 금방 닫힌 연결은 비어 있고, 권한이 없어 프로세스를 읽지 못한 연결도 비어 있습니다.
> **빈 `app_key`는 "귀속할 수 없었다"는 뜻이지 "이 연결 간선에 앱이 없다"는 뜻이 아니며**, 어느 쪽인지는
> 완전성 note에 적힙니다. 놓친 것은 사람이 채울 수 있습니다
> (`pqcota-declare-attribution`). 그러나 그 선언은 **관측을 고치지 않습니다.** 자기 레인에
> 따로 기록되고, 결합은 인벤토리 화면에서 일어납니다.

---

실행 가능한 예제: [examples/](https://github.com/randyinthedev-hash/pqcota/tree/main/examples).
