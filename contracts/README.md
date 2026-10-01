# pqcota/contracts — the contract SSOT (Single Source of Truth)


This directory holds the **one contract every component of the PQC migration platform depends on**.

Supporting document:
- [**Data model schema**](data-model.md) — purpose, key fields, and relationship map for every message and enum (a human-facing reference). Read it before the file list below and the whole picture snaps into place.

## Files

The namespaces split into the **three product stages plus a shared vocabulary** (symmetrical with `pkg/`). The namespace alone tells you which stage a contract belongs to.

| File | Package | Defines |
|---|---|---|
| `proto/pqcota/common/v1/common.proto` | `pqcota.common.v1` | shared vocabulary: Envelope, completeness, controlled-vocabulary enums (crosses all stages) |
| `proto/pqcota/discovery/v1/cbom.proto` | `pqcota.discovery.v1` | derived Finding · OpensslAxes · JcaAxes |
| `proto/pqcota/discovery/v1/collector.proto` | `pqcota.discovery.v1` | collector intake gRPC service · CollectionResult |
| `proto/pqcota/discovery/v1/edge.proto` | `pqcota.discovery.v1` | communication edge observation · ObservedEdge · QuantumPosture |
| `proto/pqcota/discovery/v1/asset.proto` | `pqcota.discovery.v1` | asset hierarchy · Application · ProcessMatch · LiveProcess (Machine→App→Process) |
| `proto/pqcota/inventory/v1/decision.proto` | `pqcota.inventory.v1` | review verdicts · Decision · DecisionStatus · DecisionConclusion |
| `proto/pqcota/inventory/v1/machine.proto` | `pqcota.inventory.v1` | human-facing machine profile · MachineProfile · Environment (display name, environment, role, owner, tags) |
| `proto/pqcota/provisioning/v1/plan.proto` | `pqcota.provisioning.v1` | finalized plan · FinalizedPlan · RemediationAction · RemediationKind · DeployAutomationLevel |
| `proto/pqcota/provisioning/v1/rollback.proto` | `pqcota.provisioning.v1` | provisioning history and rollback · ProvisioningRecord · CryptoState (before/after) |

> `common` is the contract-side counterpart of pkg/kernel — only shared vocabulary that belongs to no single stage (CryptoRuntime, DetectionMethod, Envelope, Completeness, and so on). Generated Go packages: `gen/pqcota/{common,discovery,inventory,provisioning}/v1` → `commonv1`, `discoveryv1`, `inventoryv1`, `provisioningv1`. The `Decision` and `FinalizedPlan` **schemas are SSOT** (so consuming engines share the same vocabulary).

## How consumers use it

**The generated code (`gen/`) is committed.** For the contract to really be the SSOT, that code has to
be where it is consumed. Requiring consumers to install `buf` and the protoc plugins would mean sharing
a build procedure, not a contract.

```go
import (
	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)
```

> **The module path changed when this repository was split out of `pqcota`.** The contracts and `gen/` used to be
> the `gen/...` packages of `github.com/randyinthedev-hash/pqcota`. They now live in the module
> `github.com/randyinthedev-hash/pqcota-common`, so a consumer moves its imports from
> `github.com/randyinthedev-hash/pqcota/gen/...` to `github.com/randyinthedev-hash/pqcota-common/gen/...`
> and requires `pqcota-common` instead of `pqcota`.

Generated code is never edited by hand. Edit the proto and run `make generate`. CI checks on every
change that the two have not diverged.

## Core design decisions (read before you start)

### 1. Responsibility boundary — collectors do not enrich

```
Collector    →  steps 1–2 : raw capture + conversion to standard CycloneDX + Envelope
Normalization →  steps 3–6 : enrich → validate → resolve identity → persist → derive Finding[]
```

- The collector output (`CollectionResult`) contains **no `Finding`**. It returns only standard CycloneDX plus an Envelope.
- **Interpretive enrichment** — `evidence_strength`, `pqc_readiness`, fork determination — **is done by the core alone**.
  Why: when an enrichment rule (a mapping table) improves, results must be **recomputed from the original**; if enrichment were scattered across collectors, recomputation would be impossible and the rules would drift apart. Enrichment lives in one place.
- Hence `Finding.derived_from_snapshot_id` plus `ruleset_version` are mandatory — which original and which rule a derivation came from is always traceable and reproducible (audit integrity).

### 2. `unknown` is a first-class value

Every enum's `*_UNSPECIFIED = 0` means "could not determine = unknown".
A field you could not fill is left as an **explicit zero value**, not blank or missing.
Do not silently treat it as "absent" — "genuinely not there" and "impossible to observe in principle" are distinguished by `Completeness.layers_missing`.

### 3. The provider signature registry drives enrichment

`JcaAxes.provider_set` (registration order included) is the **original** the collector observed.
The core enrichment step compares it against the provider signature registry and **derives** `pqc_readiness`, `fips_validation`, and algorithm coverage (identifying BouncyCastle / BC-FJA / JDK-native / openssl-jostle / in-house).
- **SLH-DSA is not in the JDK natively** → assets that need it are tagged as depending on BC/jostle regardless of JDK version.
- A `fips_validation` requirement surfaces in the Deploy stage **as a recommendation to use a FIPS-validated provider** (FIPS routing). The tool does not block the provider the plan chose — a validation certificate is per build, and you cannot tell from the file alone.
- The registry is a derivation rule, so it is pinned by `ruleset_version`; when it improves, recompute from the original.

### 4. `deploy_automation_level` is a plan attribute, not a Discovery one

`DeployAutomationLevel` (L1/L2/L3) is registered here as controlled vocabulary, but **collectors do not fill it in.**
It is a plan/asset attribute a reviewer decides per asset (MANUAL) and it rides on the plan entity (the workflow lives on the plan side).
Discovery's `Finding` does not have this field — a deliberate separation to prevent stage confusion.

### 5. The gRPC boundary is the GPL-contagion barrier ([license notes](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/licensing.md))

The `Collector` service boundary is also the license isolation boundary.
A GPL collector (CipherIQ's `cbom-generator`, for instance) runs as a **separate process** and
**exchanges only CycloneDX on stdout**. The core never links it as a library.
`CollectorCapabilities.license` surfaces the implications to the user ([license notes](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/licensing.md)).

### 6. The plan schema is a public contract

`plan.proto` (`FinalizedPlan`, `RemediationAction`, `RemediationKind`) is SSOT and therefore **OSS** — the provisioning artifact generator (`pkg/provisioning`) and the execution channel must speak the same vocabulary.
- The **`Executable()` gate** ("only a finalized plan is grounds for execution") is a shared contract rule → OSS `pkg/provisioning`.
- Plan **authoring and review-finalization** and **fleet orchestration** are out of scope.
- Turning the taxonomy (`RemediationKind`) into config fragments is a deterministic derivation, so the OSS generator owns it.
> Saying `DeployAutomationLevel` and the plan entity are the plan's concern means *who owns the workflow*, not *where the schema lives*.

## CycloneDX `properties` extension key convention

Tool-specific enrichment rides on standard CycloneDX `properties` under the `pqcota:` namespace.
The core pipeline reads those keys and maps them into a typed `Finding`.

| property key | Value | Corresponding Finding field |
|---|---|---|
| `pqcota:crypto_runtime` | `openssl` \| `jca` \| `cng` | `crypto_runtime` |
| `pqcota:detection_method` | `source`\|`artifact`\|`symbol-analysis`\|`runtime-introspection`\|`dynamic-trace` | `detection_method` — **how it was seen**. Strength is derived from this (seeing the real thing beats inferring it) |
| `pqcota:usage_context` | `server`\|`client`\|`at-rest`\|`signing` | `usage_context` |
| `pqcota:openssl.fork` | `OpenSSL`\|`BoringSSL`\|… | `openssl.fork` |
| `pqcota:openssl.binding_mode` | `dynamic`\|`static`\|`dlopen`\|`vendored` | `openssl.binding_mode` |
| `pqcota:jca.provider_set` | CSV in registration order | `jca.provider_set` |
| `pqcota:jca.registration_mode` | `static`\|`dynamic`\|`explicit` | `jca.registration_mode` |
| `pqcota:cng.provider_set` | CSV in registration order | `cng.provider_set` — Windows CNG. **Exactly as observed** (not sorted). Whether that order is a priority is unconfirmed on CNG |
| `pqcota:cng.algorithms` | CSV of `name:kind[:provider\|provider]` (e.g. `ML-DSA:signature:Microsoft Primitive Provider`) | `cng.algorithms` — when the kind is unknown the value is **empty**, and when the provider could not be asked **the third field is omitted**. CNG names contain no comma, colon, or `\|` (measured) |
| `pqcota:app_keys` | CSV of app keys (a shared .so has several) | `app_keys` (repeated) — asset attribution |

> `evidence_strength` and `pqc_readiness` **do not go here** — they are core-derived values (decision 1 above).

> **A note for external collectors — you must carry `pqcota:detection_method`.** The core derives
> `evidence_strength` from `detection_method` deterministically. Without that key the
> core does not invent an evidence strength; it falls honestly to `UNSPECIFIED` (unknown is
> first class, no guessing). That is **the regulated outcome, not a penalty for forgetting.** A
> collector that emits only standard CycloneDX (CBOMkit and friends) has to pass through an import
> adapter that maps its `cryptoProperties` onto these keys for strength to survive — assets that come
> in without the mapping stay at unknown strength.

## Versioning and compatibility rules

- Packages are `pqcota.{common,discovery,inventory,provisioning}.v1`. **A breaking change means a new `v2`** — never reuse a `v1` field number or change its meaning.
- When a field is removed, mark its number `reserved`. Adding an enum value is backward compatible (always append at the end).
- This contract belongs to this repo (Apache-2.0) — the canonical CBOM schema and profiles are public ([licensing notes, section 5](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/licensing.md)).

## When you change the contract — ripple check

Fixing the proto is not the end. **Two things in the code are derived from the contract. A test guards the first; nothing guards the second, so forgetting it leaves the build green and only the behaviour breaks.**

| Also look at | When | If you forget |
|---|---|---|
| [`sign.Canonical`](../pkg/kernel/sign) | **adding a field** to `CollectionResult`, `Envelope`, `MachineIdentity`, `Completeness`, or `ObservedEdge` | the new field becomes a **signature blind spot** — tamper with it and verification still passes.<br>Widening the scope **invalidates every existing signature**, so after a release it needs a migration |
| [`history.ContentHashV1`](https://github.com/randyinthedev-hash/pqcota-inventory/tree/main/pkg/inventory/history) (the snapshot fingerprint) | **adding a substantive content field** to `Finding`, `ObservedEdge`, or `Completeness` | a change to that field folds into "no change" and **vanishes silently from the history**. **Do not edit the frozen v1**: a field that must count needs a new fingerprint format version, designed together with its storage, lookup and downstream consumers |

**A test watches the first** — if the field count changes, `TestCanonicalCoversAllFields` fails (for plans, `TestCanonicalPlanCoversAllFields`) and tells you what to do. Do not wave the failure away by editing the expected value. That is precisely how blind spots get made. **No test watches the second**, so check the fingerprint by hand. The step-by-step version is [Change a contract](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/change-a-contract.md).

**If you changed a derivation rule**, bump `ruleset_version`. A derived value is a function of the rule, not a stored value, so past verdicts can be **recomputed from the original collector results if you kept them**; an inventory snapshot does not hold the raw result, and there is no command that recomputes the past for you.

Watch out for **fields where order carries meaning** — `JcaAxes.provider_set` registration order determines priority negotiation, so it is never sorted or normalized.

## Code generation

```bash
# gen/ is committed — regenerate it and put it in the same commit only when the contract changes
make generate                              # = cd contracts && buf generate
cd contracts && buf lint                   # or make lint

# compatibility checks run **from the repo root** — .git is there and the protos are under contracts/, so a subdir is needed
buf breaking contracts --against '.git#branch=main,subdir=contracts'
buf breaking contracts --against '.git#ref=HEAD~1,subdir=contracts'   # against the previous commit
```
