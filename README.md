# pqcota-common

The shared contract and code of the pqcota platform.

It holds the protobuf contracts (the single source of truth for every message that crosses a stage), their generated Go code, and the vocabulary and helpers all stages share. It is one of five repositories that make up [pqcota](https://github.com/randyinthedev-hash/pqcota): `pqcota-common`, `pqcota-inventory`, `pqcota-discovery`, `pqcota-provisioning`, and the integration repository `pqcota` (demo, examples, release bundles, contributing guide).

## What is here

| Path | What |
|---|---|
| `contracts/` | the protobuf contracts: `pqcota.{common,discovery,inventory,provisioning}.v1`. Start with [contracts/README.md](contracts/README.md) and [data-model.md](contracts/data-model.md) |
| `gen/` | Go code generated from the contracts, **committed** so consumers need only `go get` |
| `pkg/kernel/` | shared logic: `registry`, `posture`, `scope`, `machineid`, `sign`, `completeness` |
| `pkg/org/` | organization scoping of stores |
| `cmd/` | `pqcota-keygen`, the ed25519 key generator that both collector signing and plan approval use ([cmd/README.md](cmd/README.md)) |

## Depends on

Nothing in this family. Every other pqcota module depends on this one, so it imports none of them.

## Build and test

```bash
make            # every check of this repository
go test ./...   # unit tests only
```

`make generate` regenerates `gen/` from `contracts/` (needs `buf`, `protoc-gen-go` and `protoc-gen-go-grpc`; `make tools` installs the two plugins). `make lint` and `make breaking` check the contracts, and `make breaking` compares against the latest release tag.

`pqcota-common` has no sibling dependencies, so its `go.mod` has no `replace` directive. The other four repositories read it from `../pqcota-common` through theirs, so clone the repositories side by side. See the [build guide](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/build.md#get-the-source).

## Contributing · security · license

Contributing and security reporting are described in the [pqcota repository](https://github.com/randyinthedev-hash/pqcota). Licensed under [Apache-2.0](https://github.com/randyinthedev-hash/pqcota/blob/main/LICENSE).
