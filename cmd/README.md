# cmd/ — commands that belong to no single stage

The one command here is used by more than one stage, so it lives in the shared module instead of in a stage.

### `pqcota-keygen`

```
pqcota-keygen
```

No arguments. It generates an **ed25519 key pair** and prints it to stdout. The same kind of key pair signs two different things, so the output names each line for the place it goes:

| What it prints | Where it goes | Who uses it |
|---|---|---|
| `PQCOTA_SIGN_KEY` (private) | on the node, when a collector runs | signs the collector result — [pqcota-discovery cmd · Privileges and environment variables](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.md#privileges--environment-variables) |
| `PQCOTA_VERIFY_KEY` (public) | at the centre, when `pqcota-ingest` runs | verifies the collector signature. Several keys are comma-separated |

For a **plan approval** use the same two values under the names the approval commands read: the private key as `PQCOTA_APPROVAL_KEY` for [`pqcota-approve`](https://github.com/randyinthedev-hash/pqcota-provisioning/blob/main/cmd/README.md#pqcota-approve), and `<approver>=<public key>` in `PQCOTA_APPROVAL_KEYS` for [`pqcota-provision`](https://github.com/randyinthedev-hash/pqcota-provisioning/blob/main/cmd/README.md#pqcota-provision). Use a separate pair per role: a key that signs collector results should not also approve plans.

**The private key goes to stdout.** Redirect it into a file and the file stays behind; paste it into a shell and it stays in the history.

**Signing collector results is optional.** Without a key nothing is blocked; instead the centre reports *"unverified signatures: N"*. That does not mean they are wrong; it means **they were never checked**. To refuse to ingest at all when there is no key to verify with, set `PQCOTA_REQUIRE_SIGNATURE=1`. Approval, by contrast, is never optional: `pqcota-provision` refuses a plan it cannot verify unless `--allow-unverified-approvals` is written on the command line.
