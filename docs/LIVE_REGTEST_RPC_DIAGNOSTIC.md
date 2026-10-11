# WAM Core — live loopback regtest RPC diagnostic (opt-in)

This command is an additional step beyond mock/synthetic scanner tests. It uses the **real HTTP transport** in the merged scanner bridge to query an **already-running** WAM node over a numeric loopback address. It has no mock callback, no hosted scanner fallback and no executable launch path.

## Prerequisite

Before running it against a genuine WAM Core process, DEV WAM must approve the binary and isolated disposable regtest workspace in #36/#9. The signed-release review CLI in #73 checks signed archive files **but does not** establish binary-to-running-process identity. Neither this command nor a green CI substitutes for that review. Never point it at a real wallet datadir.

The isolated node must expose explicitly configured, localhost-only RPC with disposable credentials and the **pinned WAM regtest genesis**, be unpruned and have no external peers. Do not use mainnet, testnet, public RPC services, preexisting wallet files or persistent credentials.

## Invocation (interactive terminal only)

```sh
PYTHONPATH=src python -m tools.probe_existing_regtest \
  --host 127.0.0.1 --port <ISOLATED_REGTEST_RPC_PORT> \
  --rpc-user <DISPOSABLE_REGTEST_RPC_USER>
```

Password is requested interactively without echo. No password in arguments, URLs, environment defaults, source files, logs or shell history; a noninteractive stdin is explicitly refused. No default regtest RPC port is guessed. For a confirmed block, add both `--block-height <HEIGHT>` and `--previous-block-hash <64-char-lowercase-hash>` from the verified regtest chain. The default performs a read-only mempool metadata request.

Every request is preceded and followed by fresh chain/profile checks; inconsistent genesis, chain, pruning, tip, height, HTTP response, authentication or payload shape fails closed. The output is a **scalar-only, nonauthorizing** JSON report, with no raw transactions, mempool IDs, wallet addresses, keys, Core process handles or RPC password.

## Evidence boundary

- The program uses a real loopback socket, but **native CI uses a disposable HTTP protocol fixture**, not actual WAM Core.
- A genuine local RPC response alone cannot prove DEV-signed binary identity, OS execution-image immutability, consensus security or WSP-1 scanner correctness.
- No real WSP scanner/SQLite writer/lock is imported. Scanner, signer, broadcast, wallet, mainnet and release authority flags remain false.
- WAM Core is never downloaded or started by this command. The opt-in executable launch gate remains blocked under #36 until verified and DEV-approved.
- Retain synthetic adverse-response tests as security regression fixtures while replacing the *operational network path* with genuine regtest RPC evidence.

## Immediate next engineering gates

1. Obtain genuine official signed release archive, checksum and signature; run the offline reviewer from #73 with a trusted GnuPG binary.
2. Resolve executable bytes-to-process binding, Windows ACL/reparse, POSIX FD safety and regtest RPC-cookie acquisition with no inherited production secrets.
3. Establish disposable two-node actual WAM Core regtest and run this read-only diagnostic against both nodes.
4. Only after scanner upstream freeze/review may WSP-1 scanner state/locking be integrated, still on regtest. Signing and mainnet remain outside this project's authority.
