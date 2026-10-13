# Pinned WSP-1 actual offline signer CLI process — native CI acceptance

This checkpoint extends #177 cryptographic Signed PSBT review with a
**distinct launched Python interpreter** running the real upstream
`wam_sp.offline_signer` executable CLI through a pseudo-terminal.
The upstream code itself provides manual TTY recipient/fee approval,
source-verified AES-GCM keyring/request decryption, and create-once signed
PSBT output in a 0700 directory with mode 0600.

CI assembles a **disposable synthetic chain** using the existing real
WSP Scanner and Wallet APIs, and exports an encrypted keyring with a test
seed. It then:
1. Creates an encrypted intent with the real REGTEST coordinator child;
2. Runs actual upstream signer CLI in a **new process**, responds DECLINE
   at its human approval prompt, and verifies NO signed output exists;
3. Runs the same CLI in a new process with explicit test SIGN approval,
   checks the new private PSBT file is present;
4. Calls actual WSP PSBT.finalize() and the wallet-side source-pinned
   independent signed-PSBT reviewer, validating BIP352 sender metadata,
   UTXO/intent/fee invariants and Schnorr signatures;
5. Flips one Schnorr signature bit and verifies fail-closed review.
6. Keeps all raw PTY output and secrets out of CI logs.

The new proof marker is
`PINNED_WSP_OFFLINE_SIGNER_CLI_CHILD_TTY_APPROVAL_AND_REVIEW_OK`.

**Scope of proof:** separate process, TTY consent, encrypted file transport,
real pinned WSP signature validation, refusal and negative tampering tests.
This is NOT OS-enforced network isolation; no process-image binary attestation,
production custody guarantee, genuine WAM Core execution or two-node E2E.
Parent CI orchestrator owns a disposable keyring to provision the test and
does not prove absence of secrets from its own memory.

Application runtime remains unchanged: no signer subprocess is invoked by
the wallet; no Core process launch, broadcast, mainnet, release or spend
authority is enabled. Continue to HOLD #9/#82/#86/#153, #148/#151 and
upstream WSP PR #3. No actual wallet is approved by a green CI result.
