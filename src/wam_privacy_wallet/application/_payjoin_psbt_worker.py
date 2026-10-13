"""One-shot pinned PSBTv2 -> unchanged privacy validator, never a signer."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sys

from ._psbt_v2_worker import qualify_read_only_source, _GLOBAL, _INPUT, _OUTPUT
from .payjoin_proposal_review import PayjoinPsbtReview
from .synthetic_policy_demo import _verify_source_bytes


def review_pair(payload: bytes, root: Path) -> PayjoinPsbtReview:
    if type(payload) is not bytes or not 16 <= len(payload) <= 2_000_006:
        raise ValueError
    index = int.from_bytes(payload[:2], "big")
    length = int.from_bytes(payload[2:6], "big")
    original, proposal = payload[6:6 + length], payload[6 + length:]
    if index >= 256 or any(not 5 <= len(raw) <= 1_000_000 for raw in (original, proposal)):
        raise ValueError
    _verify_source_bytes()
    qualify_read_only_source(root)
    try:
        from wam_sp.psbt import PSBT, Reader, _read_map, _count
        from ..research_models.payjoin_safety.model import Transaction, TxInput, TxOutput, PayjoinContext
        from ..research_models.payjoin_safety.validator import validate_proposal

        def decode(raw, receiver_finals):
            reader = Reader(raw)
            if reader.take(5) != b"psbt\xff":
                raise ValueError
            g = _read_map(reader)
            if (not set(g) <= _GLOBAL or g.get(b"\xfb") != b"\x02\x00\x00\x00"
                    or g.get(b"\x06", b"\x00") != b"\x00"):
                raise ValueError
            ni, no = _count(g[b"\x04"], 128), _count(g[b"\x05"], 256)
            ins = tuple(_read_map(reader) for _ in range(ni))
            outs = tuple(_read_map(reader) for _ in range(no))
            reader.finish()
            allowed = _INPUT | ({b"\x08"} if receiver_finals else set())
            if any(not set(m) <= allowed for m in ins) or any(not set(m) <= _OUTPUT for m in outs):
                raise ValueError
            p = PSBT.decode(raw)  # reuse source parser; no copied wire grammar
            if p.version != 2 or any(sig is not None for sig in p.signatures):
                raise ValueError
            if any(len(script) != 34 or script[:2] != b"\x51\x20"
                   for _, script in p.utxos + p.tx.outputs):
                raise ValueError  # current strict adapter supports P2TR only
            return p, ins

        before, _ = decode(original, False)
        after, maps = decode(proposal, True)
        sender = {point: (value, script) for point, (value, script)
                  in zip(before.tx.inputs, before.utxos)}
        if len(sender) != len(before.tx.inputs):
            raise ValueError
        proposed_inputs = []
        for i, (point, (value, script), sequence, m) in enumerate(zip(
                after.tx.inputs, after.utxos, after.tx.sequence_values(), maps)):
            is_sender = point in sender
            if is_sender:
                if b"\x08" in m or sender[point] != (value, script):
                    raise ValueError
            else:
                r = Reader(m[b"\x08"])
                if r.size(1) != 1:
                    raise ValueError
                signature = r.blob(65)
                r.finish()
                if len(signature) != 64 and not (len(signature) == 65 and signature[-1] == 1):
                    raise ValueError  # DEFAULT is encoded by 64 bytes only
                # Existing pinned public verification, no sign/finalize call.
                after._verify_signature(i, signature)
            proposed_inputs.append(TxInput(*point, value,
                "sender" if is_sender else "receiver", sequence,
                finalized=not is_sender))

        def outputs(p):
            return tuple(TxOutput(script.hex(), value,
                "receiver" if i == index else "sender")
                for i, (value, script) in enumerate(p.tx.outputs))

        base = Transaction(before.tx.version, before.tx.locktime,
            tuple(TxInput(*point, value, "sender", sequence)
                  for point, (value, _), sequence in zip(
                      before.tx.inputs, before.utxos, before.tx.sequence_values())), outputs(before))
        candidate = Transaction(after.tx.version, after.tx.locktime,
                                tuple(proposed_inputs), outputs(after))
        validate_proposal(base, candidate, PayjoinContext(index))
        return PayjoinPsbtReview()
    finally:
        sys.setprofile(None)


def main() -> int:
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--source-root":
            raise ValueError
        receipt = review_pair(sys.stdin.buffer.read(2_000_007), Path(sys.argv[2]))
        print(json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        return 2  # no traceback/private PSBT/signature/source path


if __name__ == "__main__":
    raise SystemExit(main())
