"""Normalized transaction model for the Phase 4 PayJoin safety gate.

This is not a PSBT parser. A future WAM adapter must derive these fields from
canonical transaction / PSBT bytes instead of trusting remote annotations.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_MONEY = 22_000_000 * 100_000_000


def _txid(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class TxInput:
    txid: str
    vout: int
    atoms: int
    owner: str  # sender | receiver
    sequence: int = 0xFFFFFFFD
    finalized: bool = False
    utxo_present: bool = True
    has_keypaths: bool = False
    has_partial_signature: bool = False

    @property
    def outpoint(self) -> tuple[str, int]:
        return self.txid, self.vout

    def validate(self) -> None:
        if not _txid(self.txid):
            raise ValueError("INPUT_TXID")
        if type(self.vout) is not int or not 0 <= self.vout < 2**32:
            raise ValueError("INPUT_VOUT")
        if type(self.atoms) is not int or not 1 <= self.atoms <= MAX_MONEY:
            raise ValueError("INPUT_AMOUNT")
        if self.owner not in ("sender", "receiver"):
            raise ValueError("INPUT_OWNER")
        if type(self.sequence) is not int or not 0 <= self.sequence < 2**32:
            raise ValueError("INPUT_SEQUENCE")
        for value in (
            self.finalized,
            self.utxo_present,
            self.has_keypaths,
            self.has_partial_signature,
        ):
            if type(value) is not bool:
                raise ValueError("INPUT_METADATA")


@dataclass(frozen=True)
class TxOutput:
    destination: str
    atoms: int
    owner: str  # sender | receiver | external

    def validate(self) -> None:
        if not isinstance(self.destination, str) or not 1 <= len(self.destination) <= 512:
            raise ValueError("OUTPUT_DESTINATION")
        if type(self.atoms) is not int or not 1 <= self.atoms <= MAX_MONEY:
            raise ValueError("OUTPUT_AMOUNT")
        if self.owner not in ("sender", "receiver", "external"):
            raise ValueError("OUTPUT_OWNER")


@dataclass(frozen=True)
class Transaction:
    version: int
    locktime: int
    inputs: tuple[TxInput, ...]
    outputs: tuple[TxOutput, ...]

    def validate(self) -> None:
        if type(self.version) is not int or not -(2**31) <= self.version < 2**31:
            raise ValueError("TX_VERSION")
        if type(self.locktime) is not int or not 0 <= self.locktime < 2**32:
            raise ValueError("TX_LOCKTIME")
        if not self.inputs or len(self.inputs) > 128:
            raise ValueError("TX_INPUT_COUNT")
        if not self.outputs or len(self.outputs) > 256:
            raise ValueError("TX_OUTPUT_COUNT")

        seen = set()
        total_in = 0
        for txin in self.inputs:
            txin.validate()
            if txin.outpoint in seen:
                raise ValueError("DUPLICATE_INPUT")
            seen.add(txin.outpoint)
            total_in += txin.atoms

        total_out = 0
        for txout in self.outputs:
            txout.validate()
            total_out += txout.atoms

        if total_in > MAX_MONEY or total_out > MAX_MONEY or total_in < total_out:
            raise ValueError("TX_BALANCE")

    @property
    def fee_atoms(self) -> int:
        self.validate()
        return sum(i.atoms for i in self.inputs) - sum(o.atoms for o in self.outputs)


@dataclass(frozen=True)
class PayjoinContext:
    """Strict WAM PayJoin sender policy.

    v0.1 intentionally disallows receiver batch outputs. That keeps proposal
    validation small and auditable while the sender-side safety model matures.
    """

    payment_output_index: int
    max_additional_fee_contribution: int = 0
    fee_contribution_output_index: int | None = None
    allow_output_substitution: bool = False
    allow_receiver_batch_outputs: bool = False
    max_inputs: int = 128
    max_outputs: int = 256

    def validate(self, original: Transaction) -> None:
        if type(self.payment_output_index) is not int or not 0 <= self.payment_output_index < len(
            original.outputs
        ):
            raise ValueError("PAYMENT_OUTPUT_INDEX")
        if original.outputs[self.payment_output_index].owner != "receiver":
            raise ValueError("PAYMENT_OUTPUT_OWNER")
        if (
            type(self.max_additional_fee_contribution) is not int
            or not 0 <= self.max_additional_fee_contribution <= 1_000_000
        ):
            raise ValueError("MAX_FEE_CONTRIBUTION")
        if self.fee_contribution_output_index is not None:
            if (
                type(self.fee_contribution_output_index) is not int
                or not 0 <= self.fee_contribution_output_index < len(original.outputs)
                or self.fee_contribution_output_index == self.payment_output_index
                or original.outputs[self.fee_contribution_output_index].owner != "sender"
            ):
                raise ValueError("FEE_CONTRIBUTION_OUTPUT")
        elif self.max_additional_fee_contribution:
            raise ValueError("FEE_CONTRIBUTION_OUTPUT_REQUIRED")

        if type(self.allow_output_substitution) is not bool:
            raise ValueError("OUTPUT_SUBSTITUTION_POLICY")
        if type(self.allow_receiver_batch_outputs) is not bool:
            raise ValueError("BATCH_OUTPUT_POLICY")
        if type(self.max_inputs) is not int or not 1 <= self.max_inputs <= 128:
            raise ValueError("MAX_INPUTS")
        if type(self.max_outputs) is not int or not 1 <= self.max_outputs <= 256:
            raise ValueError("MAX_OUTPUTS")
