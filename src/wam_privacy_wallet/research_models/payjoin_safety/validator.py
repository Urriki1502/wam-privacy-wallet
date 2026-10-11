"""Conservative sender-side PayJoin proposal validation.

The rules track the safety-critical spirit of BIP 78 while deliberately keeping
the WAM v0.1 profile narrower than the full Bitcoin wire protocol.

No network transport, PSBT parser, signing, or broadcast functionality exists
here.
"""

from __future__ import annotations

from .model import PayjoinContext, Transaction, TxInput, TxOutput


class PayjoinError(ValueError):
    """Fixed-code proposal validation failure."""


def _fail(code: str) -> None:
    raise PayjoinError(code)


def _validate_input_metadata(txin: TxInput, *, sender: bool) -> None:
    # BIP-78 sender checklist: proposal inputs should not expose keypaths or
    # partial signatures. Sender inputs are not finalized; receiver-added inputs
    # are finalized and carry UTXO data.
    if txin.has_keypaths:
        _fail("INPUT_KEYPATH_PRESENT")
    if txin.has_partial_signature:
        _fail("INPUT_PARTIAL_SIGNATURE_PRESENT")
    if sender:
        if txin.finalized:
            _fail("SENDER_INPUT_FINALIZED")
    else:
        if not txin.finalized:
            _fail("RECEIVER_INPUT_NOT_FINALIZED")
        if not txin.utxo_present:
            _fail("RECEIVER_INPUT_UTXO_MISSING")


def _sender_input_map(tx: Transaction) -> dict[tuple[str, int], TxInput]:
    return {i.outpoint: i for i in tx.inputs if i.owner == "sender"}


def _preserves_sender_input_order(original: Transaction, proposal: Transaction) -> bool:
    original_order = [i.outpoint for i in original.inputs]
    observed = [i.outpoint for i in proposal.inputs if i.outpoint in set(original_order)]
    return observed == original_order


def validate_proposal(
    original: Transaction,
    proposal: Transaction,
    context: PayjoinContext,
) -> dict:
    """Validate a normalized PayJoin proposal and return coarse safe evidence."""

    try:
        original.validate()
        proposal.validate()
        context.validate(original)
    except ValueError as exc:
        raise PayjoinError(str(exc)) from None

    if len(proposal.inputs) > context.max_inputs:
        _fail("PROPOSAL_INPUT_LIMIT")
    if len(proposal.outputs) > context.max_outputs:
        _fail("PROPOSAL_OUTPUT_LIMIT")

    if proposal.version != original.version:
        _fail("VERSION_CHANGED")
    if proposal.locktime != original.locktime:
        _fail("LOCKTIME_CHANGED")

    # Strict profile: original transaction inputs are sender-owned.
    if any(i.owner != "sender" for i in original.inputs):
        _fail("ORIGINAL_NON_SENDER_INPUT")

    original_inputs = {i.outpoint: i for i in original.inputs}
    proposal_inputs = {i.outpoint: i for i in proposal.inputs}

    if not set(original_inputs) <= set(proposal_inputs):
        _fail("ORIGINAL_INPUT_REMOVED")
    if not _preserves_sender_input_order(original, proposal):
        _fail("ORIGINAL_INPUT_ORDER_CHANGED")

    added = [i for i in proposal.inputs if i.outpoint not in original_inputs]
    if not added:
        _fail("NO_RECEIVER_INPUT_ADDED")

    for outpoint, original_input in original_inputs.items():
        current = proposal_inputs[outpoint]
        if current.owner != "sender":
            _fail("SENDER_INPUT_OWNERSHIP_CHANGED")
        if current.sequence != original_input.sequence:
            _fail("SENDER_SEQUENCE_CHANGED")
        if current.atoms != original_input.atoms:
            _fail("SENDER_INPUT_AMOUNT_CHANGED")
        _validate_input_metadata(current, sender=True)

    for txin in added:
        if txin.owner != "receiver":
            _fail("ADDED_INPUT_NOT_RECEIVER")
        _validate_input_metadata(txin, sender=False)

    if proposal.fee_atoms < original.fee_atoms:
        _fail("ABSOLUTE_FEE_DECREASED")

    # WAM v0.1 strict profile deliberately keeps the output count stable.
    # Receiver batching can be introduced later behind a separate invariant set.
    if not context.allow_receiver_batch_outputs and len(proposal.outputs) != len(original.outputs):
        _fail("OUTPUT_COUNT_CHANGED")

    if context.allow_receiver_batch_outputs:
        # v0.1 has no independently verified mapping for third-party receiver
        # batches. Fail closed rather than pretend support.
        _fail("RECEIVER_BATCH_OUTPUTS_NOT_IMPLEMENTED")

    fee_contribution = 0

    for index, (before, after) in enumerate(zip(original.outputs, proposal.outputs)):
        if index == context.payment_output_index:
            if not context.allow_output_substitution and after.destination != before.destination:
                _fail("PAYMENT_OUTPUT_SUBSTITUTED")
            if after.owner != "receiver":
                _fail("PAYMENT_OUTPUT_OWNER_CHANGED")
            if after.atoms < before.atoms:
                _fail("PAYMENT_AMOUNT_DECREASED")
            continue

        if index == context.fee_contribution_output_index:
            if after.destination != before.destination or after.owner != "sender":
                _fail("FEE_OUTPUT_CHANGED")
            if after.atoms > before.atoms:
                _fail("FEE_OUTPUT_INCREASED")
            fee_contribution = before.atoms - after.atoms
            if fee_contribution > context.max_additional_fee_contribution:
                _fail("FEE_CONTRIBUTION_EXCEEDED")
            continue

        if after != before:
            _fail("PROTECTED_OUTPUT_CHANGED")

    # Ensure no receiver-added value is somehow represented as a new sender-owned
    # output through a shape trick. With stable output count, ownership of every
    # protected output is already fixed above.
    receiver_input_atoms = sum(i.atoms for i in added)
    payment_increase = (
        proposal.outputs[context.payment_output_index].atoms
        - original.outputs[context.payment_output_index].atoms
    )
    fee_increase = proposal.fee_atoms - original.fee_atoms

    # Conservation identity for this strict profile:
    # receiver input = receiver payment increase + proposal fee increase
    #                  - sender fee contribution.
    if receiver_input_atoms != payment_increase + fee_increase - fee_contribution:
        _fail("VALUE_FLOW_MISMATCH")

    return {
        "schema": 1,
        "receiver_inputs_added": len(added),
        "output_substitution": (
            proposal.outputs[context.payment_output_index].destination
            != original.outputs[context.payment_output_index].destination
        ),
        "sender_fee_contribution_used": fee_contribution > 0,
        "absolute_fee_increased": proposal.fee_atoms > original.fee_atoms,
        "result": "PASS",
    }


def redacted_payjoin_event(evidence: dict) -> dict:
    """Return coarse telemetry with no outpoints, destinations, or amounts."""

    allowed = {
        "schema",
        "receiver_inputs_added",
        "output_substitution",
        "sender_fee_contribution_used",
        "absolute_fee_increased",
        "result",
    }
    return {k: evidence[k] for k in allowed if k in evidence}
