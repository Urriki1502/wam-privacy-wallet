"""Adversarial normalized PayJoin model integration; no PSBT/signing authority."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import socket
import subprocess
import unittest
from unittest.mock import patch
from wam_privacy_wallet.application.payjoin_proposal_review import (
    PayjoinProposalReviewError, review_synthetic_payjoin_proposal,
)


def fixtures():
    sender = dict(txid=f'{1:064x}', vout=0, atoms=100_000, owner='sender',
                  sequence=0xFFFFFFFD, finalized=False, utxo_present=True,
                  has_keypaths=False, has_partial_signature=False)
    receiver = dict(sender, txid=f'{9:064x}', atoms=20_000, owner='receiver', finalized=True)
    original = dict(version=2, locktime=0, inputs=(sender,), outputs=(
        dict(destination='synthetic-payment', atoms=50_000, owner='receiver'),
        dict(destination='synthetic-change', atoms=49_000, owner='sender')))
    proposal = deepcopy(original)
    proposal['inputs'] += (receiver,)
    proposal['outputs'][0]['atoms'] = 69_000
    return original, proposal


class PayjoinProposalReviewTests(unittest.TestCase):
    def review(self, values=None, **kwargs):
        return review_synthetic_payjoin_proposal(*(fixtures() if values is None else values),
            **(dict(scope='synthetic-regtest', consent=True, payment_output_index=0) | kwargs))

    def denied(self, values=None, **kwargs):
        with self.assertRaisesRegex(PayjoinProposalReviewError, '^APP_PAYJOIN_PROPOSAL_REVIEW_DENIED$'):
            self.review(values, **kwargs)

    def test_actual_pinned_validator_accepts_model_without_authority(self):
        result = self.review()
        self.assertEqual(result.evidence, 'PINNED_MODEL_EXECUTED_UNTRUSTED_INPUT')
        self.assertFalse(result.psbt_verified or result.ownership_verified or result.sign_allowed or result.broadcast_allowed)

    def test_scope_consent_and_bool_index_denied(self):
        for consent in (False, 1, None):
            self.denied(consent=consent)
        self.denied(scope='mainnet')
        self.denied(payment_output_index=True)

    def test_injected_pass_credentials_and_weak_policy_denied(self):
        for key in ('result', 'psbt', 'seed', 'allow_output_substitution'):
            a, b = fixtures()
            b[key] = 'PRIVATE'
            self.denied((a, b))

    def test_bool_amount_and_input_metadata_denied(self):
        for key in ('atoms', 'vout', 'sequence', 'finalized', 'has_keypaths'):
            a, b = fixtures()
            b['inputs'][0][key] = True if key in ('atoms', 'vout', 'sequence') else 1
            self.denied((a, b))

    def test_removed_sender_input_denied(self):
        a, b = fixtures()
        b['inputs'] = (b['inputs'][1],)
        self.denied((a, b))

    def test_sender_sequence_or_amount_changed_denied(self):
        for key in ('sequence', 'atoms'):
            a, b = fixtures()
            b['inputs'][0][key] -= 1
            self.denied((a, b))

    def test_receiver_metadata_denied(self):
        for key, value in (('finalized', False), ('utxo_present', False), ('has_keypaths', True), ('has_partial_signature', True)):
            a, b = fixtures()
            b['inputs'][1][key] = value
            self.denied((a, b))

    def test_output_substitution_denied(self):
        a, b = fixtures()
        b['outputs'][0]['destination'] = 'attacker'
        self.denied((a, b))

    def test_sender_fee_contribution_denied(self):
        a, b = fixtures()
        b['outputs'][1]['atoms'] -= 100
        self.denied((a, b))

    def test_duplicate_inputs_denied(self):
        a, b = fixtures()
        b['inputs'] += (dict(b['inputs'][0]),)
        self.denied((a, b))

    def test_version_locktime_or_owner_changes_denied(self):
        for key in ('version', 'locktime'):
            a, b = fixtures()
            b[key] += 1
            self.denied((a, b))
        a, b = fixtures()
        b['outputs'][0]['owner'] = 'sender'
        self.denied((a, b))

    def test_negative_fee_or_unbalanced_transaction_denied(self):
        a, b = fixtures()
        b['outputs'][0]['atoms'] = 100_000
        self.denied((a, b))
        a, b = fixtures()
        b['outputs'][0]['atoms'] = 70_001
        self.denied((a, b))

    def test_bounds_wrong_container_and_subclass_denied(self):
        a, b = fixtures()
        b['inputs'] *= 129
        self.denied((a, b))
        a, b = fixtures()
        b['outputs'] = list(b['outputs'])
        self.denied((a, b))
        class Evil(dict):
            pass
        a, b = fixtures()
        self.denied((a, Evil(b)))
        a, b = fixtures()
        b['outputs'][0]['destination'] = 'x' * 513
        self.denied((a, b))

    def test_txid_canonicalization_and_missing_fields_denied(self):
        a, b = fixtures()
        b['inputs'][1]['txid'] = 'A' * 64
        self.denied((a, b))
        a, b = fixtures()
        del b['inputs'][1]['owner']
        self.denied((a, b))

    def test_pin_failure_and_policy_exception_are_redacted_denials_only(self):
        with patch('wam_privacy_wallet.application.payjoin_proposal_review._verify_source_bytes', side_effect=RuntimeError('PRIVATE')):
            self.denied()
        with patch('wam_privacy_wallet.research_models.payjoin_safety.validator.validate_proposal', side_effect=RuntimeError('PRIVATE')):
            self.denied()

    def test_nonprimitive_keys_denied_before_comparison_or_source_reads(self):
        class CallbackKey(str):
            calls = 0
            __hash__ = str.__hash__
            def __eq__(self, other):
                type(self).calls += 1
                return str.__eq__(self, other)
        for level in ("transaction", "input", "output"):
            a, b = fixtures()
            row, field = (b, "version") if level == "transaction" else (
                (b["inputs"][0], "owner") if level == "input" else
                (b["outputs"][0], "destination"))
            row[CallbackKey(field)] = row.pop(field)
            CallbackKey.calls = 0
            with patch("wam_privacy_wallet.application.payjoin_proposal_review._verify_source_bytes") as verify:
                self.denied((a, b))
                verify.assert_not_called()
            self.assertEqual(CallbackKey.calls, 0)
        a, b = fixtures()
        b.update({f"extra-{n}": n for n in range(1000)})
        with patch("wam_privacy_wallet.application.payjoin_proposal_review._verify_source_bytes") as verify:
            self.denied((a, b))
            verify.assert_not_called()

    def test_no_network_process_or_retained_input_and_immutable(self):
        a, b = fixtures()
        before = deepcopy((a, b))
        with (patch.object(socket, 'socket', side_effect=AssertionError),
              patch.object(socket, 'create_connection', side_effect=AssertionError),
              patch.object(subprocess, 'Popen', side_effect=AssertionError)):
            result = self.review((a, b))
        self.assertEqual((a, b), before)
        self.assertNotIn('synthetic-payment', repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.sign_allowed = True


if __name__ == '__main__':
    unittest.main()
