"""BIP format vectors and offline denials; no WAM execution or matching."""
import hashlib
import unittest

from wam_privacy_wallet.node.basic_block_filter import (
    BasicFilterError, parse_basic_filter, validate_filter_header,
)


def encoded_values(values):
    """Synthetic Golomb-Rice serialization helper, not a filter constructor."""
    n = len(values)
    prefix = bytes([n]) if n < 253 else b'\xfd' + n.to_bytes(2, 'little')
    bits = ''
    last = 0
    for value in values:
        delta = value - last
        bits += '1' * (delta >> 19) + '0' + format(delta & ((1 << 19) - 1), '019b')
        last = value
    bits += '0' * (-len(bits) % 8)
    return (prefix + bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))).hex()


class BasicBlockFilterTests(unittest.TestCase):
    def deny(self, data):
        with self.assertRaisesRegex(BasicFilterError, '^CORE_BASIC_FILTER_DENIED$'):
            parse_basic_filter(data)

    def test_official_bip158_genesis_vector_header_and_byte_order(self):
        # CC0: bitcoin/bips bip-0158/testnet-19.json. Bitcoin format evidence,
        # NEVER WAM chain or real wallet acceptance evidence.
        result = validate_filter_header('019dfca8',
            '21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750',
            '0' * 64)
        self.assertEqual((result.element_count, result.byte_count), (1, 4))

    def test_official_bip158_nonzero_parent_vector(self):
        result = validate_filter_header('016cf7a0',
            '8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a',
            '186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0')
        self.assertEqual(result.element_count, 1)

    def test_official_empty_filter_vector(self):
        self.assertEqual(validate_filter_header('00',
            '021e8882ef5a0ed932edeebbecfeda1d7ce528ec7b3daa27641acf1189d7b5dc',
            '5e5e12d90693c8e936f01847859404c67482439681928353ca1296982042864e'
        ).element_count, 0)

    def test_empty_filter_is_exactly_one_zero_byte(self):
        self.assertEqual(parse_basic_filter('00').byte_count, 1)
        for invalid in ('', '0000', '000000', 'fd0000'):
            self.deny(invalid)

    def test_decodes_zero_collisions_and_monotonic_deltas(self):
        for values in ([0], [0, 0], [0, 1, 1, 524_289], [784_930]):
            self.assertEqual(parse_basic_filter(encoded_values(values)).element_count,
                             len(values))

    def test_canonical_compactsize_boundary(self):
        self.assertEqual(parse_basic_filter(encoded_values([0] * 253)).element_count, 253)

    def test_noncanonical_compactsize_forms_refused(self):
        for value in ('fd0100', 'fefdfd0000', 'ff0000010000000000'):
            self.deny(value)

    def test_truncated_compactsize_refused(self):
        for value in ('fd', 'fd00', 'fe0000', 'ff00000000'):
            self.deny(value)

    def test_uint32_and_wallet_element_limits_refused(self):
        for value in ('ff0000000001000000',
                      (b'\xfe' + (100_001).to_bytes(4, 'little')).hex()):
            self.deny(value)

    def test_count_without_minimum_data_refused(self):
        for value in ('01', '0100', '010000', '02000000'):
            self.deny(value)

    def test_unterminated_unary_refused(self):
        self.deny('01ffffff')

    def test_cumulative_value_must_remain_in_hashed_range(self):
        self.deny(encoded_values([784_931]))
        self.deny(encoded_values([1, 2 * 784_931]))

    def test_nonzero_padding_refused(self):
        self.deny('01000001')

    def test_trailing_bytes_even_zero_refused(self):
        self.deny(encoded_values([0]) + '00')

    def test_hex_is_canonical_bounded_and_typed(self):
        for value in (None, True, 1, '0', 'gg', '01AABBCC', '01 000000',
                      '00' * 1_048_577):
            self.deny(value)

    def test_filter_hash_covers_complete_serialization(self):
        raw = bytes.fromhex(encoded_values([1, 3]))
        expected = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        self.assertEqual(parse_basic_filter(raw.hex()).filter_hash, expected)

    def test_wrong_header_and_parent_refused(self):
        for header, parent in (('0' * 64, '0' * 64), ('g' * 64, '0' * 64),
                               ('a' * 64, None), ('a' * 64, 'A' * 64)):
            with self.assertRaises(BasicFilterError):
                validate_filter_header('00', header, parent)

    def test_no_matching_or_scanner_skip_interface(self):
        import wam_privacy_wallet.node.basic_block_filter as m
        for name in ('match', 'match_any', 'siphash', 'skip_block', 'Scanner'):
            self.assertFalse(hasattr(m, name))


if __name__ == '__main__':
    unittest.main()
