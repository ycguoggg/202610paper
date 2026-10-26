import unittest
from tg_crosslayer.static.configs import (signature, group_records, within_config_variation,
                                          categorical_pair_variation, set_pair_variation)


class ConfigTests(unittest.TestCase):
    def sample(self, sample, **kw):
        return dict(sample=sample, family='TG31', capabilities=['rtc', 'media'],
                    native_libraries=['foo.so'], sdk_indicators=['sdk'], system_features=[],
                    config_features=['boot'], permissions=[], resources=[], static_network=[],
                    original_lib_names=['foo.so'], package=sample, certificate=sample,
                    app_label=sample, **kw)

    def test_set_order_is_irrelevant(self):
        a = self.sample('a'); b = self.sample('b')
        b['capabilities'] = ['media', 'rtc']
        self.assertEqual(signature(a, 2), signature(b, 2))

    def test_exact_configuration_reuse(self):
        rows = [self.sample('a'), self.sample('b'), self.sample('c')]
        rows[2]['native_libraries'] = ['other.so']
        result = group_records(rows)
        self.assertEqual(result['metrics']['L2']['groups'], 2)
        self.assertEqual(result['metrics']['L2']['recurring_samples'], 2)
        self.assertAlmostEqual(result['metrics']['L2']['recurring_coverage'], 2/3)
        self.assertEqual(result['metrics']['L5']['groups'], 3)

    def test_unresolved_excluded(self):
        rows = [self.sample('a'), self.sample('b')]
        rows[1]['family'] = None
        result = group_records(rows)
        self.assertEqual(result['metrics']['L2']['eligible_samples'], 1)
        self.assertIsNone(result['assignments'][1]['L2'])

    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            group_records([self.sample('a'), self.sample('a')])

    def test_pairwise_categorical(self):
        self.assertAlmostEqual(categorical_pair_variation(['a','a','b']), 2/3)

    def test_pairwise_jaccard_not_union_intersection(self):
        self.assertAlmostEqual(set_pair_variation([['a'], ['a', 'b'], ['b']]), 2/3)

    def test_pairwise_missing(self):
        self.assertIsNone(set_pair_variation([None, ['x']]))
        self.assertIsNone(categorical_pair_variation([None, 'x']))

    def test_within_configuration_same_pairs(self):
        rows = [self.sample('a'), self.sample('b'), self.sample('c')]
        rows[2]['capabilities'] = ['media']
        variation = within_config_variation(rows, 'package')
        self.assertEqual(variation['observable_pairs'], 1)
        self.assertEqual(variation['mean_pairwise_distance'], 1.0)

    def test_source_records_not_mutated(self):
        rows = [self.sample('a')]
        initial = repr(rows)
        group_records(rows)
        self.assertEqual(initial, repr(rows))
