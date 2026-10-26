import unittest
from tg_crosslayer.network.endpoints import normalize_event, parse_ip
from tg_crosslayer.network.pools import summarize_pools, config_pool_links
from tg_crosslayer.network.churn import analyze_churn


class NetworkTests(unittest.TestCase):
    def event(self, sample, config, ip='203.0.113.8', kind='attempted'):
        # Reserved documentation addresses; parsing with public_only=False is checked separately.
        return dict(sample=sample, config=config, ip=ip, port=443, observation_kind=kind,
                    timestamp='2000-01-01T00:00:00Z')

    def test_invalid_public_destination_rejected(self):
        with self.assertRaises(ValueError):
            normalize_event(self.event('a','X'))
        self.assertIsNone(parse_ip('192.0.2.1'))

    def test_time_zone_required(self):
        ev = self.event('a','X')
        ev['timestamp'] = '2000-01-01T00:00:00'
        with self.assertRaises(ValueError):
            normalize_event(ev, public_only=False)

    def test_shared_apps_distinct_configs(self):
        rows = [self.event('a','A'), self.event('b','B'), self.event('c','A')]
        result = summarize_pools(rows)
        self.assertEqual(result['candidate_ips'], 1)
        self.assertEqual(result['ips_shared_by_apps'], 1)
        self.assertEqual(result['ips_shared_by_configs'], 1)
        self.assertEqual(result['config_pair_sharing_edges'], 1)
        self.assertEqual(result['apps_with_shared_ip'], 3)
        self.assertEqual(len(config_pool_links(rows)), 2)

    def test_never_claims_reply_from_attempt(self):
        result = summarize_pools([self.event('a','A')])
        self.assertEqual(result['evidence_ip_counts'], {'attempted': 1})

    def snap(self, group, hour, ips, complete=True, profile='v1', ports=None):
        return dict(group=group, timestamp=f'2000-01-01T{hour:02d}:00:00+00:00',
                    ips=ips, complete=complete, decoder_profile=profile,
                    ports_by_ip=ports or {})

    def test_change_replace_reappear(self):
        rows = [self.snap('A', 0, ['192.0.2.1']), self.snap('A', 1, ['192.0.2.2']),
                self.snap('A', 2, ['192.0.2.1'])]
        r = analyze_churn(rows)
        self.assertEqual(r['transitions'], 2)
        self.assertEqual(r['ip_set_changes'], 2)
        self.assertEqual(r['complete_replacements'], 2)
        self.assertEqual(r['set_recurrence_events'], 1)
        self.assertEqual(r['median_jaccard_among_changed'], 0)

    def test_incomplete_snapshots_excluded(self):
        rows = [self.snap('A', 0, ['192.0.2.1']), self.snap('A', 1, ['192.0.2.2'], False)]
        self.assertEqual(analyze_churn(rows)['transitions'], 0)

    def test_different_decoders_excluded(self):
        rows = [self.snap('A', 0, ['192.0.2.1']), self.snap('A', 1, ['192.0.2.2'], profile='v2')]
        self.assertEqual(analyze_churn(rows)['transitions'], 0)

    def test_gap_excluded(self):
        rows = [self.snap('A', 0, ['192.0.2.1']), self.snap('A', 2, ['192.0.2.2'])]
        self.assertEqual(analyze_churn(rows, max_gap_hours=1)['transitions'], 0)

    def test_port_only(self):
        a = self.snap('A', 0, ['192.0.2.1'], ports={'192.0.2.1':[443]})
        b = self.snap('A', 1, ['192.0.2.1'], ports={'192.0.2.1':[8443]})
        result = analyze_churn([a, b])
        self.assertEqual(result['port_only_transitions'], 1)
        self.assertEqual(result['ip_set_changes'], 0)

    def test_channel_and_group_not_mixed(self):
        rows = [self.snap('A', 0, ['192.0.2.1']), self.snap('A', 1, ['192.0.2.2'])]
        rows[0]['channel']='one'; rows[1]['channel']='two'
        self.assertEqual(analyze_churn(rows, scope='channel')['transitions'], 0)

class SnapshotConflictTests(unittest.TestCase):
    def test_conflicting_duplicate_in_same_scope_rejected(self):
        first = dict(group='C', timestamp='2000-01-01T00:00:00+00:00', ips=['192.0.2.1'],
                     complete=True, decoder_profile='v1')
        second = {**first, 'ips':['192.0.2.2']}
        with self.assertRaises(ValueError):
            analyze_churn([first, second])
