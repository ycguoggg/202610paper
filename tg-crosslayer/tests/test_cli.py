import json
import tempfile
import unittest
from pathlib import Path
from tg_crosslayer.cli import main


class CommandTests(unittest.TestCase):
    def test_group_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'records.json').write_text(json.dumps([{'sample':'a','family':'TG31','capabilities':[]}]))
            main(['group','--records',str(p/'records.json'),'--output',str(p/'result.json')])
            result=json.loads((p/'result.json').read_text())
            self.assertEqual(result['metrics']['L2']['eligible_samples'],1)

    def test_pools_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'events.json').write_text(json.dumps([{'sample':'a','config':'C',
                'timestamp':'2000-01-01T00:00:00Z','ip':'192.0.2.1','port':443,
                'observation_kind':'attempted'}]))
            main(['pools','--include-nonpublic','--events',str(p/'events.json'),'--output',str(p/'result.json')])
            self.assertEqual(json.loads((p/'result.json').read_text())['candidate_ips'],1)
