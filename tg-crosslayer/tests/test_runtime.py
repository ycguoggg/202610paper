import struct
import tempfile
import unittest
from pathlib import Path
from tg_crosslayer.runtime.device import AndroidSession
from tg_crosslayer.runtime.pcap import pcap_flows, eligible


class ProbeTests(unittest.TestCase):
    def test_uid_log_parsing(self):
        line = '[ 42.100] CLB123 SRC=192.0.2.2 DST=198.51.100.4 PROTO=TCP SPT=31415 DPT=443 UID=12345'
        r = AndroidSession.parse_log(line)
        self.assertEqual(r['uid'],12345)
        self.assertEqual(r['ip'],'198.51.100.4')
        self.assertEqual(r['source_port'],31415)

    def test_background_traffic_ineligible(self):
        self.assertFalse(eligible({'ip': '127.0.0.1', 'port':443}))
        self.assertFalse(eligible({'ip': '192.0.2.1','port':53}))

    def test_header_only_pcap(self):
        # Valid empty little-endian Ethernet PCAP for the header parser.
        header = b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'empty.pcap'; path.write_bytes(header)
            self.assertEqual(pcap_flows(path,{}),{})

    def test_reject_pcapng(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'bad.pcap'; path.write_bytes(b'\x0a\x0d\x0d\x0a'+b'\0'*20)
            with self.assertRaises(ValueError):
                pcap_flows(path,{})
