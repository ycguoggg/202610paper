import tempfile
import unittest
from pathlib import Path
from tg_crosslayer.static.scan import scan_project
from tg_crosslayer.static.upstream import attribute_family, build_baseline


class ScanTests(unittest.TestCase):
    def test_scanner_and_native(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'res').mkdir()
            (root/'lib').mkdir()
            (root/'res'/'AndroidManifest.xml').write_text('<manifest><uses-permission android:name="android.permission.INTERNET"/>\n<activity/>org.telegram.tgnet</manifest>')
            (root/'res'/'config.json').write_text('{"server":"https://example.invalid/path", "sdk":"DingRTC"}')
            (root/'lib'/'libtmessages.so').write_bytes(b'\x7fELFTEST')
            result = scan_project(root, 'sample-a')
            self.assertEqual(len(result['core_hashes']), 1)
            self.assertIn('rtc', result['capabilities'])
            self.assertIn('android.permission.INTERNET', result['permissions'])
            self.assertIn('example.invalid', result['static_network'])
            b = build_baseline(str(root), 'TG31')
            self.assertEqual(attribute_family(result, [b])['evidence'], 'exact_native_core')

    def test_no_family_from_generic_sdk(self):
        b = {'family': 'TG31', 'tg_markers': ['mtproto'], 'core_hashes': [], 'native_libraries':['libfoo.so']}
        obj = {'tg_markers':[], 'core_hashes':[], 'native_libraries':['libfoo.so']}
        self.assertIsNone(attribute_family(obj, [b])['family'])

    def test_ambiguous_reference(self):
        a = {'tg_markers':['mtproto'], 'core_hashes':['abc']}
        b = [{'family': 'TG31', 'core_hashes':['abc']}, {'family': 'TG30', 'core_hashes':['abc']}]
        self.assertEqual(attribute_family(a,b)['evidence'], 'ambiguous_core')

class JNIAlignmentTests(unittest.TestCase):
    def test_unique_jni_signature_matches(self):
        symbols = ['hash-'+str(i) for i in range(12)]
        sample = {'tg_markers':['tlrpc'], 'core_hashes':[], 'core_jni_signatures':symbols}
        official = [
            {'family':'TG31', 'core_hashes':[], 'core_jni_signatures':symbols},
            {'family':'TG45', 'core_hashes':[], 'core_jni_signatures':['other-'+str(i) for i in range(12)]},
        ]
        result = attribute_family(sample, official)
        self.assertEqual(result['family'],'TG31')
        self.assertEqual(result['evidence'],'jni_core_alignment')

    def test_non_unique_jni_does_not_force_family(self):
        symbols = ['hash-'+str(i) for i in range(12)]
        sample = {'tg_markers':['tlrpc'], 'core_hashes':[], 'core_jni_signatures':symbols}
        official = [
            {'family':'TG31', 'core_hashes':[], 'core_jni_signatures':symbols},
            {'family':'TG45', 'core_hashes':[], 'core_jni_signatures':symbols},
        ]
        result = attribute_family(sample, official)
        self.assertIsNone(result['family'])
