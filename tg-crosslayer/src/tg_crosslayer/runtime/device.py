"""App-scoped Android shell, installation and measurement artifacts."""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from ..io import write_json as save

ADB = "adb"


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

class AndroidSession:
    def __init__(self, args):
        self.args = args
        self.output = pathlib.Path(args.output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.journal = self.output / 'progress.jsonl'

    def event(self, kind, **data):
        rec = dict(utc=utc(), kind=kind, **data)
        with self.journal.open('a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        print(json.dumps(rec, ensure_ascii=False), flush=True)

    def adb(self, *args, timeout=30, check=True):
        r = subprocess.run([getattr(self.args, 'adb', ADB), *(['-s', self.args.serial] if self.args.serial else []), *args],
                           capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=timeout)
        if check and r.returncode:
            raise RuntimeError((r.stdout + r.stderr)[-3000:])
        return r.stdout + r.stderr

    def root(self, cmd, **kw):
        cmd = re.sub(r'\biptables(?=\s)', 'iptables -w 5', cmd)
        return self.adb('shell', 'su -c ' + shlex.quote(cmd), **kw)

    def pull(self, remote, target):
        # Older adb builds cannot create files under Unicode Windows paths.
        with tempfile.TemporaryDirectory(prefix='app_probe_') as stage:
            tmp = pathlib.Path(stage) / pathlib.Path(remote).name
            result = self.adb('pull', remote, str(tmp))
            if not tmp.exists():
                raise RuntimeError('adb pull did not create file: ' + result)
            shutil.move(str(tmp), str(target))

    def install(self, case):
        apk = pathlib.Path(case['apk'])
        actual = sha(apk, 'md5')
        if actual != case['sample']:
            raise ValueError(f'APK MD5 mismatch {actual}')
        args = ['install', '-r']
        # Let Android choose the normal ABI. Some mixed APKs include only a
        # 64-bit business library even when the shell also offers a 32-bit ABI.
        if self.args.abi != 'auto':
            args += ['--abi', self.args.abi]
        result = self.adb(*args, str(apk), timeout=180, check=False)
        (self.output / case['sample'] / 'install.txt').write_text(result, encoding='utf-8')
        if 'Success' not in result:
            raise RuntimeError('APK installation failed: ' + result[-1000:])
        pkg = case['package']
        packages = self.adb('shell', 'pm list packages -U')
        entries = re.findall(r'package:(\S+) uid:(\d+)', packages)
        uids = [int(u) for p, u in entries if p == pkg]
        if len(uids) != 1 or uids[0] < 10000:
            raise ValueError('Invalid APP UID: ' + str(uids))
        uid = uids[0]
        peers = [p for p, u in entries if int(u) == uid]
        if peers != [pkg]:
            raise ValueError('Shared UID, refusing to affect peers: ' + str(peers))
        return uid

    def force_stop(self, pkg):
        return self.adb('shell', 'am force-stop ' + shlex.quote(pkg), check=False)

    def launch(self, pkg):
        return self.adb('shell', 'monkey -p ' + shlex.quote(pkg) +
                        ' -c android.intent.category.LAUNCHER 1', timeout=20, check=False)

    def ui(self, dest):
        focus = self.adb('shell', "dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'", check=False)
        (dest / 'foreground.txt').write_text(focus, encoding='utf-8')
        try:
            self.adb('shell', 'screencap -p /sdcard/app_probe_screen.png', timeout=10)
            self.pull('/sdcard/app_probe_screen.png', dest / 'screen.png')
            self.adb('shell', 'rm -f /sdcard/app_probe_screen.png', check=False)
        except Exception as e:
            (dest / 'screen_error.txt').write_text(str(e), encoding='utf-8')

    @staticmethod
    def parse_log(line):
        vals = dict(re.findall(r'\b([A-Z]+)=([^\s]+)', line))
        if not all(k in vals for k in ('DST', 'SRC', 'DPT', 'SPT', 'PROTO', 'UID')):
            return None
        t = re.search(r'\[\s*(\d+\.\d+)\]', line)
        return dict(monotonic=float(t.group(1)) if t else None,
                    source=vals['SRC'], ip=vals['DST'], port=int(vals['DPT']),
                    source_port=int(vals['SPT']), protocol=vals['PROTO'], uid=int(vals['UID']))

