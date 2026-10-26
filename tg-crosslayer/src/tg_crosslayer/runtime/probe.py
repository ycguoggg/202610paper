"""Progressive, reversible UID-scoped target perturbation."""
from __future__ import annotations
import ipaddress
import json
import pathlib
import re
import shlex
import time
import uuid
import xml.etree.ElementTree as ET
from ..io import write_json as save
from .device import AndroidSession, sha, utc
from .pcap import DNS_PORTS, eligible, signature, pcap_flows

class ProgressiveProbe(AndroidSession):
    def navigate_entry(self,case,folder,tag):
        """Only opening navigation labels; a visible input form ends exploration."""
        focus=self.adb('shell',"dumpsys window windows | grep mCurrentFocus",check=False)
        if case['package'] not in focus:
            return dict(action='skipped_other_foreground',focus=focus)
        remote='/sdcard/'+tag+'_ui.xml'
        text=self.adb('shell','uiautomator dump --compressed '+remote,timeout=15,check=False)
        if 'dumped to' not in text:
            return dict(action='ui_dump_unavailable',detail=text)
        path=folder/'entry_ui.xml'
        self.pull(remote,path);self.adb('shell','rm -f '+remote,check=False)
        nodes=list(ET.parse(path).getroot().iter('node'))
        if any('EditText' in n.get('class','') for n in nodes):
            return dict(action='input_form_visible_no_submit')
        labels={'开始聊天','开始使用','开始体验','start messaging','get started','account login','账号登录','密码登录'}
        for node in nodes:
            label=(node.get('text') or node.get('content-desc') or '').strip().strip(' ·.。').lower()
            if label not in labels or node.get('enabled')=='false':
                continue
            bounds=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',node.get('bounds',''))
            if bounds:
                x1,y1,x2,y2=map(int,bounds.groups())
                self.adb('shell',f'input tap {(x1+x2)//2} {(y1+y2)//2}')
                return dict(action='opened_entry_navigation',label=label,bounds=node.get('bounds'))
        return dict(action='no_navigation_label')

    def install(self, case):
        # Keep a working installed ABI for the paired comparison. New packages
        # use Android's normal choice; no implementation-family data is read.
        original = self.args.abi
        info = self.adb('shell', 'dumpsys package '+shlex.quote(case['package']), check=False)
        if self.args.reuse_installed:
            location = self.adb('shell', 'pm path '+shlex.quote(case['package']), check=False)
            apk_paths = [line[8:] for line in location.splitlines() if line.startswith('package:')]
            if len(apk_paths)==1 and sha(case['apk'],'md5')==case['sample']:
                installed_hash = self.root('md5sum '+shlex.quote(apk_paths[0]),check=False).split()
                if installed_hash and installed_hash[0]==case['sample']:
                    packages = re.findall(r'package:(\S+) uid:(\d+)',self.adb('shell','pm list packages -U'))
                    ids = [int(u) for p,u in packages if p==case['package']]
                    if len(ids)==1 and ids[0]>=10000 and [p for p,u in packages if int(u)==ids[0]]==[case['package']]:
                        save(self.output/case['sample']/'installed_reused.json',dict(md5=case['sample'],installed_path=apk_paths[0],uid=ids[0]))
                        return ids[0]
        match = re.search(r'primaryCpuAbi=(arm64-v8a|armeabi-v7a)', info)
        if original == 'auto' and match:
            self.args.abi = match.group(1)
        try:
            return super().install(case)
        finally:
            self.args.abi = original

    def probe(self, case, uid):
        folder = self.output / case['sample']
        folder.mkdir(parents=True, exist_ok=True)
        save(folder / 'case.json', case)
        tag = 'CLB'+uuid.uuid4().hex[:10]
        chain = tag+'B'
        remote = '/data/local/tmp/'+tag
        pcap_remote, pid_path = remote+'.pcap', remote+'.pid'
        cleanup = f'''iptables -D OUTPUT -m owner --uid-owner {uid} -j {tag} 2>/dev/null
iptables -F {tag} 2>/dev/null
iptables -X {tag} 2>/dev/null
iptables -F {chain} 2>/dev/null
iptables -X {chain} 2>/dev/null
'''
        stop = f'''p=$(cat {pid_path} 2>/dev/null)
if [ -n "$p" ] && tr '\\000' ' ' < /proc/$p/cmdline 2>/dev/null | grep -Fq '{pcap_remote}'; then kill -2 "$p"; fi
'''
        report = dict(sample=case['sample'], package=case['package'], uid=uid, started_utc=utc(),
                      seconds=self.args.seconds, strategy='probe_'+self.args.strategy,
                      block_mode=self.args.block_mode, block_scope=self.args.block_scope,
                      restart_interval=self.args.restart_interval, prefer_nonweb=self.args.prefer_nonweb,
                      chain=tag, attempts=[], events=[], cleanup_ok=False)
        seen, raw_lines, owned, first_seen = set(), [], {}, {}
        tried, retained = set(), set()
        pending = None
        recovering = False
        ui_tried = False
        started = time.monotonic()
        next_probe = started+self.args.warmup
        last_reset = started
        last_restart = started
        final_flows = {}

        def event(kind, **kw):
            rec = dict(kind=kind, elapsed=round(time.monotonic()-started, 3), utc=utc(), **kw)
            report['events'].append(rec)
            self.event('probe_'+kind, sample=case['sample'], **kw)

        def rules(ip, action, port=None, proto=None):
            verb = '-A' if action == 'add' else '-D'
            tcp = '-j REJECT --reject-with tcp-reset' if self.args.block_mode == 'reject' else '-j DROP'
            udp = '-j REJECT --reject-with icmp-port-unreachable' if self.args.block_mode == 'reject' else '-j DROP'
            ports = ','.join(map(str, sorted(DNS_PORTS)))
            if port is not None:
                rejection = tcp if proto=='TCP' else udp
                out = self.root(f'set -e\ncat /proc/uptime\niptables {verb} {chain} -d {ip} -p {proto.lower()} --dport {int(port)} {rejection}')
                return float(out.split()[0])
            out = self.root(f'''set -e
cat /proc/uptime
iptables {verb} {chain} -d {ip} -p tcp -m multiport ! --dports {ports} {tcp}
iptables {verb} {chain} -d {ip} -p udp -m multiport ! --dports {ports} {udp}
''')
            return float(out.split()[0])

        def hit_count(ip):
            text = self.root(f'iptables -nvxL {chain}')
            count = sum(int(row.split()[0]) for row in text.splitlines()
                        if row.split() and row.split()[0].isdigit()
                        and (ip in row.split() or ip+'/32' in row.split()))
            return count, text

        try:
            self.force_stop(case['package'])
            self.root(f'''set -e
iptables -N {tag}
iptables -N {chain}
iptables -A {tag} -p tcp --syn -m limit --limit 100/second --limit-burst 300 -j LOG --log-prefix '{tag} ' --log-uid
iptables -A {tag} -p udp -m conntrack --ctstate NEW -m limit --limit 100/second --limit-burst 300 -j LOG --log-prefix '{tag} ' --log-uid
iptables -A {tag} -j {chain}
iptables -A {tag} -j RETURN
iptables -I OUTPUT 1 -m owner --uid-owner {uid} -j {tag}
''')
            watchdog = f'sleep {self.args.seconds+120}\n'+cleanup+stop
            self.root("printf '%s' "+shlex.quote(watchdog)+f' > {remote}_watchdog.sh\nnohup sh {remote}_watchdog.sh > {remote}_watchdog.log 2>&1 < /dev/null &')
            capture = f'echo $$ > {pid_path}\nexec /vendor/bin/tcpdump -i any -s 0 -U -w {pcap_remote}'
            self.root('nohup sh -c '+shlex.quote(capture)+f' > {remote}_tcpdump.log 2>&1 < /dev/null &')
            time.sleep(.5)
            report['launch'] = self.launch(case['package'])
            started = time.monotonic(); next_probe = started+self.args.warmup; last_reset = started; last_restart = started
            self.event('probe_started', sample=case['sample'], uid=uid)
            while time.monotonic()-started < self.args.seconds:
                now = time.monotonic()
                raw = self.root(f'dmesg | grep -F "{tag} "', check=False)
                for line in raw.splitlines():
                    if line in seen:
                        continue
                    seen.add(line); raw_lines.append(line)
                    ev = self.parse_log(line)
                    if not ev or ev['uid'] != uid:
                        continue
                    ev.update(elapsed=round(now-started, 3), utc=utc(), eligible=eligible(ev))
                    report['attempts'].append(ev)
                    key = (ev['protocol'], ev['source'], ev['source_port'], ev['ip'], ev['port'])
                    if key not in owned:
                        owned[key] = ev; first_seen[key] = now
                snapshot = folder / 'live_snapshot.pcap'
                self.pull(pcap_remote, snapshot)
                final_flows = pcap_flows(snapshot, owned)
                now = time.monotonic()
                if getattr(self.args,'ui_navigation',False) and not ui_tried and now-started>=3:
                    ui_tried=True
                    event('ui_navigation',**self.navigate_entry(case,folder,tag))
                    now=time.monotonic()
                if not recovering and now-started >= self.args.seconds-self.args.recovery:
                    report['counters_before_release'] = self.root(f'iptables -nvxL {chain}')
                    self.root(f'iptables -F {chain}')
                    event('final_release_and_recovery', ips=sorted(retained | ({pending['ip']} if pending else set())))
                    retained.clear(); pending = None; recovering = True
                    report['recovery_started_elapsed'] = round(time.monotonic()-started, 3)
                    self.force_stop(case['package']); self.launch(case['package'])
                if self.args.strategy == 'cumulative' and self.args.block_scope != 'none' and not recovering and now >= next_probe:
                    def target_key(ev):
                        return ev['ip'] if self.args.block_scope=='ip' else ev['protocol']+'/'+ev['ip']+':'+str(ev['port'])
                    choices = [ev for ev in report['attempts'] if ev['eligible'] and target_key(ev) not in tried]
                    if self.args.prefer_nonweb:
                        choices.sort(key=lambda ev: ev['port'] in (80,443,8443))
                    if choices:
                        ev = choices[0]; ip = ev['ip']
                        kernel_time = rules(ip, 'add', ev['port'] if self.args.block_scope=='endpoint' else None, ev['protocol'])
                        tried.add(target_key(ev)); retained.add(target_key(ev))
                        event('temporary_block', ip=ip, observed_port=ev['port'], protocol=ev['protocol'], device_uptime_seconds=kernel_time)
                        next_probe = time.monotonic()+self.args.grace
                if not recovering and self.args.restart_interval and now-last_restart >= self.args.restart_interval:
                    self.force_stop(case['package']); self.launch(case['package'])
                    event('scheduled_restart', retained_targets=sorted(retained))
                    last_restart = time.monotonic()
                if self.args.strategy == 'adaptive' and pending and not recovering:
                    hits, counter_text = hit_count(pending['ip'])
                    if not hits and not pending.get('restarted') and now-pending['time'] >= self.args.grace:
                        # An idle/finished connection will never hit a new rule.
                        # Repeat startup with this one target unavailable.
                        self.force_stop(case['package']); self.launch(case['package'])
                        pending['restarted'] = True
                        pending['time'] = time.monotonic()
                        event('restart_while_target_blocked', ip=pending['ip'])
                    alternatives = [(key, f) for key, f in final_flows.items()
                                    if f['real_reply'] and f['ip'] != pending['ip'] and f['ip'] not in retained
                                    and eligible(f) and first_seen[key] > pending['time']
                                    and signature(f['protocol'], f['port']) in pending['signatures']]
                    if alternatives and hits:
                        alternatives.sort(key=lambda kf: kf[1]['first_epoch'])
                        key, other = alternatives[0]
                        retained.add(pending['ip'])
                        event('responding_alternative', blocked_ip=pending['ip'], alternative_ip=other['ip'],
                              alternative_port=other['port'], protocol=other['protocol'],
                              incoming_payload_bytes=other['incoming_payload_bytes'],
                              blocked_packets=hits, rule_counters=counter_text,
                              note='same UID and coarse transport type; service equivalence is unverified')
                        pending = None; next_probe = now+self.args.grace
                    elif now-pending['time'] >= self.args.probe_timeout:
                        rules(pending['ip'], 'delete')
                        event('rollback_no_visible_alternative' if hits else 'rollback_no_packet_blocked',
                              ip=pending['ip'], blocked_packets=hits, rule_counters=counter_text)
                        pending = None
                        if self.args.restart_on_stall:
                            self.force_stop(case['package']); self.launch(case['package'])
                            event('restart_after_rollback')
                        next_probe = time.monotonic()+self.args.grace
                if self.args.strategy == 'adaptive' and not recovering and now-last_reset >= self.args.reset_interval and (retained or pending):
                    self.root(f'iptables -F {chain}')
                    event('periodic_release_all', ips=sorted(retained | ({pending['ip']} if pending else set())))
                    retained.clear(); pending = None; last_reset = now
                    next_probe = now+self.args.grace
                if self.args.strategy == 'adaptive' and not recovering and pending is None and now >= next_probe:
                    choices = [(key, f) for key, f in final_flows.items()
                               if f['real_reply'] and eligible(f) and f['ip'] not in tried
                               and f['ip'] not in retained]
                    choices.sort(key=lambda kf: (signature(kf[1]['protocol'], kf[1]['port'])[1]=='web',
                                                 kf[1]['incoming_payload_bytes']==0, kf[1]['first_epoch']))
                    if choices:
                        key, flow = choices[0]; ip = flow['ip']
                        kernel_time = rules(ip, 'add'); tried.add(ip)
                        sigs = {signature(f['protocol'], f['port']) for f in final_flows.values() if f['ip']==ip}
                        pending = dict(ip=ip, time=time.monotonic(), kernel_time=kernel_time, signatures=sigs, restarted=False)
                        event('temporary_block', ip=ip, observed_port=flow['port'], protocol=flow['protocol'], device_uptime_seconds=kernel_time)
                time.sleep(min(self.args.poll, max(0, self.args.seconds-(time.monotonic()-started))))
            self.ui(folder)
            report['pid_at_finish'] = self.adb('shell', 'pidof '+shlex.quote(case['package']), check=False).strip()
        except Exception as e:
            report['error'] = f'{type(e).__name__}: {e}'
            self.event('probe_error', sample=case['sample'], error=report['error'])
        finally:
            report['elapsed_seconds'] = round(time.monotonic()-started, 3)
            self.force_stop(case['package'])
            # Include the last polling interval and screen-capture interval.
            for line in self.root(f'dmesg | grep -F "{tag} "',check=False).splitlines():
                if line in seen:
                    continue
                seen.add(line); raw_lines.append(line)
                ev=self.parse_log(line)
                if ev and ev['uid']==uid:
                    ev.update(elapsed=report['elapsed_seconds'],utc=utc(),eligible=eligible(ev))
                    report['attempts'].append(ev)
                    key=(ev['protocol'],ev['source'],ev['source_port'],ev['ip'],ev['port'])
                    owned.setdefault(key,ev)
            report['firewall_counters'] = self.root(f'iptables -nvL {tag}; iptables -nvL {chain}', check=False)
            self.root(cleanup, check=False)
            report['remaining_rules'] = self.root(f'iptables -S | grep -F {tag}', check=False).strip()
            report['cleanup_ok'] = not report['remaining_rules']
            self.root(stop, check=False); time.sleep(.6)
            self.pull(pcap_remote, folder / 'traffic.pcap')
            report['tcpdump_log'] = self.root(f'cat {remote}_tcpdump.log', check=False)
            report['pcap_sha256'] = sha(folder / 'traffic.pcap')
            final_flows = pcap_flows(folder / 'traffic.pcap', owned)
            for key, flow in final_flows.items():
                flow['first_attempt_elapsed'] = owned[key]['elapsed']
                flow['recovery_connection'] = owned[key]['elapsed'] >= report.get('recovery_started_elapsed', float('inf'))
            report['flows'] = list(final_flows.values())
            report['finished_utc'] = utc()
            report['attempted_ips'] = sorted({e['ip'] for e in report['attempts'] if e['eligible']})
            report['reply_ips'] = sorted({f['ip'] for f in final_flows.values() if eligible(f) and f['real_reply']})
            report['payload_ips'] = sorted({f['ip'] for f in final_flows.values() if eligible(f) and f['incoming_payload_bytes']})
            report['tested_targets'] = sorted(tried)
            report['tested_ips'] = sorted({e['ip'] for e in report['events'] if e['kind']=='temporary_block'})
            (folder / 'uid_kernel.log').write_text('\n'.join(raw_lines)+'\n', encoding='utf-8')
            save(folder / 'result.json', report)
            snapshot = folder / 'live_snapshot.pcap'
            if snapshot.exists():
                snapshot.unlink()
            self.root(f'rm -f {pcap_remote} {pid_path} {remote}_tcpdump.log', check=False)
        self.event('probe_completed', sample=case['sample'], attempted=len(report['attempted_ips']),
                   replies=len(report['reply_ips']), blocks=len(tried), cleanup_ok=report['cleanup_ok'])

    def run_blackbox(self):
        cases = json.loads(pathlib.Path(self.args.cases).read_text(encoding='utf-8-sig'))
        assert all(set(c) <= {'sample', 'apk', 'package', 'app_name'} for c in cases), 'Blackbox manifest must not contain family/cloud/key/oracle fields'
        if self.args.sample:
            cases = [c for c in cases if c['sample'] in self.args.sample]
        (self.output / 'firewall_before.txt').write_text(self.root('iptables-save'), encoding='utf-8')
        for c in cases:
            self.force_stop(c['package'])
        for case in cases:
            folder = self.output / case['sample']; folder.mkdir(exist_ok=True)
            done = folder / 'result.json'
            if done.exists() and not json.loads(done.read_text(encoding='utf-8')).get('error'):
                continue
            try:
                uid = self.install(case)
                self.probe(case, uid)
            except Exception as e:
                save(folder / 'case_error.json', dict(error=str(e), utc=utc()))
                self.event('probe_case_error', sample=case['sample'], error=str(e))
        (self.output / 'firewall_after.txt').write_text(self.root('iptables-save'), encoding='utf-8')
