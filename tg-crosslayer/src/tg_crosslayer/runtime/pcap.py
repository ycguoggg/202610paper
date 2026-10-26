"""PCAP IPv4 packet-header correlation for UID-attributed connection tuples."""
import ipaddress
import struct

DNS_PORTS = frozenset({53, 853, 123, 5353})


def eligible(ev):
    try:
        return ipaddress.ip_address(ev["ip"]).is_global and int(ev["port"]) not in DNS_PORTS
    except (ValueError, KeyError):
        return False


def signature(proto, port):
    return proto, ("web" if port in (80, 443, 8443) else "other")

def pcap_flows(path, owned):
    """IPv4 header-only PCAP reader. Does not inspect or decrypt payloads."""
    data = path.read_bytes()
    if len(data) < 24:
        return {}
    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        endian = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        endian = '>'
    else:
        raise ValueError('Expected ordinary PCAP, not PCAPNG')
    divisor = 1e9 if magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e6
    linktype = struct.unpack(endian+'I', data[20:24])[0]
    offset = {1: 14, 113: 16, 276: 20, 101: 0}.get(linktype)
    if offset is None:
        raise ValueError('Unsupported PCAP link type '+str(linktype))
    result, pos = {}, 24
    while pos+16 <= len(data):
        sec, frac, caplen, _ = struct.unpack_from(endian+'IIII', data, pos)
        pos += 16
        if pos+caplen > len(data):
            break  # An in-progress snapshot can end in a partial final packet.
        packet = data[pos:pos+caplen]; pos += caplen
        if len(packet) < offset+20 or packet[offset]>>4 != 4:
            continue
        ip = packet[offset:]
        ihl = (ip[0]&15)*4
        if ihl < 20 or len(ip) < ihl+8 or struct.unpack_from('!H', ip, 6)[0]&0x1fff:
            continue
        protocol = ip[9]
        if protocol not in (6, 17):
            continue
        src, dst = str(ipaddress.ip_address(ip[12:16])), str(ipaddress.ip_address(ip[16:20]))
        sp, dp = struct.unpack_from('!HH', ip, ihl)
        proto = 'TCP' if protocol == 6 else 'UDP'
        fwd, rev = (proto, src, sp, dst, dp), (proto, dst, dp, src, sp)
        outgoing = fwd in owned
        key = fwd if outgoing else rev
        if key not in owned:
            continue
        if protocol == 6:
            if len(ip) < ihl+20:
                continue
            hlen = (ip[ihl+12]>>4)*4
            payload = max(0, min(len(ip), struct.unpack_from('!H', ip, 2)[0])-ihl-hlen)
            flags = ip[ihl+13]
            useful_reply = bool(flags&2 and flags&16) or payload>0
        else:
            payload = max(0, struct.unpack_from('!H', ip, ihl+4)[0]-8)
            useful_reply = payload>0
        record = result.setdefault(key, dict(ip=key[3], port=key[4], protocol=proto,
                                             first_epoch=sec+frac/divisor, incoming_packets=0,
                                             outgoing_packets=0, incoming_payload_bytes=0,
                                             outgoing_payload_bytes=0, real_reply=False))
        if outgoing:
            record['outgoing_packets'] += 1
            record['outgoing_payload_bytes'] += payload
        else:
            record['incoming_packets'] += 1
            record['incoming_payload_bytes'] += payload
            record['real_reply'] |= useful_reply
    return result
