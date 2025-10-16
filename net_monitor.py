#!/usr/bin/env python3
"""
network_monitor_no_deps_plus_v2.py

Network monitor (no scapy, no psutil)

Features:
 - TCP stream reassembly (basic, seq-based)
 - inode->pid cache with TTL expiry
 - /proc monitoring with inotify (via ctypes) fallback to polling
 - DNS parsing (UDP/TCP) -> show domain qnames
 - Export JSON/CSV files (--export-json / --export-csv)
 - Export to syslog/journalctl in JSON format (--syslog)
 - --no-ui : plain text stdout (suitable for tee)
 - --background-log : silent capture, only export (no outputs)
"""

from collections import deque, defaultdict, Counter, namedtuple
import argparse
import ctypes
import csv
import errno
import json
import logging
import logging.handlers
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
import curses

# ---------- Config ----------
MAX_RECENT = 400
REFRESH_CONN = 2.0
REFRESH_UI = 1.0
INODE_TTL = 120.0
TCP_REASM_LIMIT = 10 * 1024 * 1024
USE_INOTIFY = True
# ----------------------------

RUNNING = True
def signal_handler(sig, frame):
    global RUNNING
    RUNNING = False
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ---------- Data ----------
_fd_socket_re = re.compile(r"socket:\[(\d+)\]")
inode2pid_lock = threading.Lock()
inode2pid = {}   # inode -> (pid:int, last_seen_ts:float)
pid_seen = set()

PacketInfo = namedtuple("PacketInfo", ["ts","proto","src","sport","dst","dport","size","pid","pname","info"])

# ---------- /proc helpers ----------
def hex_to_ipv4(hexstr):
    try:
        b = bytes.fromhex(hexstr)
        return socket.inet_ntoa(b[::-1])
    except Exception:
        return None

def hex_to_ipv6(hexstr):
    try:
        b = bytes.fromhex(hexstr)
        return socket.inet_ntop(socket.AF_INET6, b)
    except Exception:
        return None

def parse_proc_net(table):
    path = f"/proc/net/{table}"
    out = []
    if not os.path.exists(path):
        return out
    try:
        with open(path, "r") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local, rem = parts[1], parts[2]
                inode = parts[9]
                try:
                    li, lp = local.split(":")
                    ri, rp = rem.split(":")
                except Exception:
                    continue
                if table.endswith("6"):
                    local_ip = hex_to_ipv6(li)
                    rem_ip = hex_to_ipv6(ri)
                else:
                    local_ip = hex_to_ipv4(li)
                    rem_ip = hex_to_ipv4(ri)
                try:
                    local_port = int(lp,16)
                except:
                    local_port = None
                try:
                    rem_port = int(rp,16)
                except:
                    rem_port = None
                out.append({"local_ip":local_ip,"local_port":local_port,"rem_ip":rem_ip,"rem_port":rem_port,"inode":inode})
    except Exception:
        pass
    return out

def gather_socket_inodes():
    tables = ["tcp","udp","tcp6","udp6","raw","raw6","icmp","icmp6"]
    ino_map = {}
    for t in tables:
        for e in parse_proc_net(t):
            proto = "tcp" if t.startswith("tcp") else "udp" if t.startswith("udp") else "raw"
            ino = e.get("inode")
            if not ino or ino == "0":
                continue
            ino_map[ino] = {"laddr":e.get("local_ip"),"lport":e.get("local_port"),
                            "raddr":e.get("rem_ip"),"rport":e.get("rem_port"),"proto":proto}
    return ino_map

def scan_pid_fds(pid):
    found = {}
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            path = os.path.join(fd_dir, fd)
            try:
                target = os.readlink(path)
            except Exception:
                continue
            m = _fd_socket_re.search(target)
            if m:
                ino = m.group(1)
                found[ino] = int(pid)
    except Exception:
        pass
    return found

# ---------- inode cache (incremental) ----------
def incremental_inode_pid_update():
    global inode2pid, pid_seen
    try:
        current_pids = {p for p in os.listdir("/proc") if p.isdigit()}
    except Exception:
        current_pids = set()
    added = current_pids - pid_seen
    removed = pid_seen - current_pids
    if removed:
        with inode2pid_lock:
            to_remove = [ino for ino,(pid,t) in inode2pid.items() if str(pid) in removed]
            for ino in to_remove:
                inode2pid.pop(ino, None)
    for pid in added:
        scanned = scan_pid_fds(pid)
        if scanned:
            with inode2pid_lock:
                now = time.time()
                for ino,p in scanned.items():
                    if ino not in inode2pid:
                        inode2pid[ino] = (p, now)
    pid_seen = current_pids

def expire_inode_entries():
    now = time.time()
    with inode2pid_lock:
        to_del = [ino for ino,(pid,ts) in inode2pid.items() if now - ts > INODE_TTL]
        for ino in to_del:
            inode2pid.pop(ino, None)

def build_conn_map_from_cache():
    conn_map = {}
    ino_map = gather_socket_inodes()
    with inode2pid_lock:
        for ino,info in ino_map.items():
            rec = inode2pid.get(ino)
            pid = rec[0] if rec else None
            if rec:
                inode2pid[ino] = (rec[0], time.time())
            laddr = info.get("laddr"); lport = info.get("lport")
            raddr = info.get("raddr"); rport = info.get("rport"); proto = info.get("proto")
            if laddr is None or lport is None:
                continue
            key = (laddr, lport, raddr, rport, proto)
            conn_map[key] = pid
            rev = (raddr, rport, laddr, lport, proto)
            if rev not in conn_map:
                conn_map[rev] = pid
    return conn_map

# ---------- inotify via ctypes ----------
has_inotify = False
libc = None
inotify_fd = None
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200

def try_setup_inotify():
    global has_inotify, libc, inotify_fd
    try:
        libc = ctypes.CDLL("libc.so.6")
        inotify_fd = libc.inotify_init1(0)
        if inotify_fd < 0:
            return False
        wd = libc.inotify_add_watch(inotify_fd, b"/proc", IN_CREATE | IN_DELETE)
        if wd < 0:
            return False
        has_inotify = True
        # set non-blocking
        try:
            import fcntl
            flags = fcntl.fcntl(inotify_fd, fcntl.F_GETFL)
            fcntl.fcntl(inotify_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        except Exception:
            pass
        return True
    except Exception:
        has_inotify = False
        return False

# ---------- packet parsing ----------
def parse_ethernet(frame):
    if len(frame) < 14: return None, None, None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    return ethertype, frame[14:], (frame[6:12], frame[0:6])

def parse_ipv4(data):
    if len(data) < 20: return None
    ver_ihl = data[0]; ihl = (ver_ihl & 0x0F) * 4
    total_len = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    src = socket.inet_ntoa(data[12:16]); dst = socket.inet_ntoa(data[16:20])
    payload = data[ihl:total_len] if total_len<=len(data) else data[ihl:]
    return {"src":src,"dst":dst,"proto":proto,"ihl":ihl,"payload":payload,"total_len":total_len}

def parse_ipv6(data):
    if len(data) < 40: return None
    src = socket.inet_ntop(socket.AF_INET6, data[8:24]); dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    nh = data[6]; payload = data[40:]
    return {"src":src,"dst":dst,"proto":nh,"payload":payload}

def parse_tcp(data):
    if len(data) < 20: return None
    sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", data[:14])
    offset = (off_flags >> 12) * 4
    payload = data[offset:]
    return {"sport":sport,"dport":dport,"seq":seq,"ack":ack,"offset":offset,"payload":payload}

def parse_udp(data):
    if len(data) < 8: return None
    sport, dport, length = struct.unpack("!HHH", data[:6])
    payload = data[8:8+max(0,length-8)] if length and len(data)>=8 else data[8:]
    return {"sport":sport,"dport":dport,"length":length,"payload":payload}

def parse_icmp(data):
    if len(data) < 4: return None
    t,c = struct.unpack("!BB", data[:2])
    return {"type":t,"code":c,"payload":data[4:]}

def parse_arp(data):
    if len(data) < 28: return None
    try:
        oper = struct.unpack("!H", data[6:8])[0]
        spa = socket.inet_ntoa(data[14:18]); tpa = socket.inet_ntoa(data[24:28])
        return {"op":oper,"spa":spa,"tpa":tpa}
    except Exception:
        return None

# ---------- DNS parsing ----------
def decode_dns_name(buf, offset):
    labels=[]; jumped=False; max_steps=256; steps=0
    orig_after = None
    while True:
        if offset>=len(buf): return ("", offset+1)
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            if offset+1>=len(buf): return ("", offset+2)
            ptr = ((length & 0x3F)<<8) | buf[offset+1]
            if orig_after is None:
                orig_after = offset+2
            offset = ptr
            steps += 1
            if steps>max_steps:
                return ("", orig_after or offset)
            continue
        if length==0:
            offset+=1
            break
        offset+=1
        if offset+length>len(buf): return ("", offset+length)
        labels.append(buf[offset:offset+length].decode(errors="ignore"))
        offset+=length
    name = ".".join([l for l in labels if l])
    return (name, orig_after or offset)

def parse_dns_from_payload(payload, is_tcp=False):
    qnames=[]
    if not payload: return qnames
    if is_tcp:
        if len(payload)>=2:
            plen = struct.unpack("!H", payload[:2])[0]
            payload2 = payload[2:2+plen] if plen<=len(payload)-2 else payload[2:]
        else:
            payload2 = payload
    else:
        payload2 = payload
    if len(payload2)<12: return qnames
    try:
        qdcount = struct.unpack("!H", payload2[4:6])[0]
        offset=12
        for _ in range(qdcount):
            name, offset = decode_dns_name(payload2, offset)
            if offset+4<=len(payload2):
                offset += 4
            if name:
                qnames.append(name)
        return qnames
    except Exception:
        return qnames

# ---------- TCP reassembly ----------
tcp_streams = {}
tcp_lock = threading.Lock()

def canonical_conn(src, sport, dst, dport):
    t1 = (src, int(sport or 0))
    t2 = (dst, int(dport or 0))
    if t1 <= t2:
        return (src, sport, dst, dport)
    else:
        return (dst, dport, src, sport)

def add_tcp_segment(src, sport, dst, dport, seq, payload):
    if not payload:
        return None
    key = canonical_conn(src, sport, dst, dport)
    dir_flag = (src, int(sport or 0))
    with tcp_lock:
        entry = tcp_streams.get(key)
        if entry is None:
            entry = {"a_to_b":{}, "b_to_a":{}, "a_id":(key[0],int(key[1]) if key[1] else 0), "b_id":(key[2],int(key[3]) if key[3] else 0), "assembled_a":b"", "assembled_b":b""}
            tcp_streams[key] = entry
        if dir_flag == entry["a_id"]:
            bag = entry["a_to_b"]; side = "a"
        else:
            bag = entry["b_to_a"]; side = "b"
        if len(b"".join(bag.values())) + len(payload) > TCP_REASM_LIMIT:
            bag.clear()
        if seq not in bag:
            bag[seq] = payload
        try:
            seqs = sorted(bag.keys())
            assembled_chunks = []
            cur = seqs[0]
            for s in seqs:
                if s == cur:
                    assembled_chunks.append(bag[s]); cur = s + len(bag[s])
                elif s < cur:
                    off = cur - s
                    if off < len(bag[s]):
                        assembled_chunks.append(bag[s][off:]); cur = s + len(bag[s])
                else:
                    break
            assembled = b"".join(assembled_chunks)
            if side == "a":
                entry["assembled_a"] += assembled
            else:
                entry["assembled_b"] += assembled
            used_end = cur
            to_del = [s for s in bag if s < used_end]
            for s in to_del:
                bag.pop(s, None)
            if assembled:
                return assembled[:65536]
        except Exception:
            pass
    return None

# ---------- Exporters ----------
class Exporter:
    def __init__(self, json_path=None, csv_path=None):
        self.json_path = json_path
        self.csv_path = csv_path
        self.lock = threading.Lock()
        self.csv_header_done = False
        if self.csv_path:
            try:
                self.csv_header_done = os.path.exists(self.csv_path) and os.path.getsize(self.csv_path) > 0
            except Exception:
                self.csv_header_done = False

    def write(self, pkt: PacketInfo):
        d = {
            "ts": pkt.ts,
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(pkt.ts)),
            "proto": pkt.proto,
            "src": pkt.src,
            "sport": pkt.sport,
            "dst": pkt.dst,
            "dport": pkt.dport,
            "size": pkt.size,
            "pid": pkt.pid,
            "pname": pkt.pname,
            "info": pkt.info
        }
        if self.json_path:
            try:
                with self.lock:
                    with open(self.json_path, "a", encoding="utf-8") as jf:
                        jf.write(json.dumps(d, ensure_ascii=False) + "\n")
            except Exception:
                pass
        if self.csv_path:
            try:
                with self.lock:
                    write_header = not self.csv_header_done
                    with open(self.csv_path, "a", newline="", encoding="utf-8") as cf:
                        writer = csv.DictWriter(cf, fieldnames=["time","proto","src","sport","dst","dport","size","pid","pname","info"])
                        if write_header:
                            writer.writeheader(); self.csv_header_done = True
                        row = {k: d.get(k) for k in writer.fieldnames}
                        writer.writerow(row)
            except Exception:
                pass

class SyslogExporter:
    """
    Send JSON-formatted log messages to local syslog (/dev/log).
    The message is the JSON string; use journalctl -t <ident> to view.
    """
    def __init__(self, ident="netmon"):
        self.ident = ident
        self.logger = logging.getLogger(ident)
        self.logger.setLevel(logging.INFO)
        self.enabled = False
        try:
            handler = logging.handlers.SysLogHandler(address='/dev/log')
            # Keep the message as-is (we emit JSON in msg)
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.enabled = True
        except Exception:
            # Fallback to UDP syslog (localhost:514) if /dev/log not available
            try:
                handler = logging.handlers.SysLogHandler(address=('127.0.0.1', 514))
                handler.setFormatter(logging.Formatter('%(message)s'))
                self.logger.addHandler(handler)
                self.enabled = True
            except Exception:
                self.enabled = False

    def write(self, pkt: PacketInfo):
        if not self.enabled:
            return
        d = {
            "ts": pkt.ts,
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(pkt.ts)),
            "proto": pkt.proto,
            "src": pkt.src,
            "sport": pkt.sport,
            "dst": pkt.dst,
            "dport": pkt.dport,
            "size": pkt.size,
            "pid": pkt.pid,
            "pname": pkt.pname,
            "info": pkt.info
        }
        try:
            # send JSON string as message
            self.logger.info(json.dumps(d, ensure_ascii=False))
        except Exception:
            pass

# ---------- Packet handling ----------
def parse_frame_and_handle(raw_frame, filter_proto, filter_port, conn_map_getter, packets_deque, stats, exporter):
    ts = time.time(); size = len(raw_frame)
    ethertype, payload, _ = parse_ethernet(raw_frame)
    proto_name="other"; src="-" ; dst="-" ; sport=None; dport=None; info=""
    if ethertype == 0x0800:
        ip = parse_ipv4(payload)
        if not ip: return
        src=ip["src"]; dst=ip["dst"]
        if ip["proto"]==6:
            tcp = parse_tcp(ip["payload"])
            proto_name="tcp"
            if tcp:
                sport=tcp["sport"]; dport=tcp["dport"]
                seg = add_tcp_segment(src,sport,dst,dport,tcp["seq"], tcp["payload"])
                if seg and (sport==80 or dport==80 or sport==53 or dport==53):
                    try:
                        txt = seg.decode(errors="ignore")
                        if txt.startswith("GET ") or txt.startswith("POST ") or "HTTP/" in txt.splitlines()[0]:
                            info = txt.splitlines()[0][:120]
                        else:
                            if sport==53 or dport==53:
                                q = parse_dns_from_payload(seg, is_tcp=True)
                                if q: info = ",".join(q[:2])
                    except Exception:
                        pass
        elif ip["proto"]==17:
            udp = parse_udp(ip["payload"])
            proto_name="udp"
            if udp:
                sport=udp["sport"]; dport=udp["dport"]
                if sport==53 or dport==53:
                    q= parse_dns_from_payload(udp["payload"], is_tcp=False)
                    if q: info = ",".join(q[:2])
        elif ip["proto"]==1:
            icmp = parse_icmp(ip["payload"])
            proto_name="icmp"
            if icmp: info = f"icmp t={icmp.get('type')} c={icmp.get('code')}"
        else:
            proto_name=f"ip/{ip['proto']}"
    elif ethertype==0x86DD:
        ip6 = parse_ipv6(payload)
        if not ip6: return
        src=ip6["src"]; dst=ip6["dst"]; proto_name=f"ipv6/{ip6['proto']}"
    elif ethertype==0x0806:
        arp = parse_arp(payload); proto_name="arp"
        if arp:
            src=arp.get("spa","-"); dst=arp.get("tpa","-")
            info = "who-has" if arp.get("op")==1 else "reply"
    else:
        proto_name = hex(ethertype)

    # filters
    if filter_proto and filter_proto != proto_name and not proto_name.startswith(filter_proto):
        return
    if filter_port:
        try:
            pnum = int(filter_port)
            if not (pnum == sport or pnum == dport):
                return
        except Exception:
            pass

    # map to pid
    pid=None; pname=None
    conn_map = conn_map_getter()
    key = (src, sport, dst, dport, "tcp" if proto_name=="tcp" else ("udp" if proto_name=="udp" else None))
    rev = (dst, dport, src, sport, key[4])
    if key in conn_map and conn_map[key]:
        pid = conn_map[key]
    elif rev in conn_map and conn_map[rev]:
        pid = conn_map[rev]
    else:
        for k,v in conn_map.items():
            try:
                if key[4] and k[4]==key[4] and (k[0]==src or k[2]==dst):
                    pid=v; break
            except Exception:
                continue
    if pid:
        try:
            pname = open(f"/proc/{pid}/comm").read().strip()
        except Exception:
            pname = "?"

    pkt = PacketInfo(ts, proto_name, src, sport, dst, dport, size, pid, pname, info)
    packets_deque.appendleft(pkt)
    stats["total_pkts"] += 1
    stats["total_bytes"] += size
    if pid:
        stats["by_pid_bytes"][pid] += size
        stats["by_pid_pkts"][pid] += 1
    if exporter:
        exporter.write(pkt)

def packet_sniffer_thread(filter_proto, filter_port, packets_deque, stats, conn_map_getter, exporter):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.settimeout(1.0)
    except PermissionError:
        print("Permission denied: run as root.")
        return
    except Exception as e:
        print("Socket error:",e); return

    while RUNNING:
        try:
            raw_frame, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            continue
        try:
            parse_frame_and_handle(raw_frame, filter_proto, filter_port, conn_map_getter, packets_deque, stats, exporter)
        except Exception:
            continue
    try:
        sock.close()
    except Exception:
        pass

# ---------- conn refresher ----------
def conn_refresher(holder):
    inited = False
    if USE_INOTIFY:
        try:
            inited = try_setup_inotify()
        except Exception:
            inited = False
    incremental_inode_pid_update()
    holder[0] = build_conn_map_from_cache()
    last_poll = time.time()
    BUF_LEN = 4096
    if inited and has_inotify:
        while RUNNING:
            try:
                _ = os.read(inotify_fd, BUF_LEN)
                incremental_inode_pid_update()
                expire_inode_entries()
                holder[0] = build_conn_map_from_cache()
            except BlockingIOError:
                time.sleep(0.2)
            except Exception:
                time.sleep(0.2)
            if time.time() - last_poll > REFRESH_CONN:
                expire_inode_entries()
                holder[0] = build_conn_map_from_cache()
                last_poll = time.time()
    else:
        while RUNNING:
            incremental_inode_pid_update()
            expire_inode_entries()
            holder[0] = build_conn_map_from_cache()
            time.sleep(REFRESH_CONN)

# ---------- console logger ----------
def console_logger(packets_deque, stats):
    try:
        while RUNNING:
            try:
                pkt = packets_deque.popleft()
            except IndexError:
                time.sleep(0.1)
                continue
            t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt.ts))
            src_port = f":{pkt.sport}" if pkt.sport else ""
            dst_port = f":{pkt.dport}" if pkt.dport else ""
            pid_part = f"{pkt.pid}/{pkt.pname}" if pkt.pid else "-"
            info_part = f" {pkt.info}" if pkt.info else ""
            line = f"[{t}] {pkt.proto.upper():5} {pkt.src}{src_port} -> {pkt.dst}{dst_port} {pkt.size}B PID={pid_part}{info_part}"
            print(line, flush=True)
    except KeyboardInterrupt:
        pass

# ---------- curses UI ----------
def ui(stdscr, packets, stats, conn_map_holder):
    curses.use_default_colors()
    stdscr.nodelay(True)
    last = 0
    while RUNNING:
        now = time.time()
        if now - last >= REFRESH_UI:
            stdscr.erase()
            h,w = stdscr.getmaxyx()
            stdscr.addstr(0,0,"Network Monitor (v2) — JSON syslog + background logging — Ctrl-C to quit")
            stdscr.addstr(1,0,f"Pkts: {stats['total_pkts']}  Bytes: {stats['total_bytes']}  Conn map: {len(conn_map_holder[0])}")
            stdscr.addstr(2,0,"-"*(w-1))
            stdscr.addstr(3,0,"Top processes by bytes")
            stdscr.addstr(4,0,f"{'PID':>6} {'Bytes':>10} {'Pkts':>6} {'Name':>20}")
            r=5
            for pid,b in Counter(stats["by_pid_bytes"]).most_common(10):
                name="?"
                try:
                    name = open(f"/proc/{pid}/comm").read().strip()
                except Exception:
                    pass
                stdscr.addstr(r,0,f"{pid:6d} {b:10d} {stats['by_pid_pkts'][pid]:6d} {name:20.20s}")
                r+=1
            stdscr.addstr(r+1,0,"-"*(w-1))
            header = r+2
            stdscr.addstr(header,0,f"{'Time':>8} {'Proto':>8} {'Src':>20} {'Spt':>6} {'Dst':>20} {'Dpt':>6} {'Size':>6} {'PID':>6} {'Proc':>12} {'Info':>10}")
            r = header+1
            for p in list(packets)[:h-r-1]:
                t = time.strftime("%H:%M:%S", time.localtime(p.ts))
                line = f"{t:>8} {p.proto:>8} {p.src:>20} {str(p.sport or '-'):>6} {p.dst:>20} {str(p.dport or '-'):>6} {p.size:6d} {str(p.pid or '-'):>6} {p.pname or '-':>12.12s} {p.info[:10]:>10}"
                if r < h-1:
                    try: stdscr.addstr(r,0,line)
                    except: pass
                r+=1
            stdscr.refresh()
            last = now
        time.sleep(0.05)

# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(description="Network monitor no deps v2")
    parser.add_argument("--proto", default=None)
    parser.add_argument("--port", default=None)
    parser.add_argument("--export-json", default=None, help="Append JSONL to this file")
    parser.add_argument("--export-csv", default=None, help="Append CSV to this file")
    parser.add_argument("--no-ui", action="store_true", help="Disable curses UI and print plain text lines (suitable for tee/logging)")
    parser.add_argument("--background-log", action="store_true", help="Silent capture: no output, only export")
    parser.add_argument("--syslog", action="store_true", help="Send JSON logs to syslog/journal (JSON messages)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Run as root: sudo python3 network_monitor_no_deps_plus_v2.py")
        return

    packets = deque(maxlen=MAX_RECENT)
    stats = {"total_pkts":0,"total_bytes":0,"by_pid_bytes":defaultdict(int),"by_pid_pkts":defaultdict(int)}

    # init cache & conn holder
    incremental_inode_pid_update()
    conn_holder = [build_conn_map_from_cache()]

    # choose exporter chain (you can have file exporter + syslog exporter)
    exporters = []
    file_exporter = None
    syslog_exporter = None
    if args.export_json or args.export_csv:
        file_exporter = Exporter(json_path=args.export_json, csv_path=args.export_csv)
        exporters.append(file_exporter)
    if args.syslog:
        syslog_exporter = SyslogExporter()
        # only append if enabled
        if syslog_exporter.enabled:
            exporters.append(syslog_exporter)

    # chain exporter wrapper
    def exporter_write(pkt):
        for ex in exporters:
            try:
                ex.write(pkt)
            except Exception:
                pass

    # start threads
    t_conn = threading.Thread(target=conn_refresher, args=(conn_holder,), daemon=True)
    t_conn.start()
    t_sniff = threading.Thread(target=packet_sniffer_thread, args=(args.proto, args.port, packets, stats, lambda: conn_holder[0], type("E",(),{"write":exporter_write})()), daemon=True)
    t_sniff.start()

    try:
        if args.background_log:
            # silent: just run until signal. Exporters write from sniffer.
            while RUNNING:
                time.sleep(1)
        elif args.no_ui:
            console_logger(packets, stats)
        else:
            curses.wrapper(ui, packets, stats, conn_holder)
    except Exception as e:
        print("UI/Runtime error:", e, file=sys.stderr)

    time.sleep(0.2)
    print("Stopping...")

if __name__ == "__main__":
    main()