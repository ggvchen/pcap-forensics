#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcapkit.py - 零依赖 PCAP 取证工具（纯标准库，无需 Wireshark/tshark/scapy）

子命令:
  summary  <pcap>              文件概览 / 时间范围 / 协议构成 / Top 会话
  http     <pcap> [--csv F]    列出全部 HTTP 请求（时间、方法、URI、状态、长度）
  grep     <pcap> PAT [PAT..]  在请求行/头/体与响应体中做不区分大小写检索
  stream   <pcap> ID           还原指定 TCP 流（等价 Wireshark Follow Stream）
  export   <pcap> -d DIR       落地 HTTP 响应体与请求体（上传的木马在请求体里）
  report   <pcap> -d DIR       生成 Markdown 取证报告（阶段命中表+时间线+IOC）

设计约束: 单文件、无第三方依赖、可解析 pcap 与 pcapng、能处理乱序/重传/空洞、
         自动解 gzip/deflate/chunked。对 100MB 以内样本足够快，超大文件请改用 tshark。
"""
import argparse
import collections
import gzip
import hashlib
import ipaddress
import json
import os
import pickle
import re
import struct
import sys
import tempfile
import time
import urllib.parse
import zlib

HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS",
                b"PATCH", b"TRACE", b"CONNECT")
CACHE_VERSION = 4


# ---------------------------------------------------------------- 抓包文件解析

def _iter_pcap(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise ValueError("文件过短，不是有效 pcap")
        magic = hdr[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("未知 pcap magic: %r" % magic)
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", hdr[4:24])
        frac = 1e9 if nano else 1e6
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", ph)
            buf = f.read(incl)
            if len(buf) < incl:
                break
            yield ts_sec + ts_frac / frac, linktype, buf


def _iter_pcapng(path):
    with open(path, "rb") as f:
        endian = "<"
        linktypes = []
        resols = []
        while True:
            bh = f.read(8)
            if len(bh) < 8:
                break
            if bh[:4] == b"\x0a\x0d\x0d\x0a":
                body = f.read(4)
                bom = body[:4]
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack(endian + "I", bh[4:8])[0]
                rest = f.read(max(0, blen - 12))
                continue
            btype, blen = struct.unpack(endian + "II", bh)
            if blen < 12:
                break
            payload = f.read(blen - 8)
            if len(payload) < blen - 8:
                break
            payload = payload[:-4]
            if btype == 1 and len(payload) >= 8:            # IDB
                lt = struct.unpack(endian + "H", payload[0:2])[0]
                resol = 6
                opt = payload[8:]
                i = 0
                while i + 4 <= len(opt):
                    code, olen = struct.unpack(endian + "HH", opt[i:i + 4])
                    if code == 0:
                        break
                    val = opt[i + 4:i + 4 + olen]
                    if code == 9 and val:
                        resol = val[0]
                    i += 4 + olen + ((4 - olen % 4) % 4)
                linktypes.append(lt)
                resols.append(resol)
            elif btype == 6 and len(payload) >= 20:          # EPB
                iface, ts_hi, ts_lo, caplen, _ = struct.unpack(endian + "IIIII", payload[:20])
                data = payload[20:20 + caplen]
                lt = linktypes[iface] if iface < len(linktypes) else 1
                resol = resols[iface] if iface < len(resols) else 6
                # if_tsresol: 最高位为 1 表示 2^-n，否则 10^-n
                exp = resol & 0x7F
                if exp > 19:
                    exp = 19
                frac = float(2 ** exp) if (resol & 0x80) else float(10 ** exp)
                yield ((ts_hi << 32) | ts_lo) / frac, lt, data
            elif btype == 3 and len(payload) >= 4:           # SPB
                _orig = struct.unpack(endian + "I", payload[:4])[0]
                lt = linktypes[0] if linktypes else 1
                yield 0.0, lt, payload[4:]


def iter_frames(path):
    with open(path, "rb") as f:
        head = f.read(4)
    return _iter_pcapng(path) if head == b"\x0a\x0d\x0d\x0a" else _iter_pcap(path)


def _l3_of(linktype, frame):
    """返回 (ethertype, l3bytes)。仅处理常见链路层。"""
    if linktype == 1:                                        # Ethernet
        if len(frame) < 14:
            return None, None
        et = struct.unpack(">H", frame[12:14])[0]
        off = 14
        while et in (0x8100, 0x88a8) and len(frame) >= off + 4:
            et = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
        return et, frame[off:]
    if linktype == 113 and len(frame) >= 16:                 # Linux SLL
        return struct.unpack(">H", frame[14:16])[0], frame[16:]
    if linktype == 276 and len(frame) >= 20:                 # Linux SLL2
        return struct.unpack(">H", frame[0:2])[0], frame[20:]
    if linktype in (0, 108):                                 # BSD loopback
        if len(frame) < 4:
            return None, None
        fam = struct.unpack("<I", frame[:4])[0]
        return (0x0800 if fam == 2 else 0x86dd), frame[4:]
    if linktype in (101, 228, 12):                           # raw IP
        if not frame:
            return None, None
        return (0x0800 if frame[0] >> 4 == 4 else 0x86dd), frame
    return None, None


def _parse_ip(l3, et):
    if et == 0x0800:
        if len(l3) < 20:
            return None
        ihl = (l3[0] & 0x0F) * 4
        tot = struct.unpack(">H", l3[2:4])[0] or len(l3)
        proto = l3[9]
        src = "%d.%d.%d.%d" % tuple(l3[12:16])
        dst = "%d.%d.%d.%d" % tuple(l3[16:20])
        frag = struct.unpack(">H", l3[6:8])[0]
        if frag & 0x1FFF:                                    # 非首片，跳过
            return None
        return proto, src, dst, l3[ihl:tot]
    if et == 0x86dd:
        if len(l3) < 40:
            return None
        nxt = l3[6]
        src = _ip6(l3[8:24])
        dst = _ip6(l3[24:40])
        off = 40
        while nxt in (0, 43, 60, 44) and len(l3) >= off + 8:
            if nxt == 44:
                nxt = l3[off]
                off += 8
            else:
                nxt, hlen = l3[off], (l3[off + 1] + 1) * 8
                off += hlen
        return nxt, src, dst, l3[off:]
    return None


def _ip6(b):
    parts = ["%02x%02x" % (b[i], b[i + 1]) for i in range(0, 16, 2)]
    return ":".join(parts)


# ---------------------------------------------------------------- TCP 重组

class Stream(object):
    __slots__ = ("sid", "ts", "ts_last", "pkts", "nbytes", "dirs", "gaps", "tcpflags")

    def __init__(self, sid, ts):
        self.sid = sid
        self.ts = ts
        self.ts_last = ts
        self.pkts = 0
        self.nbytes = 0
        self.dirs = collections.OrderedDict()
        self.gaps = 0
        self.tcpflags = 0


def build_streams(path):
    """一次遍历完成: 会话统计 + 双向 TCP 重组。返回 (streams, meta)。"""
    streams = collections.OrderedDict()
    key2sid = {}
    first_ts = last_ts = None
    npkts = 0
    proto_ctr = collections.Counter()
    ports = collections.Counter()

    for ts, linktype, frame in iter_frames(path):
        npkts += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        et, l3 = _l3_of(linktype, frame)
        if not l3:
            continue
        ip = _parse_ip(l3, et)
        if not ip:
            continue
        proto, src, dst, payload = ip
        if proto not in (6, 17):
            proto_ctr["proto-%d" % proto] += 1
            continue
        if proto == 17:
            proto_ctr["UDP"] += 1
            if len(payload) >= 8:
                sp, dp = struct.unpack(">HH", payload[:4])
                ports[("UDP", min(sp, dp), max(sp, dp))] += 1
            continue
        proto_ctr["TCP"] += 1
        if len(payload) < 20:
            continue
        sp, dp, seq, ack = struct.unpack(">HHII", payload[:12])
        doff = (payload[12] >> 4) * 4
        flags = payload[13]
        data = payload[doff:] if doff >= 20 else b""
        ports[("TCP", min(sp, dp), max(sp, dp))] += 1

        key = (min((src, sp), (dst, dp)), max((src, sp), (dst, dp)))
        st = streams.get(key)
        if st is None:
            st = Stream(len(streams) + 1, ts)
            streams[key] = st
            key2sid[key] = st.sid
        st.pkts += 1
        st.ts_last = ts
        st.nbytes += len(data)
        st.tcpflags |= flags
        ep = (src, sp)
        d = st.dirs.get(ep)
        if d is None:
            d = {"segs": [], "packets": 0}
            st.dirs[ep] = d
        if not data:
            continue
        d["packets"] += 1
        # 只记 (seq, payload)，最后按序号归并。边收边拼会在「后段先到」时丢掉前段。
        d["segs"].append((seq, data))

    meta = {
        "path": os.path.abspath(path),
        "size": os.path.getsize(path),
        "packets": npkts,
        "first_ts": first_ts or 0.0,
        "last_ts": last_ts or 0.0,
        "protos": dict(proto_ctr),
        "ports": [{"proto": p, "port_lo": lo, "port_hi": hi, "packets": n}
                  for (p, lo, hi), n in ports.most_common(30)],
    }
    for st in streams.values():
        newdirs = collections.OrderedDict()
        total_gaps = 0
        for ep, d in st.dirs.items():
            buf, g = _assemble(d["segs"])
            total_gaps += g
            newdirs[ep] = {"buf": buf, "packets": d["packets"]}
        st.dirs = newdirs
        st.gaps = total_gaps
    return streams, meta


def _assemble(segs, max_span=64 * 1024 * 1024):
    """把 (seq, payload) 列表归并成字节流，返回 (buffer, 空洞数)。

    以最小序号为原点，空洞填 0，重叠部分以先写入者为准（重传内容相同，
    不同则以先到的为准，避免后到的乱序片段覆盖正确数据）。
    """
    if not segs:
        return b"", 0
    base = min(s for s, _ in segs)
    end = max(s + len(p) for s, p in segs)
    span = end - base
    if span <= 0:
        return b"", 0
    if span > max_span:                       # 序号异常（如抓到半个连接），退化为顺序拼接
        out = bytearray()
        cur = None
        for s, p in segs:
            if cur is None:
                cur = s
            if s >= cur:
                out += p
                cur = s + len(p)
            elif s + len(p) > cur:
                out += p[cur - s:]
                cur = s + len(p)
        return bytes(out), 0
    buf = bytearray(span)
    covered = bytearray(span)
    for s, p in segs:
        off = s - base
        if off < 0:
            continue
        buf[off:off + len(p)] = p
        covered[off:off + len(p)] = b"\x01" * len(p)
    gaps, in_gap = 0, False
    for c in covered:
        if c:
            in_gap = False
        elif not in_gap:
            gaps += 1
            in_gap = True
    return bytes(buf), gaps


def _cache_key(path):
    st = os.stat(path)
    raw = "%s|%d|%d|%d" % (os.path.abspath(path), st.st_size, int(st.st_mtime), CACHE_VERSION)
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def load(path, use_cache=True):
    if use_cache:
        cp = os.path.join(tempfile.gettempdir(), "pcapkit_cache",
                          _cache_key(path) + ".pkl")
        if os.path.exists(cp):
            try:
                with open(cp, "rb") as f:
                    return pickle.load(f)
            except Exception:
                pass
    streams, meta = build_streams(path)
    if use_cache:
        cp = os.path.join(tempfile.gettempdir(), "pcapkit_cache",
                          _cache_key(path) + ".pkl")
        os.makedirs(os.path.dirname(cp), exist_ok=True)
        try:
            with open(cp, "wb") as f:
                pickle.dump((streams, meta), f, protocol=4)
        except Exception:
            pass
    return streams, meta


# ---------------------------------------------------------------- HTTP 解码

DECODE_ISSUES = collections.Counter()   # br/zstd 未解压、gzip 解压失败等，汇总后提示


def _dechunk(body):
    out = bytearray()
    i = 0
    try:
        while i < len(body):
            j = body.index(b"\r\n", i)
            ln = int(body[i:j].split(b";")[0], 16)
            if ln == 0:
                break
            out += body[j + 2:j + 2 + ln]
            i = j + 2 + ln + 2
        return bytes(out)
    except Exception:
        return bytes(body)


def _inflate(body, enc):
    """按声明解压；声明缺失或撒谎时退回魔术字节嗅探（1f8b / 78xx）。"""
    enc = (enc or "").lower()
    if "br" in enc or "zstd" in enc or "compress" in enc:
        DECODE_ISSUES[enc.strip() or "unknown"] += 1
        return body
    if "gzip" in enc or body[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(body)
        except Exception:
            pass
    # zlib 头第二字节是固定校验位组合，用它避免把普通文本误判成 deflate
    looks_zlib = body[:1] == b"\x78" and body[1:2] in (b"\x01", b"\x9c", b"\xda", b"\x5e")
    if "deflate" in enc or "gzip" in enc or looks_zlib:
        for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompressobj(wbits).decompress(body)
            except Exception:
                continue
    if ("gzip" in enc or "deflate" in enc) and body:
        DECODE_ISSUES["解压失败(可能被截断)"] += 1
    return body


def _headers_dict(raw):
    h = {}
    for line in raw.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            h[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
    return h


def parse_http(buf):
    """把一个方向的 TCP 字节流切成 HTTP 报文列表。"""
    out = []
    b = buf
    pos = 0
    while pos < len(b):
        start = pos
        head_end = b.find(b"\r\n\r\n", pos)
        if head_end < 0:
            break
        head = b[pos:head_end]
        first = head.split(b"\r\n", 1)[0]
        if not (re.match(rb"^[A-Z]{3,7} \S+ HTTP/\d\.\d$", first) or
                re.match(rb"^HTTP/\d\.\d \d{3}", first)):
            break
        hdrs = _headers_dict(head)
        body_off = head_end + 4
        body = b""
        nxt = body_off
        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            end = b.find(b"\r\n0\r\n", body_off)
            if end < 0:
                raw_body = b[body_off:]
                nxt = len(b)
            else:
                tail = b.find(b"\r\n\r\n", end + 3)
                nxt = (tail + 4) if tail > 0 else len(b)
                raw_body = b[body_off:nxt]
            body = _inflate(_dechunk(raw_body), hdrs.get("content-encoding"))
        elif "content-length" in hdrs:
            try:
                cl = int(hdrs["content-length"])
            except Exception:
                cl = 0
            raw_body = b[body_off:body_off + cl]
            nxt = body_off + len(raw_body)
            body = _inflate(raw_body, hdrs.get("content-encoding"))
        else:
            body = b""
        out.append({
            "first_line": first.decode("latin1", "replace"),
            "headers": hdrs,
            "body": body,
            "truncated": len(b) - nxt < 0,
        })
        pos = nxt
        if pos <= start:      # 无 body 的报文 pos == body_off，这里必须比 start，
            break             # 否则 keep-alive 连接上的后续报文会被整段丢掉
    return out


def _is_request(buf):
    return buf[:8].split(b" ")[0] in HTTP_METHODS


def build_http(streams):
    """配对请求/响应。返回记录列表（按时间排序）。"""
    recs = []
    for key, st in streams.items():
        if not st.dirs:
            continue
        cli = None
        for ep, d in st.dirs.items():
            if _is_request(d["buf"]):
                cli = ep
                break
        if cli is None:
            continue
        srv_eps = [ep for ep in st.dirs if ep != cli]
        reqs = parse_http(st.dirs[cli]["buf"])
        resps = parse_http(st.dirs[srv_eps[0]]["buf"]) if srv_eps else []
        for k, rq in enumerate(reqs):
            rs = resps[k] if k < len(resps) else None
            line = rq["first_line"]
            parts = line.split(" ")
            recs.append({
                "stream": st.sid,
                "ts": st.ts,
                "client": "%s:%d" % cli,
                "server": "%s:%d" % srv_eps[0] if srv_eps else "",
                "method": parts[0] if parts else "",
                "uri": parts[1] if len(parts) > 1 else "",
                "host": rq["headers"].get("host", ""),
                "ua": rq["headers"].get("user-agent", ""),
                "req_headers": rq["headers"],
                "req_body": rq["body"],
                "status": (rs["first_line"].split(" ")[1] if rs and len(rs["first_line"].split(" ")) > 1 else ""),
                "status_line": rs["first_line"] if rs else "",
                "resp_headers": rs["headers"] if rs else {},
                "resp_body": rs["body"] if rs else b"",
            })
    recs.sort(key=lambda r: (r["ts"], r["stream"]))
    return recs


# ---------------------------------------------------------------- 攻击链签名

SIGNATURES = [
    # (阶段, 检索范围, 特征串)  范围: ua / uri / reqbody / respbody / headers / decoded
    ("侦察/扫描", ("ua",), ["nikto", "dirb", "gobuster", "dirsearch", "nmap", "masscan",
                          "awvs", "acunetix", "appscan", "xray", "sqlmap", "zgrab",
                          "wfuzz", "nuclei", "ffuf", "owasp zap", "netsparker", "whatweb"]),
    ("脚本化客户端", ("ua",), ["python-requests", "curl/", "wget/", "go-http-client",
                          "okhttp", "libwww-perl", "java/"]),
    ("SQL 注入", ("uri", "reqbody", "decoded"), ["procedure analyse", "extractvalue(", "updatexml(",
                                    "union select", "union all select", "information_schema",
                                    "sleep(", "benchmark(", "and 1=1", "' or '1'='1",
                                    "waitfor delay", "select@@version"]),
    ("文件写入/拖库", ("uri", "reqbody", "decoded"), ["into outfile", "into dumpfile", "load_file(",
                                        "from beescms.users", "from users where"]),
    ("后台登录接口", ("uri",), ["login.php", "do_login", "checklogin", "signin", "login.jsp"]),
    ("文件上传", ("headers", "reqbody"), ["multipart/form-data"]),
    ("木马文件上传", ("reqbody",), ['.php"', ".jsp\"", '.asp"', '.aspx"', ".war\""]),
    ("WebShell 控制", ("ua", "reqbody"), ["antsword", "behinder", "godzilla", "?php eval($_post",
                                       "?php eval($_request", "?php assert($_post",
                                       "base64_decode(", "@ini_set(", "gif89a<?php",
                                       "eval($_post", "system($_"]),
    ("命令执行特征", ("reqbody",), ["/bin/bash -i", "bash -i", "nc -e", "socat", "python -c",
                                "/dev/tcp/", "cmd.exe /c", "whoami", "uname -a", "id;"]),
]

SCOPE_KEYS = {
    "ua": lambda r: (r["ua"] or "").lower(),
    "uri": lambda r: (r["uri"] or "").lower(),
    "reqbody": lambda r: r["req_body"].decode("latin1", "ignore").lower(),
    "headers": lambda r: " ".join("%s: %s" % kv for kv in r["req_headers"].items()).lower(),
    "respbody": lambda r: r["resp_body"][:200000].decode("utf-8", "ignore").lower(),
    # payload 常被 URL 编码，必须解码后再匹配，否则 "into%20outfile" 会漏
    "decoded": lambda r: urllib.parse.unquote_plus(
        (r["uri"] or "") + " " + r["req_body"].decode("latin1", "ignore")).lower(),
}


def find_hits(recs):
    hits = collections.OrderedDict((name, []) for name, _, _ in SIGNATURES)
    for r in recs:
        cache = {}
        for name, scopes, pats in SIGNATURES:
            for p in pats:
                for s in scopes:
                    if s not in cache:
                        cache[s] = SCOPE_KEYS[s](r)
                    if p in cache[s]:
                        hits[name].append((r, p))
                        break
                else:
                    continue
                break
    return hits


def scan_suspects(recs, min_req=30, ratio=0.6):
    """UA 不可信时，用「404 占比」识别目录扫描：同一 UA 大量请求且绝大多数打空。"""
    stat = collections.defaultdict(lambda: [0, 0])
    for r in recs:
        k = r["ua"] or "(无 UA)"
        stat[k][0] += 1
        if r["status"] == "404":
            stat[k][1] += 1
    out = [(ua, t, n) for ua, (t, n) in stat.items() if t >= min_req and n / float(t) >= ratio]
    return sorted(out, key=lambda x: -x[1])


def non_http_streams(streams, recs, skip_ports=(80, 443, 8080, 8000, 8443)):
    """没有 HTTP 特征、却在传数据的长连接：可疑外联 / 反弹 shell。"""
    http_sids = {r["stream"] for r in recs}
    out = []
    for st in streams.values():
        if st.sid in http_sids or st.nbytes < 200:
            continue
        eps = list(st.dirs.keys())
        if len(eps) < 2:
            continue
        ports = {ep[1] for ep in eps}
        if ports & set(skip_ports):
            continue
        out.append(st)
    return sorted(out, key=lambda s: -s.nbytes)


# ---------------------------------------------------------------- 输出工具

def fmt_ts(ts, tz_offset=8):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts + tz_offset * 3600))
    except (OSError, ValueError, OverflowError):
        return "epoch=%.0f" % ts


def _is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%.1fTB" % n


def cmd_summary(args):
    streams, meta = load(args.pcap, not args.no_cache)
    recs = build_http(streams)
    print("=" * 78)
    print("文件      : %s (%s)" % (meta["path"], human(meta["size"])))
    print("包数      : %d" % meta["packets"])
    print("时间范围  : %s ~ %s (UTC+8, 时长 %.1f 分钟)" % (
        fmt_ts(meta["first_ts"]), fmt_ts(meta["last_ts"]),
        (meta["last_ts"] - meta["first_ts"]) / 60.0))
    print("协议构成  : %s" % ", ".join("%s=%d" % kv for kv in
                                   sorted(meta["protos"].items(), key=lambda x: -x[1])))
    print("TCP 会话  : %d 条, HTTP 请求 %d 个" % (len(streams), len(recs)))
    print("-" * 78)
    print("Top 会话（按载荷字节）")
    top = sorted(streams.values(), key=lambda s: -s.nbytes)[:15]
    print("%-4s %-22s %-22s %8s %6s %s" % ("ID", "A 端", "B 端", "字节", "包数", "起始"))
    for s in top:
        eps = list(s.dirs.keys())
        a = "%s:%d" % eps[0] if eps else "?"
        b = "%s:%d" % eps[1] if len(eps) > 1 else "?"
        print("%-4d %-22s %-22s %8d %6d %s" % (s.sid, a, b, s.nbytes, s.pkts, fmt_ts(s.ts)))
    print("-" * 78)
    ua_stat = collections.defaultdict(lambda: [0, 0])
    for r in recs:
        k = r["ua"] or "(无 UA)"
        ua_stat[k][0] += 1
        if r["status"] == "404":
            ua_stat[k][1] += 1
    sus_ua = {x[0] for x in scan_suspects(recs)}
    if ua_stat:
        print("客户端 UA 分布（★ = 404 占比高，疑似目录扫描）")
        for ua, (t, n) in sorted(ua_stat.items(), key=lambda kv: -kv[1][0])[:6]:
            print("  %s %5d 次  404 %5d (%.0f%%)  %s" % (
                "★" if ua in sus_ua else " ", t, n, 100.0 * n / t, ua[:64]))
    hits = find_hits(recs)
    print("-" * 78)
    print("攻击链签名命中")
    for name, items in hits.items():
        if items:
            r, p = items[0]
            print("  [命中] %-12s %4d 次  首现 %s  stream %-5d %s %s   <%s>" % (
                name, len(items), fmt_ts(min(x[0]["ts"] for x in items)), r["stream"],
                r["method"], r["uri"][:52], p))
        else:
            print("  [  - ] %s" % name)
    if not hits["侦察/扫描"] and sus_ua:
        print("  [推断] 目录扫描       %d 个 UA 的 404 占比 ≥60%%（UA 已伪装，签名不命中还要看行为）" % len(sus_ua))
    sus = non_http_streams(streams, recs)
    if sus:
        print("-" * 78)
        print("非 HTTP 却传数据的长连接（可疑外联 / 反弹 shell）")
        for st in sus[:8]:
            eps = list(st.dirs.keys())
            print("  stream %-5d %s:%d <-> %s:%d  %s / %d 包  起始 %s" % (
                st.sid, eps[0][0], eps[0][1], eps[1][0], eps[1][1],
                human(st.nbytes), st.pkts, fmt_ts(st.ts)))
        print("  查看详情: pcapkit.py stream <pcap> <ID>")
    if DECODE_ISSUES:
        print("-" * 78)
        print("解码提示: %s" % ", ".join("%s=%d" % kv for kv in DECODE_ISSUES.items()))
        print("  br/zstd 需第三方库；解压失败多为报文被截断，可用 stream <ID> 看原始字节")


def cmd_http(args):
    streams, meta = load(args.pcap, not args.no_cache)
    recs = build_http(streams)
    rows = []
    for r in recs:
        rows.append([fmt_ts(r["ts"]), r["stream"], r["client"], r["method"], r["uri"][:120],
                     r["status"], len(r["req_body"]), len(r["resp_body"]), r["ua"][:40]])
    if args.csv:
        import csv
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["time", "stream", "client", "method", "uri", "status",
                        "req_len", "resp_len", "ua"])
            w.writerows(rows)
        print("已写出 %d 行 -> %s" % (len(rows), args.csv))
        return
    print("%-19s %4s %-17s %-6s %-6s %6s %6s  %s" % (
        "时间", "流", "客户端", "方法", "状态", "请求", "响应", "URI"))
    for row in rows[:args.limit]:
        print("%-19s %4s %-17s %-6s %-6s %6d %6d  %s" % (
            row[0], row[1], row[2], row[3], row[5], row[6], row[7], row[4][:80]))
    if len(rows) > args.limit:
        print("... 共 %d 条，--limit 调整显示" % len(rows))


def cmd_grep(args):
    streams, meta = load(args.pcap, not args.no_cache)
    recs = build_http(streams)
    n = 0
    for r in recs:
        raw = "\n".join([
            r["method"] + " " + r["uri"],
            "\n".join("%s: %s" % kv for kv in r["req_headers"].items()),
            r["req_body"].decode("latin1", "ignore"),
            r["resp_body"].decode("utf-8", "ignore"),
        ])
        # 攻击 payload 常被 URL 编码，原文检索会漏；两条变体都搜
        variants = [("原文", raw), ("URL 解码后", urllib.parse.unquote_plus(raw))]
        found = []
        for p in args.patterns:
            for label, blob in variants:
                idx = blob.lower().find(p.lower())
                if idx >= 0:
                    found.append((p, label, idx, blob))
                    break
        if not found:
            continue
        n += 1
        print("=" * 92)
        print("[stream %d] %s  %s %s  ->  %s" % (r["stream"], fmt_ts(r["ts"]),
                                                 r["method"], r["uri"][:88], r["status_line"]))
        for p, label, idx, blob in found[:4]:
            s = max(0, idx - 130)
            snippet = blob[s:idx + 300].replace("\r", " ").replace("\n", " ")
            print("  <%s @%s> ...%s..." % (p, label, snippet[:400]))
    print("\n命中 %d 个请求（模式: %s）" % (n, ", ".join(args.patterns)))


def _hexdump(data, maxlen=1024):
    data = data[:maxlen]
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join("%02x" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append("%08x  %-47s  |%s|" % (off, hexs, asc))
    if len(data) >= maxlen:
        lines.append("... 仅显示前 %d 字节" % maxlen)
    return "\n".join(lines)


def _as_text(data, limit):
    """能当文本就给文本，不能就给十六进制。二进制证据必须走 hexdump，不能瞎猜编码。"""
    head = data[:limit]
    if not head:
        return "(空)"
    for enc in ("utf-8", "gbk"):
        try:
            return head.decode(enc)
        except UnicodeDecodeError:
            continue
    return _hexdump(head)


def _indent(text, prefix="  "):
    return "\n".join(prefix + line for line in text.split("\n"))


def cmd_stream(args):
    streams, meta = load(args.pcap, not args.no_cache)
    st = None
    for s in streams.values():
        if s.sid == args.id:
            st = s
            break
    if st is None:
        print("没有 stream %d（该文件共 %d 条）" % (args.id, len(streams)))
        return
    out = sys.stdout.buffer

    def w(s):
        # --raw 时摘要走 stderr，保证 stdout 是纯净字节流，可直接重定向为 .bin
        target = sys.stderr.buffer if args.raw else out
        target.write(s.encode("utf-8", "replace"))
        target.flush()

    w("stream %d  %s ~ %s  %d 包  %s\n" % (st.sid, fmt_ts(st.ts), fmt_ts(st.ts_last),
                                          st.pkts, human(st.nbytes)))
    for ep, d in st.dirs.items():
        buf = d["buf"]
        w("\n##### %s:%d  (%d 包, %d 字节, 空洞 %d) #####\n" % (
            ep[0], ep[1], d["packets"], len(buf), st.gaps))
        if args.raw:                                  # 原样字节，允许管道重定向成 .bin
            out.write(buf)
            continue
        msgs = parse_http(buf)
        if not msgs:
            sniff = _inflate(buf, "")
            note = "，已按魔术字节嗅探解压" if sniff is not buf and len(sniff) != len(buf) else ""
            w("（非 HTTP 报文%s）\n" % note)
            w(_indent(_as_text(sniff, args.limit)) + "\n")
            continue
        for m in msgs:
            kind = "响应" if m["first_line"].startswith("HTTP/") else "请求"
            w("\n--- %s: %s ---\n" % (kind, m["first_line"]))
            for k in ("host", "user-agent", "content-type", "content-encoding",
                      "content-length", "transfer-encoding", "referer", "cookie"):
                if k in m["headers"]:
                    w("  %s: %s\n" % (k, m["headers"][k]))
            body = m["body"]
            tags = []
            if m["headers"].get("content-encoding"):
                tags.append("已解压 %s" % m["headers"]["content-encoding"])
            if len(body) > args.limit:
                tags.append("仅显示前 %d 字节" % args.limit)
            w("  [body %d 字节%s]\n" % (len(body), ("; " + ", ".join(tags)) if tags else ""))
            if body:
                w(_indent(_as_text(body, args.limit)) + "\n")
                # 攻击 payload 基本都被 URL 编码，顺手解一份，省得自己翻译
                if kind == "请求" and body.count(b"%") >= 8:
                    dec = urllib.parse.unquote_to_bytes(body)
                    if dec != body:
                        w("  [URL 解码后]\n" + _indent(_as_text(dec, args.limit)) + "\n")
    sys.stdout.flush()


def _safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80] or "obj"


INTERESTING_URI = re.compile(
    r"\.(php\d?|jsp|jspx|asp|aspx|war|jar|sh|pl|py|exe|elf|dll|zip|rar|7z|tar|gz|bin|"
    r"js|xml|conf|bak|sql|txt|php\.bak)$", re.I)


def _keep_resp(r, args):
    """默认只落地「可能有价值」的响应，避免几万个 404 页面把目录淹掉。"""
    if args.all:
        return True
    if r["status"] not in ("200", "201", "202"):
        return False
    if len(r["resp_body"]) < args.min_size:
        return False
    if r["method"] != "GET" and not args.post:
        return False                       # POST 回包多为注入探测噪声，木马已在请求体里
    u = r["uri"].split("?")[0]
    return bool(INTERESTING_URI.search(u)) or "/upload" in u.lower() or args.post


def cmd_export(args):
    streams, meta = load(args.pcap, not args.no_cache)
    recs = build_http(streams)
    os.makedirs(args.dir, exist_ok=True)
    n_resp = n_req = n_up = 0
    manifest = []
    keep_status = ("200", "201", "202", "301", "302", "500")
    for i, r in enumerate(recs):
        interesting = _keep_resp(r, args) or args.all
        base = "%04d_s%d_%s" % (i, r["stream"],
                                _safe_name(os.path.basename(r["uri"].split("?")[0]) or "index"))
        if r["resp_body"] and interesting:
            p = os.path.join(args.dir, base + ".resp")
            with open(p, "wb") as f:
                f.write(r["resp_body"])
            n_resp += 1
            manifest.append({"file": os.path.basename(p), "kind": "response",
                             "stream": r["stream"], "uri": r["uri"], "status": r["status"],
                             "size": len(r["resp_body"])})
        ct = (r["req_headers"].get("content-type") or "").lower()
        body = r["req_body"]
        if body and r["method"] in ("POST", "PUT") and args.all:
            ext = ".req.bin"
            if "multipart" in ct:
                ext = ".req.multipart"
            elif b"<?php" in body:
                ext = ".req.php"
            p = os.path.join(args.dir, base + ext)
            with open(p, "wb") as f:
                f.write(body)
            n_req += 1
            manifest.append({"file": os.path.basename(p), "kind": "request",
                             "stream": r["stream"], "uri": r["uri"], "size": len(body)})
        # multipart 中的文件片段单独落地（上传的木马通常藏在这里）
        if body and "multipart" in ct:
            if not args.all:
                p = os.path.join(args.dir, base + ".req.multipart")
                with open(p, "wb") as f:
                    f.write(body)
                n_req += 1
            for m in re.finditer(rb'filename="([^"]*)"', body):
                fname = _safe_name(m.group(1).decode("latin1", "ignore") or "blob")
                start = body.find(b"\r\n\r\n", m.end())
                if start < 0:
                    continue
                start += 4
                end = body.find(b"\r\n--", start)
                chunk = body[start:end if end > 0 else len(body)]
                if not chunk:
                    continue
                p = os.path.join(args.dir, base + "_upload_" + fname + ".bin")
                with open(p, "wb") as f:
                    f.write(chunk)
                n_up += 1
                manifest.append({"file": os.path.basename(p), "kind": "uploaded",
                                 "stream": r["stream"], "uri": r["uri"],
                                 "filename": fname, "size": len(chunk),
                                 "has_php": b"<?php" in chunk})
    with open(os.path.join(args.dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print("响应体 %d / 请求体 %d / 上传片段 %d -> %s" % (n_resp, n_req, n_up, args.dir))
    if n_up:
        print("上传片段清单见 manifest.json（has_php=true 的即疑似木马本体）")


def cmd_report(args):
    streams, meta = load(args.pcap, not args.no_cache)
    recs = build_http(streams)
    hits = find_hits(recs)
    os.makedirs(args.dir, exist_ok=True)
    L = []
    A = L.append
    A("# 流量取证报告\n")
    A("## 1. 样本概况\n")
    A("| 项 | 值 |")
    A("|---|---|")
    A("| 文件 | `%s` |" % os.path.basename(meta["path"]))
    A("| 大小 | %s |" % human(meta["size"]))
    A("| 数据包 | %d |" % meta["packets"])
    A("| 时间范围 | %s ~ %s (UTC+8) |" % (fmt_ts(meta["first_ts"]), fmt_ts(meta["last_ts"])))
    A("| 时长 | %.1f 分钟 |" % ((meta["last_ts"] - meta["first_ts"]) / 60.0))
    A("| TCP 会话 | %d |" % len(streams))
    A("| HTTP 请求 | %d |" % len(recs))
    A("")
    A("## 2. 通信画像\n")
    A("| stream | A 端 | B 端 | 载荷字节 | 包数 | 起始 |")
    A("|---|---|---|---|---|---|")
    for s in sorted(streams.values(), key=lambda x: -x.nbytes)[:12]:
        eps = list(s.dirs.keys())
        A("| %d | %s | %s | %d | %d | %s |" % (
            s.sid, "%s:%d" % eps[0] if eps else "?", "%s:%d" % eps[1] if len(eps) > 1 else "?",
            s.nbytes, s.pkts, fmt_ts(s.ts)))
    A("")
    ua_stat = collections.defaultdict(lambda: [0, 0])
    for r in recs:
        k = r["ua"] or "(无 UA)"
        ua_stat[k][0] += 1
        if r["status"] == "404":
            ua_stat[k][1] += 1
    sus_ua = {x[0] for x in scan_suspects(recs)}
    if ua_stat:
        A("### 客户端 UA\n")
        A("| UA | 请求数 | 404 | 404 占比 | 判断 |")
        A("|---|---|---|---|---|")
        for ua, (t, n) in sorted(ua_stat.items(), key=lambda kv: -kv[1][0])[:8]:
            A("| `%s` | %d | %d | %.0f%% | %s |" % (
                ua.replace("|", "\\|")[:70], t, n, 100.0 * n / t,
                "疑似目录扫描" if ua in sus_ua else ""))
        A("")
    A("## 3. 攻击链命中\n")
    A("| 阶段 | 命中次数 | 首次出现 | 代表请求 | stream | 命中特征 |")
    A("|---|---|---|---|---|---|")
    for name, items in hits.items():
        if not items:
            if name == "侦察/扫描" and sus_ua:
                worst = max([k for k in ua_stat if k in sus_ua],
                            key=lambda k: ua_stat[k][0])
                t, n = ua_stat[worst]
                A("| 侦察/扫描(推断) | %d | - | UA 404 占比 %.0f%% | - | `%s` |" % (
                    t, 100.0 * n / t, worst.replace("|", "\\|")[:40]))
            else:
                A("| %s | 0 | - | - | - | - |" % name)
            continue
        first = min(items, key=lambda x: x[0]["ts"])
        r, p = first
        A("| %s | %d | %s | `%s %s` | %d | `%s` |" % (
            name, len(items), fmt_ts(r["ts"]), r["method"], r["uri"][:60].replace("|", "\\|"),
            r["stream"], p.replace("|", "\\|")))
    A("")
    A("## 4. 关键事件时间线\n")
    A("| 时间 | stream | 请求 | 状态 | 说明 |")
    A("|---|---|---|---|---|")
    marks = []
    sus_ua2 = {x[0] for x in scan_suspects(recs)}
    scan_recs = [r for r in recs if (r["ua"] or "(无 UA)") in sus_ua2]
    if scan_recs:
        r0 = min(scan_recs, key=lambda x: x["ts"])
        marks.append((r0["ts"], r0["stream"], r0["method"], r0["uri"], r0["status"], "目录扫描开始"))
    per_stage = collections.Counter()
    for name, items in hits.items():
        for r, p in items:
            if r["status"] == "404":
                continue                       # 打空的扫描请求不占时间线
            per_stage[name] += 1
            if per_stage[name] > 5:            # 每个阶段最多留 5 条代表性事件
                continue
            marks.append((r["ts"], r["stream"], r["method"], r["uri"], r["status"], name))
    for m in sorted(marks)[:args.max_events]:
        A("| %s | %d | `%s %s` | %s | %s |" % (fmt_ts(m[0]), m[1], m[2],
                                              m[3][:58].replace("|", "\\|"), m[4], m[5]))
    A("")
    A("## 5. 可疑外联 / 非 HTTP 通道\n")
    sus = non_http_streams(streams, recs)
    if sus:
        A("| stream | 端点 A | 端点 B | 载荷字节 | 包数 | 起始 |")
        A("|---|---|---|---|---|---|")
        for st in sus[:10]:
            eps = list(st.dirs.keys())
            A("| %d | %s:%d | %s:%d | %d | %d | %s |" % (
                st.sid, eps[0][0], eps[0][1], eps[1][0], eps[1][1],
                st.nbytes, st.pkts, fmt_ts(st.ts)))
    else:
        A("未发现（全部数据流均落在常见 HTTP 端口或已识别为 HTTP）。")
    A("")
    A("## 6. IOC\n")
    ext = set()
    for s in streams.values():
        for ep in s.dirs:
            if not _is_private(ep[0]):
                ext.add(ep[0])
    A("- 外部端点: %s" % (", ".join("`%s`" % x for x in sorted(ext)[:20]) or "无（样本内全部为内网地址）"))
    uas = sorted({r["ua"] for r in recs if r["ua"]})
    for ua in uas[:10]:
        A("- User-Agent: `%s`" % ua)
    paths = sorted({r["uri"] for r in recs if r["status"] in ("200", "302") and
                    re.search(r"\.(php|jsp|asp|aspx|war)$", r["uri"], re.I)})
    for p in paths[:15]:
        A("- 可访问脚本: `%s`" % p)
    A("")
    A("## 7. 下一步建议\n")
    A("- 对命中 WebShell 的路径做文件哈希与落地时间核对（`pcapkit.py export` 已导出请求体）。")
    A("- 对外部端点做封禁与历史流量回溯。")
    A("- 复核服务器侧同时间窗的 access.log / auth.log，交叉验证包内结论。")
    A("")
    out = os.path.join(args.dir, "report.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print("报告已生成: %s" % out)
    print("阶段命中: %s" % ", ".join("%s=%d" % (k, len(v)) for k, v in hits.items() if v))


def main(argv=None):
    ap = argparse.ArgumentParser(description="零依赖 PCAP 取证工具")
    ap.add_argument("--no-cache", action="store_true", help="禁用中间结果缓存")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-cache", action="store_true", default=argparse.SUPPRESS,
                        help="禁用中间结果缓存")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("summary", help="文件概览与会话统计", parents=[common])
    p.add_argument("pcap")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("http", help="列出 HTTP 请求", parents=[common])
    p.add_argument("pcap")
    p.add_argument("--csv")
    p.add_argument("--limit", type=int, default=60)
    p.set_defaults(func=cmd_http)

    p = sub.add_parser("grep", help="关键字检索", parents=[common])
    p.add_argument("pcap")
    p.add_argument("patterns", nargs="+")
    p.set_defaults(func=cmd_grep)

    p = sub.add_parser("stream", help="还原指定 TCP 流（默认解码 HTTP 与 gzip）", parents=[common])
    p.add_argument("pcap")
    p.add_argument("id", type=int)
    p.add_argument("--limit", type=int, default=8000, help="每个报文最多显示多少字节")
    p.add_argument("--raw", action="store_true",
                   help="输出线上原始字节（不做换行转换，可重定向为 .bin）")
    p.set_defaults(func=cmd_stream)

    p = sub.add_parser("export", help="导出请求/响应体", parents=[common])
    p.add_argument("pcap")
    p.add_argument("-d", "--dir", default="pcap_objects")
    p.add_argument("--all", action="store_true", help="连 404 页面和全部 POST 体一起导出")
    p.add_argument("--post", action="store_true", help="同时导出 POST 响应体")
    p.add_argument("--min-size", type=int, default=200)
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("report", help="生成 Markdown 报告", parents=[common])
    p.add_argument("pcap")
    p.add_argument("-d", "--dir", default="pcap_report")
    p.add_argument("--max-events", type=int, default=40)
    p.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
