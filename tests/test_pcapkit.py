#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcapkit 回归测试：合成各类抓包，断言解析/解码/取证行为。

运行: python tests/test_pcapkit.py         （或 python -m unittest discover -s tests -v）
只用标准库，不依赖任何样本文件。

注意: 用例里的 webshell 载荷是用片段拼出来的，不写字面量。
      否则在装了终端防护的 Windows 上，本文件会被当成木马直接隔离
      （实测：Defender 会删掉含完整一句话木马的 .py）。
"""
import gzip
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import pcapkit as P  # noqa: E402

TOOL = os.path.join(ROOT, "scripts", "pcapkit.py")
TMP = tempfile.mkdtemp(prefix="pcapkit_test_")


# ---------------------------------------------------------------- 构造工具

def _php_shell():
    """片段拼接，避免在源码里留下可被查杀的完整 webshell。"""
    return b"".join([b"GIF89a\n", b"<", b"?", b"php ", b"ev", b"al", b"(",
                     b"$_", b"PO", b"ST", b"[", b"'pass'", b"]", b")", b";",
                     b"?", b">"])


def eth(payload, ethertype=0x0800, vlan=None):
    head = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
    if vlan is not None:
        return head + b"\x81\x00" + struct.pack(">H", vlan) + struct.pack(">H", ethertype) + payload
    return head + struct.pack(">H", ethertype) + payload


def ipv4(proto, src, dst, payload):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def ipv6(proto, src, dst, payload):
    return struct.pack(">IHBB", 0x60000000, len(payload), proto, 64) + \
        socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload


def tcp(sport, dport, seq, payload=b"", flags=0x18, ack=0):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def pkt(src, dst, sport, dport, seq, payload=b"", flags=0x18, v6=False, vlan=None, ack=0):
    seg = tcp(sport, dport, seq, payload, flags, ack)
    l3 = ipv6(6, src, dst, seg) if v6 else ipv4(6, src, dst, seg)
    return eth(l3, 0x86DD if v6 else 0x0800, vlan)


def pkt_raw_ip(src, dst, sport, dport, seq, payload):
    return ipv4(6, src, dst, tcp(sport, dport, seq, payload))


def pkt_sll(src, dst, sport, dport, seq, payload):
    l3 = ipv4(6, src, dst, tcp(sport, dport, seq, payload))
    return struct.pack(">HHH", 1, 1, 6) + b"\x00" * 8 + b"\x08\x00" + l3


def pkt_udp(src, dst, sport, dport, payload):
    return eth(ipv4(17, src, dst, struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload))


def write_pcap(name, frames, linktype=1, endian="<", nano=False):
    path = os.path.join(TMP, name)
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
        for ts, fr in frames:
            sec = int(ts)
            frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
            f.write(struct.pack(endian + "IIII", sec, frac, len(fr), len(fr)))
            f.write(fr)
    return path


def _blk(btype, body):
    body += b"\x00" * ((-len(body) - 12) % 4)
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def write_pcapng(name, frames, linktype=1):
    path = os.path.join(TMP, name)
    out = _blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += _blk(1, struct.pack("<HHI", linktype, 0, 0))
    for ts, fr in frames:
        us = int(round(ts * 1e6))
        out += _blk(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(fr), len(fr)) + fr)
    with open(path, "wb") as f:
        f.write(out)
    return path


# ---------------------------------------------------------------- 报文片段

REQ = (b"GET /index.php HTTP/1.1\r\nHost: t.local\r\nUser-Agent: Mozilla/5.0\r\n"
       b"Accept-Encoding: gzip, deflate\r\n\r\n")
HTML = b"<!DOCTYPE html><html><body>" + b"A" * 200 + b"</body></html>"


def resp(body=HTML, extra=b"", enc=None, chunked=False):
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
    if enc:
        head += b"Content-Encoding: " + enc + b"\r\n"
    head += extra
    if chunked:
        head += b"Transfer-Encoding: chunked\r\n\r\n"
        out = b""
        for i in range(0, len(body), 100):
            part = body[i:i + 100]
            out += b"%x\r\n" % len(part) + part + b"\r\n"
        return head + out + b"0\r\n\r\n"
    return head + b"Content-Length: %d\r\n\r\n" % len(body) + body


def conv(path):
    streams, meta = P.load(path, use_cache=False)
    return P.build_http(streams), meta


# ---------------------------------------------------------------- 用例

class TestFormats(unittest.TestCase):
    def _basic(self, **kw):
        p = write_pcap("fmt.pcap", [(1588923183.5, pkt("10.0.0.1", "10.0.0.2", 1234, 80, 1, REQ)),
                                    (1588923183.6, pkt("10.0.0.2", "10.0.0.1", 80, 1234, 1, resp()))], **kw)
        recs, meta = conv(p)
        self.assertEqual(len(recs), 1, "应解析出 1 个请求")
        self.assertEqual(recs[0]["uri"], "/index.php")
        self.assertEqual(recs[0]["status"], "200")
        return meta

    def test_pcap_little_endian(self):
        m = self._basic(endian="<")
        self.assertEqual(m["packets"], 2)
        self.assertAlmostEqual(m["first_ts"], 1588923183.5, places=2)

    def test_pcap_big_endian(self):
        self._basic(endian=">")

    def test_pcap_nanosecond(self):
        p = write_pcap("nano.pcap", [(1588923183.123456789,
                                      pkt("10.0.0.1", "10.0.0.2", 1234, 80, 1, REQ))], nano=True)
        recs, meta = conv(p)
        self.assertAlmostEqual(meta["first_ts"], 1588923183.1235, places=3)

    def test_pcapng(self):
        p = write_pcapng("t.pcapng", [(1588923183.0, pkt("10.0.0.1", "10.0.0.2", 1234, 80, 1, REQ)),
                                      (1588923184.0, pkt("10.0.0.2", "10.0.0.1", 80, 1234, 1, resp()))])
        recs, meta = conv(p)
        self.assertEqual(len(recs), 1)
        self.assertAlmostEqual(meta["first_ts"], 1588923183.0, places=1)

    def test_linktype_raw_ip(self):
        p = write_pcap("rawip.pcap", [(1.0, pkt_raw_ip("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ))],
                       linktype=101)
        self.assertEqual(len(conv(p)[0]), 1)

    def test_linktype_linux_sll(self):
        p = write_pcap("sll.pcap", [(1.0, pkt_sll("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ))],
                       linktype=113)
        self.assertEqual(len(conv(p)[0]), 1)

    def test_vlan_tagged(self):
        p = write_pcap("vlan.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ, vlan=100))])
        self.assertEqual(len(conv(p)[0]), 1)

    def test_ipv6(self):
        p = write_pcap("v6.pcap", [(1.0, pkt("fd00::1", "fd00::2", 1, 80, 1, REQ, v6=True))])
        recs, _ = conv(p)
        self.assertEqual(len(recs), 1)
        self.assertIn("fd00", recs[0]["client"])

    def test_udp_does_not_crash(self):
        p = write_pcap("udp.pcap", [(1.0, pkt_udp("10.0.0.1", "10.0.0.2", 5353, 53, b"x" * 40))])
        recs, meta = conv(p)
        self.assertEqual(recs, [])
        self.assertEqual(meta["protos"].get("UDP"), 1)

    def test_bad_magic_raises(self):
        p = os.path.join(TMP, "bad.pcap")
        with open(p, "wb") as f:
            f.write(b"NOTAPCAP" + b"\x00" * 40)
        with self.assertRaises(ValueError):
            P.load(p, use_cache=False)

    def test_truncated_file(self):
        p = write_pcap("trunc.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ))])
        with open(p, "rb") as f:
            raw = f.read()
        with open(p, "wb") as f:
            f.write(raw[:-20])            # 砍掉包尾
        recs, meta = conv(p)              # 不应抛异常
        self.assertIsInstance(meta["packets"], int)

    def test_empty_file(self):
        p = os.path.join(TMP, "empty.pcap")
        open(p, "wb").close()
        with self.assertRaises(ValueError):
            P.load(p, use_cache=False)


class TestReassembly(unittest.TestCase):
    def _run(self, frames):
        p = write_pcap("re.pcap", [(1.0 + i * 0.001, fr) for i, fr in enumerate(frames)])
        return conv(p)[0]

    def test_out_of_order(self):
        """后段先到、前段后到，仍要拼出完整请求。"""
        seg1, seg2 = REQ[:200], REQ[200:] + b"x" * 300
        frames = [pkt("10.0.0.1", "10.0.0.2", 1, 80, 100000 + 200, seg2),   # 后段先到
                  pkt("10.0.0.1", "10.0.0.2", 1, 80, 100000, seg1)]
        recs = self._run(frames)
        self.assertEqual(len(recs), 1, "乱序也要拼出完整请求")
        self.assertEqual(recs[0]["uri"], "/index.php")

    def test_retransmission(self):
        frames = [pkt("10.0.0.1", "10.0.0.2", 1, 80, 500, REQ),
                  pkt("10.0.0.1", "10.0.0.2", 1, 80, 500, REQ)]
        recs = self._run(frames)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["uri"], "/index.php")

    def test_partial_retransmission(self):
        frames = [pkt("10.0.0.1", "10.0.0.2", 1, 80, 500, REQ),
                  pkt("10.0.0.1", "10.0.0.2", 1, 80, 510, REQ[10:])]
        self.assertEqual(len(self._run(frames)), 1)

    def test_gap_recorded(self):
        p = write_pcap("gap.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 500, REQ)),
                                    (1.1, pkt("10.0.0.1", "10.0.0.2", 1, 80, 900, b"tail"))])
        streams, _ = P.load(p, use_cache=False)
        st = list(streams.values())[0]
        self.assertGreaterEqual(st.gaps, 1, "应记录空洞")
        self.assertEqual(len(P.build_http(streams)), 1)

    def test_keepalive_multi_message(self):
        frames = [pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ + REQ),
                  pkt("10.0.0.2", "10.0.0.1", 80, 1, 1, resp(b"one") + resp(b"two"))]
        recs = self._run(frames)
        self.assertEqual(len(recs), 2, "keep-alive 应拆成两条记录")
        self.assertEqual([r["resp_body"] for r in recs], [b"one", b"two"])


class TestDecoding(unittest.TestCase):
    def _resp_only(self, raw_resp):
        p = write_pcap("dec.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ)),
                                    (1.1, pkt("10.0.0.2", "10.0.0.1", 80, 1, 1, raw_resp))])
        return conv(p)[0][0]

    def test_gzip(self):
        self.assertEqual(self._resp_only(resp(gzip.compress(HTML), enc=b"gzip"))["resp_body"], HTML)

    def test_deflate_zlib(self):
        self.assertEqual(self._resp_only(resp(zlib.compress(HTML), enc=b"deflate"))["resp_body"], HTML)

    def test_deflate_raw(self):
        co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        raw = co.compress(HTML) + co.flush()
        self.assertEqual(self._resp_only(resp(raw, enc=b"deflate"))["resp_body"], HTML)

    def test_chunked_plus_gzip(self):
        self.assertEqual(self._resp_only(resp(gzip.compress(HTML), enc=b"gzip", chunked=True))["resp_body"], HTML)

    def test_chunked_only(self):
        self.assertEqual(self._resp_only(resp(HTML, chunked=True))["resp_body"], HTML)

    def test_magic_sniff_without_header(self):
        """Content-Encoding 缺失时靠 1f8b 嗅探解压。"""
        self.assertEqual(self._resp_only(resp(gzip.compress(HTML)))["resp_body"], HTML)

    def test_truncated_gzip_keeps_raw(self):
        r = self._resp_only(resp(gzip.compress(HTML)[:20], enc=b"gzip"))
        self.assertIsInstance(r["resp_body"], bytes)

    def test_brotli_reports_issue(self):
        P.DECODE_ISSUES.clear()
        r = self._resp_only(resp(b"\x0b\x02\x80fake", enc=b"br"))
        self.assertEqual(r["resp_body"], b"\x0b\x02\x80fake")
        self.assertIn("br", P.DECODE_ISSUES)


class TestForensics(unittest.TestCase):
    def _attack_pcap(self):
        inj = (b"POST /admin/login.php?action=ck_login HTTP/1.1\r\nHost: t.local\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 60\r\n\r\n"
               b"user=admin%27%20UNION%20ALL%20SELECT%20NULL%20FROM%20information_schema")
        shell = _php_shell()
        mp_head = (b"POST /admin/upload.php HTTP/1.1\r\nHost: t.local\r\n"
                   b"Content-Type: multipart/form-data; boundary=----X\r\nContent-Length: %d\r\n\r\n")
        mp_body = (b"------X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"1.php\"\r\n"
                   b"Content-Type: image/gif\r\n\r\n" + shell + b"\r\n------X--\r\n")
        mp = mp_head % len(mp_body) + mp_body
        ws = (b"POST /upload/1.php HTTP/1.1\r\nHost: t.local\r\nUser-Agent: antSword/v2.1\r\n"
              b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\npass=ls")
        scan = b"GET /a1b2c3 HTTP/1.1\r\nHost: t.local\r\nUser-Agent: scanner/1.0\r\n\r\n"
        notfound = b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope"
        frames = [
            (1.0, pkt("10.0.0.9", "10.0.0.2", 5000, 80, 1, scan)),
            (1.1, pkt("10.0.0.2", "10.0.0.9", 80, 5000, 1, notfound)),
            (2.0, pkt("10.0.0.9", "10.0.0.2", 5002, 80, 1, inj)),
            (2.1, pkt("10.0.0.2", "10.0.0.9", 80, 5002, 1, resp(b"err"))),
            (3.0, pkt("10.0.0.9", "10.0.0.2", 5004, 80, 1, mp)),
            (3.1, pkt("10.0.0.2", "10.0.0.9", 80, 5004, 1, resp(b"OK"))),
            (4.0, pkt("10.0.0.9", "10.0.0.2", 5006, 80, 1, ws)),
            (4.1, pkt("10.0.0.2", "10.0.0.9", 80, 5006, 1, resp(b"ok"))),
        ]
        return write_pcap("attack.pcap", frames)

    def test_signatures(self):
        recs, _ = conv(self._attack_pcap())
        hits = P.find_hits(recs)
        self.assertTrue(hits["SQL 注入"], "应命中 SQL 注入")
        self.assertTrue(hits["木马文件上传"], "应命中木马上传")
        self.assertTrue(hits["WebShell 控制"], "应命中 WebShell")
        self.assertTrue(hits["文件上传"], "应命中文件上传")

    def test_url_encoded_payload_matched(self):
        """INTO OUTFILE 被 URL 编码后仍要命中（关键回归点）。"""
        p = write_pcap("enc.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1,
                        b"POST /a.php HTTP/1.1\r\nHost: t\r\nContent-Length: 40\r\n\r\n"
                        b"x=1%20INTO%20OUTFILE%20%27/tmp/a.php%27"))])
        recs, _ = conv(p)
        self.assertTrue(P.find_hits(recs)["文件写入/拖库"])

    def test_scan_ratio_heuristic(self):
        frames = []
        for i in range(40):
            frames.append((1.0 + i, pkt("10.0.0.9", "10.0.0.2", 6000 + i, 80, 1,
                                        b"GET /n%d HTTP/1.1\r\nHost: t\r\nUser-Agent: fake-chrome\r\n\r\n" % i)))
            frames.append((1.0 + i + 0.5, pkt("10.0.0.2", "10.0.0.9", 80, 6000 + i, 1,
                                              b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")))
        recs, _ = conv(write_pcap("scan.pcap", frames))
        suspects = P.scan_suspects(recs)
        self.assertEqual(len(suspects), 1)
        self.assertEqual(suspects[0][2], 40)

    def test_export_multipart_and_manifest(self):
        p = self._attack_pcap()
        out = os.path.join(TMP, "obj")
        P.main(["export", p, "-d", out])
        uploads = [f for f in os.listdir(out) if "_upload_" in f]
        self.assertTrue(uploads, "应拆出上传片段")
        target = os.path.join(out, uploads[0])
        self.assertGreater(os.path.getsize(target), 0)
        try:                                   # 含 webshell 的文件可能被安全软件锁定
            with open(target, "rb") as f:
                self.assertIn(b"php", f.read())
        except OSError as e:
            self.assertEqual(e.errno, 22, "仅允许被安全软件锁定这一种失败")
        with open(os.path.join(out, "manifest.json"), encoding="utf-8") as f:
            man = json.load(f)
        self.assertTrue(any(m.get("has_php") for m in man))

    def test_export_filters_404(self):
        p = self._attack_pcap()
        out = os.path.join(TMP, "obj2")
        P.main(["export", p, "-d", out])
        for f in os.listdir(out):
            if f.endswith(".resp"):
                try:
                    with open(os.path.join(out, f), "rb") as fh:
                        self.assertNotIn(b"nope", fh.read())
                except OSError:
                    pass

    def test_report_generated(self):
        p = self._attack_pcap()
        out = os.path.join(TMP, "rep")
        P.main(["report", p, "-d", out])
        with open(os.path.join(out, "report.md"), encoding="utf-8") as f:
            md = f.read()
        for section in ("样本概况", "攻击链命中", "关键事件时间线", "IOC"):
            self.assertIn(section, md)
        self.assertLess(len(md), 200000, "报告不应被噪声撑爆")


class TestCli(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True)

    def test_help(self):
        r = self._run("--help")
        self.assertEqual(r.returncode, 0)
        for cmd in (b"summary", b"http", b"grep", b"stream", b"export", b"report"):
            self.assertIn(cmd, r.stdout)

    def test_missing_file(self):
        self.assertNotEqual(self._run("summary", os.path.join(TMP, "no_such.pcap")).returncode, 0)

    def test_no_cache_accepted_before_and_after_subcommand(self):
        p = write_pcap("cli0.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ))])
        for args in (("--no-cache", "summary", p), ("summary", p, "--no-cache")):
            r = self._run(*args)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))

    def test_invalid_stream_id(self):
        p = write_pcap("cli.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ))])
        r = self._run("stream", p, "99999", "--no-cache")
        self.assertEqual(r.returncode, 0)
        self.assertIn("没有 stream", r.stdout.decode("utf-8", "replace"))

    def test_stream_decoded_and_raw(self):
        raw_resp = resp(gzip.compress(HTML), enc=b"gzip")
        p = write_pcap("cli2.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ)),
                                     (1.1, pkt("10.0.0.2", "10.0.0.1", 80, 1, 1, raw_resp))])
        r = self._run("stream", p, "1", "--no-cache")
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertIn(b"<!DOCTYPE html>", r.stdout, "默认输出应是解压后的 HTML")
        self.assertIn("已解压 gzip".encode("utf-8"), r.stdout)
        self.assertNotIn(b"\x1f\x8b", r.stdout, "默认输出不应含 gzip 原始字节")
        self.assertNotIn(b"\r\r\n", r.stdout, "不应出现双回车")

        raw = self._run("stream", p, "1", "--raw", "--no-cache")
        self.assertIn(b"\x1f\x8b", raw.stdout, "--raw 应保留原始压缩字节")
        self.assertEqual(len(raw.stdout), len(REQ) + len(raw_resp),
                         "--raw 应输出纯净字节（摘要走 stderr）")

    def test_summary_http_grep(self):
        p = write_pcap("cli3.pcap", [(1.0, pkt("10.0.0.1", "10.0.0.2", 1, 80, 1, REQ)),
                                     (1.1, pkt("10.0.0.2", "10.0.0.1", 80, 1, 1, resp()))])
        for cmd in ("summary", "http"):
            r = self._run(cmd, p, "--no-cache")
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        r = self._run("http", p, "--csv", os.path.join(TMP, "o.csv"), "--no-cache")
        self.assertTrue(os.path.exists(os.path.join(TMP, "o.csv")))
        r = self._run("grep", p, "index.php", "--no-cache")
        self.assertIn("命中 1 个请求", r.stdout.decode("utf-8", "replace"))


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
