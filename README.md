# pcap-forensics

一个 **零依赖的 pcap 流量取证技能**：不装 Wireshark、不装 scapy、不装 tshark，只用 Python 标准库，
把一份抓包文件讲成「谁、什么时候、用什么手法、留下了什么证据」。

面向入侵回溯 / 应急响应 / CTF 流量题 / 内网事件排查。

## 它解决什么问题

拿到一个 `.pcap`，常见困境是：环境里没装 Wireshark，于是开始用 `struct.unpack` 逐字节手撸解析器，
一边写一边踩 gzip、chunked、TCP 重传、URL 编码、multipart 的坑，最后写出几百行一次性脚本，下次还得重来。

这个技能把那一整套沉淀成一条命令，并把它固化成一个可被 AI 助手直接调用的 WorkBuddy Skill。

## 安装

### 作为 WorkBuddy 技能

```bash
git clone https://github.com/ggvchen/pcap-forensics.git ~/.workbuddy/skills/pcap-forensics
```

之后在会话里说「分析这个 pcap」「这个包里谁在攻击」即可自动触发。

### 只当命令行工具用

```bash
git clone https://github.com/ggvchen/pcap-forensics.git
python pcap-forensics/scripts/pcapkit.py summary 你的文件.pcap
```

要求：Python 3.8+，无第三方依赖。

## 快速开始

```bash
# 1. 三分钟定盘子：时间范围、协议构成、Top 会话、UA 分布、攻击链命中
python scripts/pcapkit.py summary 流量.pcap

# 2. 按阶段检索（自动带 URL 解码，命中率远高于直接搜原文）
python scripts/pcapkit.py grep 流量.pcap "union select" "into outfile" "antsword"

# 3. 还原单条 TCP 流（等价 Wireshark Follow Stream）
python scripts/pcapkit.py stream 流量.pcap 13706

# 4. 证据落地：响应体 + multipart 里上传的木马本体
python scripts/pcapkit.py export 流量.pcap -d objects/

# 5. 出报告
python scripts/pcapkit.py report 流量.pcap -d report/
```

## 六个子命令

| 子命令 | 作用 | 关键参数 |
|---|---|---|
| `summary` | 文件概览、会话排行、UA 404 率、八段攻击链命中 | — |
| `http` | 列出全部 HTTP 请求，可导出 CSV | `--csv out.csv` `--limit N` |
| `grep` | 请求行/头/体/响应体检索，自动比对 URL 解码后文本 | 多个模式并列 |
| `stream` | 还原指定 stream 的双向字节流 | `--limit N` |
| `export` | 落盘响应体、POST 体、multipart 文件片段 | `--all` `--post` `--min-size` |
| `report` | 生成 Markdown 取证报告 | `--max-events N` |

## 实测

对一份 31.4MB / 138162 包的入侵样本，`summary` 耗时 **2.9 秒**，输出：

```
攻击链签名命中
  [命中] SQL 注入       1300 次  首现 16:39:21  <union all select>
  [命中] 文件写入/拖库        20 次  首现 16:42:07  <into outfile>
  [命中] 后台登录接口       7567 次  首现 16:33:45  <login.jsp>
  [命中] 文件上传            4 次  首现 16:47:04  <multipart/form-data>
  [命中] 木马文件上传          2 次  首现 16:47:27  <.php">
  [命中] WebShell 控制    16 次  首现 16:48:07  <?php eval($_post>
  [推断] 目录扫描       1 个 UA 的 404 占比 ≥60%（UA 已伪装，签名不命中还要看行为）
```

`export` 把上传的木马单独落成文件，内容是典型的 `GIF89a` 头 + 一句话：

```
GIF89a
<?php phpinfo(); ?>
```

## 设计取舍

- **为什么不用 scapy / dpkt**：它们要么需要安装，要么对畸形包容错差。取证现场经常是离线沙箱，
  「能跑起来」比「功能全」重要。
- **为什么重点做了 URL 解码匹配**：真实攻击里 payload 几乎 100% 被编码，
  直接搜 `INTO OUTFILE` 会命中 0，这是最容易被误判成「没有攻击」的坑。
- **为什么用 404 率而不是 UA 判扫描**：UA 可以随便改，行为不会。
- **为什么不追求支持所有协议**：聚焦 HTTP 入侵链（扫描→注入→上传→WebShell→外联），
  这也覆盖了绝大多数 Web 类应急场景。DNS 隧道、TLS JA3 等留给 tshark 专项。

## 已知边界

- 不做 TLS 解密（有 keylog 文件才能解，本工具不处理）。
- 单文件 > 500MB 建议改用 `tshark --export-objects`，纯 Python 遍历会慢。
- `stream` 编号是本工具按首次出现顺序分配的，与 tshark 的 `tcp.stream` 不一定一致，
  写报告时注明来源即可。
- 只处理 HTTP/1.x；HTTP/2 需 h2 解码。

## 目录结构

```
SKILL.md                        # 技能主流程与硬规则
scripts/pcapkit.py              # 零依赖分析工具（单文件）
references/wireshark-filters.md # Wireshark / tshark 过滤器速查
references/report-template.md   # 取证报告模板
```

## License

MIT
