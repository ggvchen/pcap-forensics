# Wireshark / tshark 过滤器速查（按攻击链分组）

## 一、开局四件事（GUI）

| 目的 | 路径 |
|---|---|
| 文件信息、时间范围 | 统计 → 捕获文件属性 |
| 协议构成 | 统计 → 协议分级 |
| 谁和谁在通信 | 统计 → 会话 → IPv4（按字节排序） |
| 请求全貌 | 统计 → HTTP → 请求（按 URI 频次） |
| 时间格式 | 视图 → 时间显示格式 → UTC 日期和时间 / 自捕获开始秒数 |
| 关掉校验和红黑 | 编辑 → 首选项 → Protocols → TCP → 取消 Validate the TCP checksum |

## 二、显示过滤器（可直接粘贴）

```text
# 只看这一对主机之间的 HTTP
ip.addr==10.0.0.5 && ip.addr==10.0.0.9 && http

# 请求 / 响应
http.request
http.response

# 扫描器 UA
http.user_agent contains "Nikto" || http.user_agent contains "dirb" || http.user_agent contains "sqlmap"

# 扫描行为（不看 UA，看结果）
http.response.code == 404

# 注入
http.request.uri contains "union"
http contains "information_schema"
http contains "extractvalue("
http contains "sleep("

# 写文件 / 拖库
http contains "INTO OUTFILE"
http contains "INTO DUMPFILE"

# 上传
http.request.method == "POST" && http.content_type contains "multipart/form-data"
http.request.uri contains "upload"

# WebShell 工具
http.user_agent contains "antSword"
http.user_agent contains "Behinder" || http.user_agent contains "Godzilla"

# 认证与会话
http.cookie
http.request.uri contains "login" && http.request.method == "POST"

# 外联 / 反弹
ip.addr == 120.79.139.46
tcp.flags.syn == 1 && tcp.flags.ack == 0        # 谁在主动连出去
tcp.port == 8864
```

保存为按钮：过滤器栏右侧「+」→ 命名 → 之后一键切换，比每次手打快得多。

## 三、跟随流与导出

| 需求 | 操作 |
|---|---|
| 看一次完整请求响应 | 右键包 → 跟随 → HTTP 流 |
| 看裸 TCP（非 HTTP、反弹 shell） | 右键包 → 跟随 → TCP 流，显示数据切 ASCII |
| 导出下载的文件 / 页面 | 文件 → 导出对象 → HTTP |
| 导出**上传**的文件 | **导出对象拿不到请求体**：跟随 HTTP 流 → 显示数据切「原始数据」→ 全选 → 另存 |
| 只看某条流的所有包 | `tcp.stream eq 12` |

## 四、tshark 一条命令干一件事

```bash
# 会话排行（谁在传大文件）
tshark -r a.pcap -q -z conv,ip | sort -k4 -n -r | head -20

# 全部请求导出 CSV（时间/源/方法/URI/UA）
tshark -r a.pcap -Y "http.request" -T fields -e frame.time -e ip.src \
  -e http.request.method -e http.request.uri -e http.user_agent -E separator=, > req.csv

# 关键字命中（区分大小写敏感与否）
tshark -r a.pcap -Y 'http contains "union"' -T fields -e frame.number -e http.request.uri

# 状态码分布
tshark -r a.pcap -Y "http.response" -T fields -e http.response.code | sort | uniq -c | sort -rn

# 导出所有 HTTP 对象到目录
tshark -r a.pcap --export-objects http,./objects

# 提取所有 POST 请求体（上传的木马在这里）
tshark -r a.pcap -Y 'http.request.method=="POST"' -T fields -e frame.number -e http.file_data

# 还原某条 TCP 流的 ASCII / 原始字节
tshark -r a.pcap -q -z follow,tcp,ascii,12
tshark -r a.pcap -q -z follow,tcp,raw,12

# 提取 TLS SNI（加密流量也能看访问了哪个域名）
tshark -r a.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

## 五、坑

- **payload 被 URL 编码**：`http contains "INTO OUTFILE"` 对 `INTO%20OUTFILE` 不命中。
  先 `http.request.uri contains "OUTFILE"`，或直接对解码后的文本搜。
- **gzip 响应看不懂**：首选 HTTP → 勾 Uncompress entity bodies；仍乱码说明流被截断，
  需要改用「跟随流」看原始字节自己解。
- **一条流里有多个请求**（keep-alive）：跟随流会看到串在一起的多个报文，
  按 `\r\n\r\n` 分段读。
- **大文件打开慢**：先 `editcap -A "16:30:00" -B "16:40:00" in.pcap out.pcap` 切片再分析。
- **checksum 报红**：抓包点做 offload 的常见现象，不代表包损坏。
