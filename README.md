# access-sum

零依赖 Python CLI：汇总 HTTP 访问日志。支持 Apache Combined / Common、Nginx 带耗时的自定义格式，以及一行一条的 JSON。看状态码分布、热点路径、最慢请求、流量时段，都在本机完成，不上传任何文件。

## 做什么

线上出了 5xx，或只是想知道「哪个接口最慢、谁在打」，access log 往往又长又杂：IP、时间、URL、状态码、字节数、UA 挤在一行。`access-sum` 在本机解析日志，压成一页摘要。

它会：

- 读取 Combined、Common（无 Referer / User-Agent），以及 Combined 后面附加的 `$request_time` / `$upstream_response_time`
- 读取 JSON / JSONL（常见字段名：`time_local` / `timestamp`、`remote_addr` / `client_ip`、`request` 或 `method`+`path`、`status`、`body_bytes_sent`、`request_time` 或 `duration_ms`、`http_user_agent`）
- 统计请求数、流量、状态码、方法；有耗时字段时给出 avg / p50 / p95 / p99 和最慢请求
- 默认去掉 query string，避免把 token、session 打进汇总；`--normalize` 会把数字、UUID、长十六进制路径段收成 `:id`
- 按 User-Agent 关键词粗分爬虫 / 脚本客户端（Googlebot、curl、python-requests 等）
- 支持 `--since` / `--until`、`--status 5xx,404`、`--method GET,POST`、`--tz Asia/Shanghai`
- `--json` 便于脚本处理；`--strict` 在有无法解析的行或文件读失败时以状态码 1 退出
- 支持多文件和 stdin（`-` 或管道）

## 要求

- Python 3.8+
- 仅标准库（`argparse` / `json` / `datetime` / `re` 等；`--tz` 使用 IANA 时区时需要 `zoneinfo`，Python 3.9+ 自带）

## 用法

```bash
# 查看仓库里的示例日志（虚构的 shop.example.com 和文档保留地址）
python3 access_sum.py examples/nginx-timed.log --tz Asia/Shanghai --normalize

# 多文件一起汇总
python3 access_sum.py /var/log/nginx/access.log examples/combined.log --tz +0800

# 只看 4xx / 5xx，并把 /users/17 收成 /users/:id
python3 access_sum.py access.log --status 4xx,5xx --normalize

# 时间窗口（ISO、Apache 时间或 epoch 都可以）
python3 access_sum.py access.log --since 2026-11-23T10:00:00+08:00 --until 2026-11-23T11:00:00+08:00

# 管道 / stdin
tail -n 5000 access.log | python3 access_sum.py --tz Asia/Shanghai
python3 access_sum.py - < examples/jsonl.log

# 机器可读 JSON
python3 access_sum.py examples/combined.log --json --tz +0800
```

`examples/` 里是虚构的演示日志（域名 `shop.example.com`，客户端用 RFC 5737 / RFC 3849 文档保留地址，没有真实用户或业务数据）。访问日志可能含 IP 和查询参数，请只在本机处理自己的日志；本工具默认不把 query string 打进路径汇总，需要时再加 `--keep-query`。

## 示例

`python3 access_sum.py examples/nginx-timed.log --tz Asia/Shanghai --normalize --top 5`：

```
Source:     examples/nginx-timed.log
Lines:      parsed 10   skipped 0
Range:      2026-11-23 10:00:01 +0800  →  2026-11-23 10:07:00 +0800  (6m 59.0s)
Requests:   10
Bytes:      16.7 KB
Time:       avg 572ms   p50 91ms   p95 3.012s   p99 3.012s
Bots:       2  (20.0% of requests, by User-Agent keyword)

Status
  200       7  ███████████        70.0%
  201       1  ██                 10.0%
  404       1  ██                 10.0%
  502       1  ██                 10.0%

Methods
  GET         9
  POST        1

Top paths
    hits      bytes    avg  path
        3     1.97 KB  1.074s  /api/items/:id
        2     12.0 KB   198ms  /api/items
        1     2.00 KB    28ms  /
        1       512 B   220ms  /api/orders/:id
        1       144 B  1.842s  /api/orders

Slowest
   3.012s  502  GET   /api/items/:id  203.0.113.24
   1.842s  201  POST  /api/orders  203.0.113.22
    355ms  200  GET   /api/items  203.0.113.21
    220ms  200  GET   /api/orders/:id  203.0.113.23
    118ms  200  GET   /api/items/:id  203.0.113.21

4xx / 5xx paths
        1  /api/items/:id  (1×502)
        1  /api/missing  (1×404)

Top clients
        3  203.0.113.21
        2  203.0.113.22
        2  203.0.113.24
        1  203.0.113.23
        1  198.51.100.8

Top User-Agents
        3  Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/2010010...
        3  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, ...
        2  Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/60...
        1  curl/8.7.1  [bot]
        1  Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)  [bot]

Top referers
        5  https://shop.example.com/catalog
        1  https://shop.example.com/checkout
        1  https://shop.example.com/orders
        1  https://shop.example.com/

Traffic
  10:00               7  ████████████████████████
  10:05               3  ██████████
```

## 限制

- 只认常见的 Combined / Common、其后附加的耗时字段，以及常见键名的 JSON 行；不解析 ELB / CloudFront / IIS 的专用格式
- 没有耗时字段时不会编造延迟，只统计次数和字节
- User-Agent 的 bot 标记只是关键词匹配，不是完整的爬虫库
- 百分位用 nearest-rank，样本很少时 p95 / p99 可能落到最大值
- 单文件超过 100 MB 会跳过；大日志请先 `tail` / 按时间切一段再送进来
- 无时间戳的行在 `--since` / `--until` 下会被丢掉

## 后续可改进

- 对比两段日志，标出新增的 5xx 路径和突然变慢的接口
- 识别更多 Nginx / Envoy / Caddy 自定义 `log_format`
- 按上游、主机名或 `X-Forwarded-For` 分组（默认脱敏）

## 许可

MIT。见 [LICENSE](LICENSE)。
