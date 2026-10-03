# KeyPool — API Key 轮换池平台

一个**零依赖、单文件部署**的本地 API Key 池网关：把多个平台的多个 API Key 统一管理，Agent / 客户端只对接 KeyPool 一个地址，后端自动在密钥间轮换；某个 Key 触发 **429 限流 / 5xx / 超时 / 401 / 欠费** 时自动切换下一个可用 Key，并按策略冷却熔断。

> 设计参考了 one-api / new-api / gpt-load / uni-api 等项目的渠道池 + 故障转移思路，用 Node.js ≥ 18 原生能力实现，无需 npm install。

## 功能特性

| 能力 | 说明 |
|---|---|
| 多平台渠道 | 自定义 Base URL，支持 OpenAI 兼容 / Anthropic / Google Gemini / Azure OpenAI 四类协议 |
| 多密钥管理 | 单个或批量导入（每行一个），支持 `key|备注|优先级` 格式；打码显示、点击复制 |
| 自动轮换 | 轮询（最久未用优先）或 优先级 两种策略；请求内自动 failover |
| 故障熔断 | 429 指数退避冷却；5xx/超时/网络错误短冷却；401/403 自动禁用；欠费类长冷却（关键词可配） |
| 全池保护 | 所有 Key 冷却中时返回 `429 + Retry-After`，避免客户端风暴重试 |
| 流式透传 | SSE（`data:` 分块）完整透传，含跨帧 usage 统计捕获、空闲超时、客户端断连中止上游 |
| 网关鉴权 | 全局密钥（访问所有渠道）+ **渠道专属 Key**（只访问绑定的渠道），支持 Bearer / x-api-key |
| 渠道专属 Key | 每个渠道可自动生成（`kp-渠道名-xxxx`）或手动指定专属 Key，填进 Agent 后请求只路由到该渠道；独立启停/重新生成/删除，按 Key 统计请求 |
| Web 管理后台 | 渠道/密钥 CRUD、实时状态（可用/冷却/禁用）、请求与 Token 统计、连通性测试、运行日志 |
| 模型列表聚合 | `/v1/models` 跨密钥并发拉取并去重合并（模型授权按 Key 下发时列表依然稳定完整），30s 缓存 |
| 渠道模型池 | 每个渠道持久化一份上游模型快照：**加 Key / 连通性测试 / 改 Base URL 时自动拉取**，后台可手动刷新；网关据此**按模型路由**（A 平台的模型不会发给 B 平台的 Key），上游模型接口挂掉时用池子兜底 |
| 对话模型过滤 | 池子里带上游 `mode` 元数据，网关默认只对外暴露可对话模型（过滤 TTS/ASR/图像等），`/v1/models?all=1` 或渠道设置可关闭过滤 |
| 双协议接入 | OpenAI 型渠道可勾选「同时接受 Anthropic 协议」，同一把 `kp-` Key 既能给 OpenAI 客户端用，也能给 Claude 类客户端用（要求上游本身暴露 `/v1/messages`） |
| 路径宽容 | 客户端把 Base URL 填成 `https://host`（漏掉 `/v1`）时，`/models`、`/chat/completions` 等自动补齐，不再报"获取不到模型" |
| 持久化 | 状态落盘 `data/state.json`，重启不丢配置 |

## 快速开始

```bash
# 需要 Node.js >= 18（零依赖，无需 npm install）
node server.js                 # 默认 127.0.0.1:8787
node server.js --port 9000     # 自定义端口
node server.js --host 0.0.0.0  # 允许局域网访问
```

1. 打开管理后台 `http://127.0.0.1:8787/admin`，首次进入设置管理密码；
2. 「渠道与密钥」→ 添加渠道：
   - 名称：`tierflow`
   - 类型：`OpenAI 兼容`
   - Base URL：`https://tierflow.cn/v1`（填域名或带 `/v1` 均可，自动适配）
   - API Keys：粘贴多个 Key（每行一个，可 `sk-xxx|账号A|10` 带备注和优先级）；
3. Agent 的 API 地址改为 `http://127.0.0.1:8787/v1` 即可。

Windows 可直接双击 `start.bat`。

## Agent 接入示例

```python
# OpenAI SDK
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="任意（或在后台设置了网关密钥则填它）")
r = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
```

```bash
# curl（OpenAI 协议）
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer 网关密钥" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'

# Anthropic 协议（派发给 Anthropic 型渠道，或勾选了「同时接受 Anthropic 协议」的 OpenAI 兼容渠道）
curl http://127.0.0.1:8787/v1/messages \
  -H "x-api-key: 网关密钥" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
```

支持的网关路径：`/v1/chat/completions`、`/v1/completions`、`/v1/responses`、`/v1/embeddings`、`/v1/moderations`、`/v1/models`、`/v1/images/*`、`/v1/audio/*`、`/v1/rerank`、`/v1/messages`（Anthropic）、`/v1beta/*`（Gemini 原生）。

> **`/v1` 前缀可省略**：客户端 Base URL 填成 `https://host` 时，`/models`、`/chat/completions`、`/messages` 等会按 `/v1/…` 处理。
>
> **OpenAI 兼容渠道走 Anthropic 协议**：编辑渠道勾选「同时接受 Anthropic 协议」后，`/v1/messages` 会转发到该渠道的 `/v1/messages`，并同时带上 `Authorization: Bearer` 与 `x-api-key`（兼容两种上游约定）。未勾选时返回 `400 protocol_mismatch` 并给出开启提示。

响应头会标记本次实际使用的渠道与密钥（打码）：`x-keypool-target`、`x-keypool-key`。

## 轮换与熔断策略（可在后台「设置」调整）

| 错误类型 | 动作 | 默认 |
|---|---|---|
| `429` 限流 | 指数退避冷却（8s → 16s → 32s …，上限 30 分钟），遵循上游 `Retry-After` | 基数 8s |
| `5xx` 服务器错误 | 短冷却后自动恢复 | 5s |
| 超时 / 网络错误 | 短冷却 | 3s |
| `401 / 403` | 判定 Key 无效，**自动禁用**（后台手动启用恢复） | — |
| `402` / 关键词命中（credit、balance、quota、欠费…） | 判定欠费，长冷却 | 60 分钟 |
| `4xx` + 模型不可用关键词（invalid model / 模型不存在…） | 判定该 Key 不支持**该模型**：轮换下一个 Key，并在 60s 内让该模型的请求跳过此密钥；密钥本身不冷却不禁用，其他模型照常使用 | 60s |

单请求默认最多尝试 6 个 Key（`maxAttempts` 可调）；全部失败返回 `502 all_keys_failed`，全部在冷却中返回 `429 all_keys_cooling + Retry-After`；若全池均因**模型不支持**失败，返回 `400 model_not_supported`（这是请求问题，不是密钥故障）。

> ⚠️ **请求体必须是合法 JSON**：两个上游对非法 JSON body 的报错极具误导性——tierflow 回 `invalid model field`，SenseAudio 回 `参数错误：body` / `Syntax error at index N`，看起来都像"模型不存在"。网关在 body 解析失败时会跳过模型池路由（日志里模型名显示「?」）并原样转发，由上游给出报错。排查时先确认客户端发的真是合法 JSON（常见坑：shell 里手工转义引号）。

**模型池路由**：请求带模型名且 body 可解析时，只在「模型池包含该模型」的渠道内轮换，省掉必然失败的往返；若所有渠道池子里都没有该模型（池子过期/新模型），保持全量轮换，由上游给权威答复。

**并发调度**：同一 Key 并发达到 `maxConcurrentPerKey`（0=不限）时优先分配到其他 Key；空闲 Key 按「最久未使用」优先，天然把并发请求分散到不同密钥，减少撞 429 的概率。`inFlight` 在流式响应期间全程占用，准确反映实时并发。

## API（管理后台）

登录：`POST /admin/login {"password":"..."}` → `{"token":"..."}`，后续请求带 `x-admin-token` 头。

- `GET  /admin/api/overview` — 总览统计
- `GET|POST /admin/api/targets`、`PUT|DELETE /admin/api/targets/:id` — 渠道管理
- `POST /admin/api/targets/:id/keys` — 批量导入密钥；`PATCH|DELETE /admin/api/targets/:id/keys/:keyId`
- `POST /admin/api/targets/:id/gateway-keys` — 生成渠道专属 Key（`{key?, note?}`，留空自动生成）
- `PATCH /admin/api/targets/:id/gateway-keys/:keyId` — 启停 / 改备注 / 重新生成（`{regenerate:true}`）/ 重置统计
- `DELETE /admin/api/targets/:id/gateway-keys/:keyId` — 删除专属 Key
- `POST /admin/api/password` — 修改管理密码 `{oldPassword, newPassword}`（成功返回新 token，旧会话失效）
- `POST /admin/api/targets/:id/test` — 连通性测试（全部或指定 Key；**同时刷新该渠道模型池**，响应里带回 `models`）
- `GET  /admin/api/targets/:id/models` — 渠道模型池快照（`models` / `updatedAt` / `note` / `chatOnly`）
- `POST /admin/api/targets/:id/models/refresh` — 强制重新拉取上游模型并落盘
- `GET  /admin/api/keystates` — 每个 Key 的实时状态与统计
- `GET|PUT /admin/api/settings` — 轮换策略 / 全局网关密钥
- `GET  /admin/api/logs` — 运行日志
- `GET  /health` — 健康检查

### 渠道专属 Key 语义

- 用专属 Key 调用：请求**只路由到绑定渠道**（含 `/v1/models`），看不到其他渠道；绑定渠道禁用时返回 `403 target_disabled`，渠道没配上游密钥时返回 `503 no_upstream_keys`
- 专属 Key 的协议受渠道类型约束：OpenAI 型渠道默认只接 OpenAI/Gemini 协议，勾选「同时接受 Anthropic 协议」后也可用于 Claude 类客户端（`/v1/messages`）
- 只要存在任何网关密钥（全局或专属），网关即关闭匿名访问；两者都未配置时保持开放（向后兼容）

## 目录结构

```
key-pool/
├── server.js        # 全部服务端逻辑（网关 + 管理 API + 轮换引擎）
├── public/
│   └── index.html   # Web 管理后台（单文件，无构建）
├── test/
│   └── run.js       # 自动化测试（Mock 上游，32 项断言）
├── data/            # 运行时生成：state.json
├── start.bat        # Windows 一键启动
└── package.json
```

## 测试

```bash
node test/run.js
# 85 通过，0 失败（覆盖：轮换、429 指数退避、401 自动禁用、402 欠费冷却、
# 5xx 短冷却、全池熔断、SSE 流式透传与 usage 统计、网关鉴权、Anthropic 协议、
# 模型权限轮换、/v1/models 聚合、渠道模型池（自动拉取/对话过滤/按池路由/上游失败兜底）、
# 专属 Key 隔离、/v1 前缀别名、acceptAnthropic 透传、探测）
```

## 接入 DSH（DeepSeek Harness）

DSH 的 LLM provider 编辑器会对手写路由发 `GET {baseURL}/models`（Bearer）做模型发现，
发现的正是 KeyPool 的模型池；但**手声明路由必须带非空 `models` 列表**才能保存，
所以推荐直接用渠道「复制接入配置」按钮生成片段。

1. **TLS 无需任何配置**：KeyPool 已使用 Let's Encrypt 正式证书，DSH 内置 Node 用系统信任链即可直连。
   （历史遗留：若你曾为自签证书设置过 `NODE_EXTRA_CA_CERTS`，现在可以删掉——
   `[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS',$null,'User')`，然后重启 DSH。）
2. 把 KeyPool 的全局网关密钥写进凭据库 `~/.dsh/.credentials.yaml`（与 `QS_API_KEY` 同一位置）：
   ```yaml
   refs:
     KEYPOOL_API_KEY: kp-xxxxxxxxxxxxxxxx
   ```
3. 在 profile patch（`~/.dsh/profiles/desktop/cordis.patch.yml`）里加一个 provider，模型列表取自模型池：
   ```yaml
   - id: llm-pi-ai
     name: "@deepseek-ai/dsh-llm-pi-ai"
     config:
       providers:
         keypool:
           displayName: KeyPool 轮换池
           apiKeyEnv: KEYPOOL_API_KEY
           api: openai-completions
           baseURL: https://yy.720820.xyz/v1
           models:
             - id: tierflow_pro
               name: tierflow_pro
             - id: senseaudio-s2
               name: senseaudio-s2
   ```
   之后在 DSH 设置里把默认模型切到 `keypool/<model>` 即可；KeyPool 会按模型池把请求路由到对应渠道并在密钥间自动轮换。

## 安全提示

- 默认只监听 `127.0.0.1`；如需局域网访问用 `--host 0.0.0.0` 并务必设置网关密钥。
- 管理密码哈希存储；上游 Key 明文存于 `data/state.json`，请保护好该文件。

## 服务器部署（yy.720820.xyz，直连 HTTPS）

已部署到 `yy.720820.xyz`（Debian 11，IP `155.103.158.76`，域名直接解析到本机，无 frp）：

- **访问地址**：`https://yy.720820.xyz`（KeyPool 原生 TLS 443，**Let's Encrypt 正式证书**，公网受信：浏览器 / curl / Node / .NET 全部零配置直连，无需 `-k` 或导入 CA）；`http://yy.720820.xyz` 自动 301 跳转 HTTPS（ACME 校验路径除外）
- **部署目录**：`/usr/local/keypool`，Node 运行时 `/usr/local/node`（v20.18.1），数据 `/usr/local/keypool/data/state.json`
- **端口**：443 = HTTPS（对外，`--host 0.0.0.0`）；80 = HTTP 跳转 + ACME HTTP-01 校验（对外）；8787 = 明文 HTTP（仅本机 `--http-host 127.0.0.1`，管理/运维用）
- **服务**：`systemctl status keypool`（开机自启），`/etc/systemd/system/keypool.service`
- **更新程序**：覆盖 `server.js` / `public/index.html` 后 `systemctl restart keypool`
- **证书与自动续签**：`acme.sh`（`/root/.acme.sh`，LE CA，RSA-2048，90 天）+ crontab 每天 5/11/17/23 点检查续签
  - 首次签发 / 手动续签：`/root/.acme.sh/acme.sh --issue -d yy.720820.xyz -w /etc/keypool/acme --server letsencrypt --keylength 2048`
  - 安装到服务路径：`/root/.acme.sh/acme.sh --install-cert -d yy.720820.xyz --key-file /etc/keypool/certs/yy.720820.xyz.key --fullchain-file /etc/keypool/certs/yy.720820.xyz.crt --reloadcmd "echo renewed"`
  - KeyPool 每 60s 检查证书文件 mtime，变化即 `setSecureContext` **热加载**，续签全程不重启、不断流
  - 80 端口对 `/.well-known/acme-challenge/*` 从 `--acme-webroot`（默认 `/etc/keypool/acme`）直出文件、不做 301，因此可在服务运行期间完成 HTTP-01 校验
  - 旧的自签证书备份在 `/etc/keypool/certs/selfsigned-backup.crt/.key`（已不再使用，可随时删除）
- **备份**：重装前的历史配置存于 `/root/keypool-state-backup.json`

本地运维脚本见 `deploy/`（`ssh_run.py` 远程执行、`ssh_put.py` 上传、`setup_server.sh` / `setup_https.sh` 初始化脚本）。
