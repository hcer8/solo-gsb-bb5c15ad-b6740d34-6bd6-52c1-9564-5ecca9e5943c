# JSON Redaction API

基于 **Python + FastAPI** 的 JSON 结构脱敏服务。接收任意 JSON 文档与一组规则，
按 [JSON Pointer (RFC 6901)](https://www.rfc-editor.org/rfc/rfc6901) 路径定位节点，
支持 `*` / `**` 通配，执行 `mask`、`remove`、`sha256` 三种动作，并返回完整审计轨迹。

规则既可在请求中**内联**给出，也可作为**带版本的持久化策略（policy）**统一管理：
每次更新都会生成一条不可变、单调递增的版本快照，历史版本可随时精确复现。

## 一键启动（8080 端口）

```bash
docker compose up --build
```

服务在 <http://localhost:8080> 就绪：

- `POST /redact` — 脱敏接口（内联规则或引用策略，二选一）
- `PUT  /policies/{name}` — 创建 / 更新策略（ETag 乐观并发）
- `GET  /policies/{name}/versions/{version}` — 查询不可变版本快照
- `GET  /health` — 健康检查
- `GET  /docs`   — Swagger UI（可直接在线试用）

不想用 Docker 时：

```bash
pip install -r requirements.txt
REDACT_SALT=change-me uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `REDACT_SALT` | `""` | `sha256` 动作加盐使用的盐，生产环境务必设置非空值 |
| `POLICY_DB` | 容器内 `/data/policies.db`；本地开发 `data/policies.db` | SQLite 数据库文件路径 |

Docker 部署时可在 Shell 或 `.env` 文件中覆盖：

```bash
cat > .env <<'EOF'
REDACT_SALT=your-strong-secret
EOF
docker compose up --build -d
```

### 数据持久化

`docker compose` 会创建并挂载名为 `policy-data` 的 Docker volume 到容器 `/data`，
策略库（SQLite，含 WAL 辅助文件）全部写入该 volume。容器重建、升级或重启后，
所有策略及其历史版本都不会丢失：

```bash
docker compose down          # 只停容器，volume 保留
docker volume ls | grep policy-data
docker compose down -v       # 如需彻底删除策略数据
```

SQLite 以 **WAL 模式**运行：读不阻塞写，写之间通过 `BEGIN IMMEDIATE` 串行化；
更新采用 ETag 乐观锁，并发更新同一版本时只有一个成功，其余收到 `412`，
可凭响应中回传的最新 ETag 重试。

## 策略库 API

### 创建策略（首次）

首次 `PUT` **不要**携带 `If-Match`；成功返回 `201`，并在 `ETag` 响应头给出当前版本标识：

```bash
curl -si -X PUT http://localhost:8080/policies/pii \
  -H 'Content-Type: application/json' \
  -d '{"rules":[
    {"pointer":"/users/*/email","action":"mask"},
    {"pointer":"/**/ssn","action":"sha256","name":"ssn"}
  ]}'
# HTTP/1.1 201 Created
# ETag: "9f2a..."
# {"name":"pii","version":1,"etag":"9f2a...","created_at":"...","rules":[...]}
```

策略名只允许 `[A-Za-z0-9_.-]` 且以字母或数字开头（1–128 字符），可直接放进 URL。

### 更新策略（后续必须携带当前 ETag）

对已存在的策略再次 `PUT` 时，必须用 `If-Match` 携带**当前** ETag；成功后版本号
不可变递增（1 → 2 → …），并返回新的 ETag。旧版本永不修改、永不删除：

```bash
curl -si -X PUT http://localhost:8080/policies/pii \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "9f2a..."' \
  -d '{"rules":[{"pointer":"/users/*/email","action":"remove"}]}'
# 200 OK，ETag 变为新版本
```

并发与冲突行为：

| 场景 | 结果 |
| --- | --- |
| 首次创建（无 `If-Match`） | `201`，版本 1 |
| 对已存在策略再次无 `If-Match` | `412 Precondition Failed` |
| `If-Match` 为当前 ETag | `200`，生成下一不可变版本 |
| `If-Match` 为过期/伪造 ETag | `412`，响应头回带当前 `ETag` |
| `If-Match: *` 对已存在策略 | 无条件更新到下一版本 |
| `If-Match: *` 对不存在的策略 | `412`（不能用 `*` 创建） |
| 多个客户端用同一旧 ETag 并发更新 | 恰好一个成功，其余 `412`（无丢更新） |

### 查询版本快照

```bash
curl -s http://localhost:8080/policies/pii/versions/1
curl -s http://localhost:8080/policies/pii/versions/2
```

返回该版本**创建时的完整规则快照**与创建时间，`ETag` 头即该版本的永久标识。
策略名或版本号不存在返回 `404`。

## /redact：内联规则与策略引用二选一

请求体在 `rules`（内联）与 `policy`（引用）之间**必须且只能**提供一个：

```json
{
  "data": { "任意": "JSON" },
  "policy": { "name": "pii", "version": 2 }
}
```

- `policy.version` **省略**时：在请求处理时**原子读取**最新版本
  （SQLite 单事务内完成“取当前版本号 + 取版本行”，与并发 `PUT` 互不交错）；
- `policy.version` **指定**时：精确应用该历史版本，即使策略后来又更新也不受影响；
- 策略不存在或版本不存在返回 `404`；
- 同时提供 `rules` 与 `policy` 返回 `422`。

响应与每条审计记录都会标明**实际生效的策略名与版本**：

```json
{
  "redacted": { "...": "脱敏后的文档" },
  "audit": [
    {
      "pointer": "/users/0/email",
      "action": "mask",
      "rule": { "index": 0, "pointer": "/users/*/email", "action": "mask" },
      "policy": { "name": "pii", "version": 2, "latest": false }
    }
  ],
  "policy": { "name": "pii", "version": 2, "latest": false }
}
```

- `latest: true` 表示请求未指定版本、本次原子读到的是当时最新版本（其版本号已固定在响应中）；
- `latest: false` 表示请求显式钉住了某个历史版本；
- 内联规则请求没有 `policy` 字段（响应顶层与审计项中均为 `null`）。

历史版本始终可复现：保存一次响应中的 `name` + `version`，日后用
`{"policy":{"name":...,"version":...}}` 重放同一文档，结果完全一致。

## 规则路径（JSON Pointer + 通配）

| 写法 | 含义 |
| --- | --- |
| `/users/0/email` | 字面路径；`~1` 表示 `/`，`~0` 表示 `~`（RFC 6901 转义） |
| `""`（空字符串） | 整个文档根节点 |
| `/users/*/email` | `*` 匹配**恰好一个**段（任意 key 或数组下标） |
| `/**/ssn` | `**` 匹配**零个或多个**段，可位于任意深度（含零宽，即 `/ssn` 也命中） |
| `/drop/**` | 命中 `/drop` 子树内所有节点（含 `/drop` 自身） |

数组下标即对应段，例如 `/items/2`。带 `/`、`~` 的 key 按 RFC 6901 转义书写。

## 动作

| 动作 | 效果 |
| --- | --- |
| `mask` | 将节点整体替换为固定字符串 `"***REDACTED***"` |
| `remove` | 删除对象键或数组元素；命中根节点时结果为 `null` |
| `sha256` | 将节点替换为加盐哈希字符串。哈希输入为 `SHA256(REDACT_SALT + canonical_json(node))`，其中 canonical JSON 对 key 排序、无多余空白（`sort_keys=True, separators=(",",":")`），故哈希结果与 key 书写顺序无关 |

相同输入 + 相同盐才会得到相同摘要；**请在生产环境务必设置非空盐**。

## 多规则冲突的裁决

当多条规则同时命中同一节点时，按以下优先级选出**唯一**生效规则：

1. **字面段更多**者胜（精确路径优先于通配路径）；
2. 字面段相同时，**通配段更少**者胜（`/users/*/email` 胜过 `/**/*/email`）；
3. 仍相同时，**声明顺序更靠后**者胜（后写的覆盖先写的）。

所有匹配均基于**原始结构**一次性计算完成：先解析出每个原始节点的命中规则，
再统一执行。因此删除数组元素不会造成后续指针错位——例如同时配置
`/items/0` remove 与 `/items/*/x` mask，`/items/2/...` 始终指向原始第 3 个元素。

当一个节点被子树规则整体处理（mask/remove/sha256）时，其后代不会重复处理，
审计轨迹中只记录该子树的最近命中规则。

## 完整示例

```bash
# 1) 创建策略 v1
curl -si -X PUT http://localhost:8080/policies/pii \
  -H 'Content-Type: application/json' \
  -d '{"rules":[
    {"pointer":"/users/*/password","action":"remove"},
    {"pointer":"/users/*/email","action":"mask"},
    {"pointer":"/**/name","action":"sha256"}
  ]}'

# 2) 用最新版本脱敏（响应中记录实际版本）
curl -s -X POST http://localhost:8080/redact \
  -H 'Content-Type: application/json' \
  -d '{
    "data": {"users": [
      {"name": "alice", "email": "a@x.io", "password": "p1"},
      {"name": "bob",   "email": "b@x.io", "password": "p2"}
    ]},
    "policy": {"name": "pii"}
  }'

# 3) 更新策略（用第 1 步返回的 ETag）
curl -si -X PUT http://localhost:8080/policies/pii \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "<上一步的 ETag>"' \
  -d '{"rules":[{"pointer":"/users/*/email","action":"remove"}]}'

# 4) v1 仍然可以精确复现
curl -s -X POST http://localhost:8080/redact \
  -H 'Content-Type: application/json' \
  -d '{"data": {...}, "policy": {"name": "pii", "version": 1}}'
```

内联规则的老用法保持不变：

```bash
curl -s -X POST http://localhost:8080/redact \
  -H 'Content-Type: application/json' \
  -d '{
    "data": {"users": [
      {"name": "alice", "email": "a@x.io", "password": "p1"},
      {"name": "bob",   "email": "b@x.io", "password": "p2"}
    ]},
    "rules": [
      {"pointer": "/users/*/password", "action": "remove"},
      {"pointer": "/users/*/email", "action": "mask"},
      {"pointer": "/**/name", "action": "sha256"}
    ]
  }'
```

## 本地开发与测试

```bash
pip install -r requirements.txt pytest httpx
python -m pytest -q
```

测试会使用临时目录中的独立 SQLite 文件，不会污染本地 `data/policies.db`。

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 应用：/redact、/policies 路由、ETag 处理
│   ├── policies.py    # SQLite 持久化策略库：不可变版本、ETag 并发控制
│   ├── redaction.py   # 核心引擎：pointer 解析、通配匹配、冲突裁决、动作执行
│   ├── schemas.py     # 请求/响应 Pydantic 模型
│   └── config.py      # REDACT_SALT / POLICY_DB 环境变量
├── tests/
│   ├── test_engine.py    # 引擎单元测试（通配、优先级、数组稳定性、根节点等）
│   ├── test_api.py       # HTTP 层集成测试（内联规则）
│   └── test_policies.py  # 策略库测试：版本、ETag/412、并发、复现、持久化
├── Dockerfile
├── docker-compose.yml    # 8080 端口 + policy-data volume
└── requirements.txt
```

## 安全说明

- 盐只影响 `sha256` 动作，mask 标记固定可见；不要把哈希当作加密，它无法还原但可被字典猜测。
- 服务本身不做鉴权/限流，生产环境请置于网关之后并妥善保管盐值（不要提交 `.env`）。
- 策略库接口可改变脱敏行为，同样应置于受信网络 / 网关之后。
