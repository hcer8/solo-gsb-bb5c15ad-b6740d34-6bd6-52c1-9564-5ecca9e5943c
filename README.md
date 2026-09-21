# JSON Redaction API

基于 **Python + FastAPI** 的 JSON 结构脱敏服务。接收任意 JSON 文档与一组规则，
按 [JSON Pointer (RFC 6901)](https://www.rfc-editor.org/rfc/rfc6901) 路径定位节点，
支持 `*` / `**` 通配，执行 `mask`、`remove`、`sha256` 三种动作，并返回完整审计轨迹。

## 一键启动（8080 端口）

```bash
docker compose up --build
```

服务在 <http://localhost:8080> 就绪：

- `POST /redact` — 脱敏接口
- `GET  /health` — 健康检查
- `GET  /docs`   — Swagger UI（可直接在线试用）

不想用 Docker 时：

```bash
pip install -r requirements.txt
REDACT_SALT=change-me uvicorn app.main:app --host 0.0.0.0 --port 8080
```

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

### 盐值配置

盐通过环境变量 `REDACT_SALT` 注入，默认空字符串。Docker 部署时可在 Shell 或 `.env`
文件中设置：

```bash
echo 'REDACT_SALT=your-strong-secret' > .env
docker compose up --build -d
```

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

## 请求 / 响应

请求体：

```json
{
  "data": { "任意": "JSON" },
  "rules": [
    { "pointer": "/users/*/password", "action": "remove", "name": "可选名称" },
    { "pointer": "/users/*/email", "action": "mask" },
    { "pointer": "/**/ssn", "action": "sha256" }
  ]
}
```

- `data`：任意合法 JSON（对象、数组、标量、null 均可）；
- `rules`：按声明顺序排列；`pointer` 为 JSON Pointer，`action` 为三种动作之一，
  `name` 可选并会原样出现在审计轨迹中；
- 非法 pointer 或 action 返回 `422`。

响应体：

```json
{
  "redacted": { "...": "脱敏后的文档" },
  "audit": [
    {
      "pointer": "/users/0/email",
      "action": "mask",
      "rule": { "index": 1, "pointer": "/users/*/email", "action": "mask" }
    }
  ]
}
```

- `redacted`：脱敏结果（输入文档不会被修改）；
- `audit`：每个实际生效的动作一条记录，按原始文档深度优先顺序排列；
  - `pointer`：被处理节点在**原始文档**上的 JSON Pointer；
  - `action`：实际执行的动作；
  - `rule`：命中的规则，含声明下标 `index`、规则 `pointer`、`action` 及可选 `name`。

## 示例

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

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 应用与 POST /redact
│   ├── redaction.py   # 核心引擎：pointer 解析、通配匹配、冲突裁决、动作执行
│   ├── schemas.py     # 请求/响应 Pydantic 模型
│   └── config.py      # REDACT_SALT 环境变量
├── tests/
│   ├── test_engine.py # 引擎单元测试（通配、优先级、数组稳定性、根节点等）
│   └── test_api.py    # HTTP 层集成测试
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 安全说明

- 盐只影响 `sha256` 动作，mask 标记固定可见；不要把哈希当作加密，它无法还原但可被字典猜测。
- 服务本身不做鉴权/限流，生产环境请置于网关之后并妥善保管盐值（不要提交 `.env`）。
