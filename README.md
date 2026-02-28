# IP 质量检测 / IP Quality Check

基于 Cloudflare Workers 的 IP 质量检测工具，聚合多个权威数据库，提供全面的 IP 风险评估。

灵感来源于 [IPQuality (ip.sh)](https://github.com/xykt/IPQuality)。

## ✨ 功能

- **基础信息** — ASN、组织、地理位置、坐标、时区
- **IP 类型属性** — 使用类型 & 公司类型（来自 4 个数据库交叉比对）
- **风险评分** — 5 个数据库的欺诈/滥用评分可视化
- **风险因子矩阵** — 代理/Tor/VPN/服务器/滥用/机器人 × 6 个数据库

### 数据源

| 数据库 | 类型 | 提供数据 |
|--------|------|----------|
| **ipapi** | 基础信息 + 风险 | 地理位置、ASN、IP 类型、风险评分、风险因子 |
| **IPinfo** | 基础信息 + 类型 | 地理位置、注册地、IP 类型 |
| **ipregistry** | 类型 + 风险因子 | IP 类型、代理/VPN/Tor/服务器检测 |
| **Scamalytics** | 评分 + 风险因子 | 欺诈评分、代理/VPN/Tor/服务器/机器人检测 |
| **AbuseIPDB** | 评分 + 类型 | 滥用置信度评分、使用类型、Tor 检测 |
| **IPQS** | 评分 + 风险因子 | 欺诈评分、代理/VPN/Tor/滥用/机器人检测 |
| **ipdata** | 风险因子 | 代理/Tor/服务器/滥用检测 |
| **DB-IP** | 评分 + 机器人 | 威胁等级、爬虫检测 |

## 🚀 部署

### 前置要求

- [Node.js](https://nodejs.org/) >= 18
- [Cloudflare 账户](https://dash.cloudflare.com/)

### 本地开发

```bash
# 安装依赖
npm install

# 配置 API Key（创建 .dev.vars 文件）
cat > .dev.vars << 'EOF'
IPAPI_API_KEY=your_ipapi_key
IPREGISTRY_API_KEY=your_ipregistry_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
IPDATA_API_KEY=your_ipdata_key
IPQS_API_KEY=your_ipqs_key
EOF

# 启动开发服务器
npm run dev
```

访问 http://localhost:8787

### 生产部署

```bash
# 设置 Secrets
wrangler secret put IPAPI_API_KEY
wrangler secret put IPREGISTRY_API_KEY
wrangler secret put ABUSEIPDB_API_KEY
wrangler secret put IPDATA_API_KEY
wrangler secret put IPQS_API_KEY

# 部署
npm run deploy
```

## 🔑 API Key 获取

| 数据库 | 申请地址 | 备注 |
|--------|----------|------|
| ipapi | https://ipapi.is/ | 有免费 demo 额度，无 key 也可用 |
| ipregistry | https://ipregistry.co/ | 免费共 100000 次 |
| AbuseIPDB | https://www.abuseipdb.com/api | 免费 1000 次/天 |
| ipdata | https://ipdata.co/ | 免费 1500 次/天 |
| IPQS | https://www.ipqualityscore.com/ | 免费 1000 次/月 |
| Scamalytics | — | 直接爬取网页，无需 key |
| DB-IP | — | 直接爬取网页，无需 key |

## 📡 API

### 查询 IP

```
GET /api/check?ip=1.1.1.1
```

返回 JSON，包含 `basic`、`type`、`scores`、`factors` 四个主要字段。

## 📁 项目结构

```
├── worker.js        # Worker 主文件（含前后端全部代码）
├── wrangler.toml    # Cloudflare Workers 配置
├── .dev.vars        # 本地开发环境变量（不提交 Git）
├── package.json
└── README.md
```

## 📄 License

MIT
