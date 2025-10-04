# Love Wall 后端服务

一个基于 Go + Gin + SQLite 的表白墙后端服务，支持用户注册登录、发布表白帖子、评论系统、公告管理和标签系统。

## ✨ 功能特性

- 🔐 **用户认证** - JWT 认证，支持 Bearer Token 和 Cookie 两种方式
- 💌 **表白帖子** - 发布、编辑、删除、置顶、精选表白内容，支持图片上传
- 💬 **评论系统** - 对表白帖子进行评论，支持隐藏和管理
- 📢 **公告管理** - 系统公告的发布和管理
- 🏷️ **标签系统** - 用户标签和兑换码系统
- 👑 **权限管理** - 超级管理员和细粒度权限控制
- 🔒 **安全防护** - 限流、安全头等
- 🐳 **容器化** - Docker 和 Docker Compose 部署支持

## 🚀 快速开始

### 环境要求

- Go 1.22+
- SQLite 3
- Docker (可选)

### 本地运行

1. **克隆项目**
   ```bash
   git clone https://github.com/ZZSZ-YCT/lovewall-backend.git
   cd lovewall-backend
   ```

2. **安装依赖**
   ```bash
   go mod download
   ```

3. **配置环境变量**
   ```bash
   export JWT_SECRET="your-super-secret-key"
   export DB_DSN="./data/app.db"
   export UPLOAD_DIR="./data/uploads"
   export ADMIN_INIT_USER="admin"
   export ADMIN_INIT_PASS="admin123"
   ```

4. **运行服务**
   ```bash
   go run ./cmd/server
   ```

服务将在 `http://localhost:8000` 启动。

### Docker 部署

使用 Docker Compose 快速部署：

```bash
# 构建并启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

服务将在 `http://localhost:8124` 启动。

## 📖 API 文档

详细的 API 文档请参考 [API.md](API.md)，包含所有接口的详细说明、请求参数和响应示例。

### 主要 API 端点

- **认证相关**
  - `POST /api/register` - 用户注册
  - `POST /api/login` - 用户登录
  - `POST /api/logout` - 用户登出
  - `GET /api/profile` - 获取用户信息

- **表白帖子**
  - `GET /api/posts` - 获取帖子列表
  - `POST /api/posts` - 发布新帖子
  - `GET /api/posts/{id}` - 获取帖子详情
  - `PUT /api/posts/{id}` - 编辑帖子
  - `DELETE /api/posts/{id}` - 删除帖子

- **评论系统**
  - `GET /api/posts/{id}/comments` - 获取帖子评论
  - `POST /api/posts/{id}/comments` - 发表评论
  - `PUT /api/comments/{id}` - 编辑评论
  - `DELETE /api/comments/{id}` - 删除评论

- **管理功能**
  - `GET /api/users` - 用户管理
  - `POST /api/posts/{id}/pin` - 置顶帖子
  - `POST /api/posts/{id}/feature` - 精选帖子
  - `POST /api/announcements` - 发布公告

## 🔧 配置说明

| 环境变量 | 描述 | 默认值 |
|---------|------|--------|
| `PORT` | 服务端口 | `8000` |
| `DB_DRIVER` | 数据库驱动 | `sqlite` |
| `DB_DSN` | 数据库连接字符串 | `./data/app.db` |
| `JWT_SECRET` | JWT 签名密钥 | **必填** |
| `JWT_TTL` | JWT 过期时间(秒) | `86400` |
| `UPLOAD_DIR` | 文件上传目录 | `./data/uploads` |
| `UPLOAD_BASE_URL` | 文件访问 URL 前缀 | `/uploads` |
| `MAX_UPLOAD_MB` | 最大上传文件大小(MB) | `10` |
| `ADMIN_INIT_USER` | 初始管理员用户名 | `` |
| `ADMIN_INIT_PASS` | 初始管理员密码 | `` |
| `RATE_LIMIT_RPS` | 限流每秒请求数 | `20` |
| `RATE_LIMIT_BURST` | 限流突发请求数 | `40` |

## 🛠️ 项目结构

```
lovewall-backend/
├── cmd/server/          # 应用入口
├── internal/
│   ├── auth/           # 认证相关
│   ├── config/         # 配置管理
│   ├── db/            # 数据库操作
│   ├── http/
│   │   ├── handler/   # HTTP 处理器
│   │   ├── middleware/ # 中间件
│   │   └── response.go # 统一响应格式
│   ├── model/         # 数据模型
│   ├── service/       # 业务逻辑
│   └── storage/       # 文件存储
├── migrations/         # 数据库迁移文件
├── API.md             # API 文档
├── Dockerfile         # Docker 构建文件
└── docker-compose.yml # Docker Compose 配置
```

## 🔒 权限系统

系统支持基于角色的权限控制：

- **超级管理员** (`is_superadmin=true`): 拥有所有权限
- **权限点**:
  - `MANAGE_USERS` - 用户管理
  - `MANAGE_POSTS` - 帖子审核/隐藏/删除
  - `MANAGE_FEATURED` - 置顶/精选帖子
  - `MANAGE_ANNOUNCEMENTS` - 公告管理
  - `MANAGE_COMMENTS` - 评论管理
  - `MANAGE_TAGS` - 标签和兑换码管理

## 💾 数据库

使用 SQLite 作为默认数据库，支持以下主要表：

- `users` - 用户表
- `posts` - 帖子表
- `comments` - 评论表
- `announcements` - 公告表
- `user_permissions` - 用户权限表
- `tags` - 标签表
- `redemption_codes` - 兑换码表
- `user_tags` - 用户标签关联表

## 🧪 开发

### 运行测试
```bash
go test ./...
```

### 构建
```bash
go build -o server ./cmd/server
```

### 生成 API 文档
API 文档已包含在 `API.md` 文件中，包含所有接口的详细说明。

## 📝 License

MIT License - 详见 LICENSE 文件。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📞 联系

如有问题或建议，请通过 Issue 联系。