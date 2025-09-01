# Love Wall 后端 API 文档 (v1)

本项目提供基于 JWT 的简洁 REST API，统一 JSON 响应结构，支持 Cookie 或 `Authorization: Bearer` 传递访问令牌。本文档描述当前已实现的接口与约定。

- 基础路径: `/api`
- 数据格式: `application/json`（除文件上传外）
- 认证方式: `Authorization: Bearer <token>` 或 HttpOnly Cookie（名默认 `auth_token`）
- 统一响应: 见“统一响应格式”一节
- 分页约定: 见“分页约定”一节

## 统一响应格式

成功:
```json
{
  "success": true,
  "data": { "...": "..." },
  "trace_id": "c39e8a8a-..."
}
```

失败:
```json
{
  "success": false,
  "error": { "code": "UNAUTHORIZED", "message": "missing token" },
  "trace_id": "c39e8a8a-..."
}
```

常见错误码:
- `UNAUTHORIZED` 401 未登录或 Token 失效
- `FORBIDDEN` 403 权限不足
- `NOT_FOUND` 404 资源不存在或不可见
- `VALIDATION_FAILED` 422 参数校验失败
- `CONFLICT` 409 冲突（如用户名占用）
- `INTERNAL_ERROR` 500 服务器内部错误

## 分页约定

- 查询参数: `page`（默认1），`page_size`（默认20，最大100）
- 返回字段: `total`, `items`, `page`, `page_size`

## 认证与用户

### 注册
- 方法: `POST`
- 路径: `/api/register`
- 认证: 否
- Body:
```json
{ "username": "demo", "password": "secret123" }
```
- 说明: 首个注册用户在 `ADMIN_INIT_USER` 未设置或与用户名匹配时将被标记为超级管理员。
- 成功响应:
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "...",
      "username": "demo",
      "display_name": null,
      "email": null,
      "phone": null,
      "avatar_url": null,
      "bio": null,
      "is_superadmin": false,
      "status": 0,
      "last_login_at": null,
      "last_ip": null,
      "metadata": null,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    },
    "access_token": "<jwt>"
  },
  "trace_id": "..."
}
```

### 登录
- 方法: `POST`
- 路径: `/api/login`
- 认证: 否
- Body:
```json
{ "username": "demo", "password": "secret123" }
```
- 成功响应: 同注册（返回 `user` 与 `access_token`）。若启用 Cookie，将同时下发 HttpOnly Cookie。

### 登出
- 方法: `POST`
- 路径: `/api/logout`
- 认证: 是
- 说明: 清除 Cookie（如启用 Cookie 认证）。
- 响应:
```json
{ "success": true, "data": {"ok": true}, "trace_id": "..." }
```

### 个人信息
- 方法: `GET`
- 路径: `/api/profile`
- 认证: 是
- 成功响应（示例）:
```json
{
  "success": true,
  "data": {
    "user": { "id": "...", "username": "demo", "is_superadmin": false, "created_at": "...", "updated_at": "..." },
    "permissions": ["PIN_POST", "FEATURE_POST"]
  },
  "trace_id": "..."
}
```

### 用户列表（管理员）
- 方法: `GET`
- 路径: `/api/users`
- 认证: 是（`MANAGE_USERS`）
- 查询参数: `q`（用户名/邮箱模糊），`status`，`page`，`page_size`
- 响应: 分页结构，`items` 为用户精简信息。

### 设置用户权限（仅超管）
- 方法: `POST`
- 路径: `/api/users/{id}/permissions`
- 认证: 是（仅超级管理员）
- Body:
```json
{ "permissions": ["PIN_POST", "FEATURE_POST", "HIDE_POST", "DELETE_POST", "EDIT_POST", "MANAGE_USERS", "MANAGE_ANNOUNCEMENTS"] }
```
- 说明: 覆盖式写入，原有权限将被清空后重建。

## 帖子（Love Wall）

实体字段（主要）:
- `id` `string` UUID
- `author_id` `string`
- `author_name` `string`
- `target_name` `string`
- `content` `string`
- `image_path` `string|null` 静态可访问 URL（例如 `/uploads/<uuid>.jpg`）
- `status` `int` 0=发布，1=隐藏，2=已删除（软）
- `is_pinned` `bool` 置顶
- `is_featured` `bool` 精选
- `created_at/updated_at/deleted_at`

### 列表（公开）
- 方法: `GET`
- 路径: `/api/posts`
- 查询参数:
  - `page`, `page_size`
  - `featured`=`true|false`（可选）
  - `pinned`=`true|false`（可选）
- 过滤: 默认仅返回 `status=0` 的帖子。
- 响应: 分页结构。

### 详情（公开）
- 方法: `GET`
- 路径: `/api/posts/{id}`
- 规则: `status!=0` 一律返回 404（仅管理员/作者等可通过管理接口查看/操作）。

### 新建（需认证）
- 方法: `POST`
- 路径: `/api/posts`
- 认证: 是
- Content-Type: `multipart/form-data`
- 表单字段:
  - `author_name` `string` 必填
  - `target_name` `string` 必填
  - `content` `string` 必填
  - `image` `file` 可选（MIME: jpeg/png/webp/gif；大小<=`MAX_UPLOAD_MB`）
- 成功响应: 201 + 新建帖子对象。
- 说明: 图片将保存到 `UPLOAD_DIR` 并返回对应 `UPLOAD_BASE_URL` 下的相对 URL。

### 编辑（作者限时或管理员）
- 方法: `PUT`
- 路径: `/api/posts/{id}`
- 认证: 是
- Body（任意字段可选）:
```json
{ "author_name": "匿名A", "target_name": "小王", "content": "更新内容" }
```
- 规则:
  - 作者在创建后 15 分钟内可编辑；超时需要 `EDIT_POST` 或超管。

### 删除（软删）
- 方法: `DELETE`
- 路径: `/api/posts/{id}`
- 认证: 是
- 规则: 作者或具备 `DELETE_POST` 的用户可执行；将 `status` 置为 2。

### 置顶（管理员）
- 方法: `POST`
- 路径: `/api/posts/{id}/pin`
- 认证: 是（`PIN_POST`）
- Body:
```json
{ "pin": true }
```
- 响应（示例）:
```json
{ "success": true, "data": {"id": "...", "is_pinned": true}, "trace_id": "..." }
```

### 精选（管理员）
- 方法: `POST`
- 路径: `/api/posts/{id}/feature`
- 认证: 是（`FEATURE_POST`）
- Body:
```json
{ "feature": true }
```

### 隐藏（管理员）
- 方法: `POST`
- 路径: `/api/posts/{id}/hide`
- 认证: 是（`HIDE_POST`）
- Body:
```json
{ "hide": true }
```
- 说明: `hide=true` 将 `status` 置为 1，`false` 恢复为 0。

## 公告（Announcements）

实体字段（主要）:
- `id` `string` UUID
- `title` `string`
- `content` `string`
- `is_active` `bool`
- `metadata` `string|null`
- `created_at/updated_at/deleted_at`

### 列表（公开）
- 方法: `GET`
- 路径: `/api/announcements`
- 规则: 仅返回 `is_active=1` 且未删除。

### 新建（管理员）
- 方法: `POST`
- 路径: `/api/announcements`
- 认证: 是（`MANAGE_ANNOUNCEMENTS`）
- Body:
```json
{ "title": "系统维护", "content": "今晚0点维护...", "is_active": true, "metadata": "{\"level\":\"info\"}" }
```
- 成功: 201 + 公告对象。

### 更新（管理员）
- 方法: `PUT`
- 路径: `/api/announcements/{id}`
- 认证: 是（`MANAGE_ANNOUNCEMENTS`）
- Body（任意字段可选）:
```json
{ "title": "更新标题", "content": "更新内容", "is_active": false, "metadata": "..." }
```

### 删除（管理员）
- 方法: `DELETE`
- 路径: `/api/announcements/{id}`
- 认证: 是（`MANAGE_ANNOUNCEMENTS`）
- 说明: 当前实现为“停用”（`is_active=false`），保留记录。

## 认证与权限

- 登录后后端签发 JWT（HS256），载荷包含：`sub`（用户ID）、`is_superadmin`、`exp` 等。
- 传递方式：`Authorization: Bearer <token>` 或后端下发 HttpOnly Cookie。
- 超级管理员：`is_superadmin=true`，默认拥有全部权限，且可通过接口覆盖普通用户权限。
- 权限点（建议）：
  - `MANAGE_USERS` 用户管理
  - `EDIT_POST` 编辑帖子（超时编辑）
  - `DELETE_POST` 删除帖子
  - `HIDE_POST` 隐藏/恢复帖子
  - `PIN_POST` 置顶帖子
  - `FEATURE_POST` 精选帖子
  - `MANAGE_ANNOUNCEMENTS` 公告管理
  - `MANAGE_COMMENTS` 评论管理
  - `MANAGE_TAGS` 标签和兑换码管理

## 示例（curl）

登录:
```bash
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"secret"}'
```

发帖（含图片）:
```bash
curl -X POST http://localhost:8000/api/posts \
  -H "Authorization: Bearer <token>" \
  -F "author_name=匿名" \
  -F "target_name=小王" \
  -F "content=勇敢说爱你！" \
  -F "image=@/path/to/pic.jpg"
```

置顶（管理员）:
```bash
curl -X POST http://localhost:8000/api/posts/<post_id>/pin \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"pin": true}'
```

公告创建（管理员）:
```bash
curl -X POST http://localhost:8000/api/announcements \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"系统维护","content":"今晚0点维护...","is_active":true}'
```

## 备注与限制

- CORS: 服务按环境变量 `ALLOW_ORIGINS` 控制允许来源（逗号分隔）。
- 上传: 仅允许 `image/jpeg`, `image/png`, `image/webp`, `image/gif`，大小由 `MAX_UPLOAD_MB` 限制。
- 时间窗编辑: 作者创建 15 分钟内可直接编辑；超时需 `EDIT_POST` 或超管。
- 软删除策略: 帖子通过 `status=2` 标记；公共列表默认过滤 `status!=0`。
- 稳定性: 返回携带 `trace_id`，便于日志排查。

## 预留与 Roadmap（未实现）

- OIDC/三方登录：`/api/auth/oidc/:provider/login` 和回调绑定流程。
- 刷新令牌、设备管理、速率限制更细粒度、审计日志等。

## 评论（Comments）

实体字段（主要）:
- `id` `string` UUID
- `post_id` `string`
- `user_id` `string`
- `content` `string`
- `status` `int` 0=正常, 1=隐藏
- `created_at/updated_at/deleted_at`

### 列表（公开）
- 方法: `GET`
- 路径: `/api/posts/{id}/comments`
- 查询: `page`, `page_size`
- 规则: 仅当父帖子 `status=0` 时可见；仅返回 `status=0` 的评论。

### 创建（需认证）
- 方法: `POST`
- 路径: `/api/posts/{id}/comments`
- Body:
```json
{ "content": "写下你的看法..." }
```
- 规则: 仅当父帖子 `status=0` 时允许评论。

### 删除（隐藏，作者或管理员）
- 方法: `DELETE`
- 路径: `/api/comments/{id}`
- 认证: 是（作者本人或 `MANAGE_COMMENTS` 或超管）
- 行为: 将评论 `status` 置为 1（隐藏）。

### 编辑（作者限时或管理员）
- 方法: `PUT`
- 路径: `/api/comments/{id}`
- 认证: 是
- Body:
```json
{ "content": "更新后的评论" }
```
- 规则: 作者创建 15 分钟内可编辑；超时需要 `MANAGE_COMMENTS` 或超管。

### 管理隐藏/恢复（管理员）
- 方法: `POST`
- 路径: `/api/comments/{id}/hide`
- 认证: 是（`MANAGE_COMMENTS` 或超管）
- Body:
```json
{ "hide": true }
```
- 说明: `hide=true` → `status=1`，`false` → `status=0`。

### 我的评论（需认证）
- 方法: `GET`
- 路径: `/api/my/comments`
- 查询: `page`, `page_size`
- 说明: 列出当前登录用户的评论（包含被隐藏的）。

### 审核列表（管理员）
- 方法: `GET`
- 路径: `/api/comments`
- 认证: 是（`MANAGE_COMMENTS` 或超管）
- 查询: `post_id`, `user_id`, `status(0|1)`, `page`, `page_size`
- 说明: 评论管理分页列表。

## 标签系统（Tag System）

实体字段（主要）:

**Tag（标签）**:
- `id` `string` UUID
- `name` `string` 唯一标识名
- `title` `string` 显示标题
- `background_color` `string` 背景色 (#RRGGBB)
- `text_color` `string` 文字色 (#RRGGBB)
- `description` `string|null` 描述
- `is_active` `bool` 是否启用
- `created_at/updated_at/deleted_at`

**RedemptionCode（兑换码）**:
- `id` `string` UUID
- `code` `string` 兑换码（格式: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX）
- `tag_id` `string` 关联标签
- `is_used` `bool` 是否已使用
- `used_by` `string|null` 使用者ID
- `used_at` `datetime|null` 使用时间
- `expires_at` `datetime|null` 过期时间
- `batch_id` `string|null` 批次ID
- `created_at/updated_at/deleted_at`

**UserTag（用户标签）**:
- `id` `string` UUID
- `user_id` `string` 用户ID
- `tag_id` `string` 标签ID
- `obtained_at` `datetime` 获得时间
- `is_active` `bool` 是否为当前活跃标签
- `created_at/updated_at/deleted_at`

### 标签列表（公开）
- 方法: `GET`
- 路径: `/api/tags`
- 查询参数: `active`=`true|false`, `page`, `page_size`
- 说明: 公开浏览所有可用标签

### 标签详情
- 方法: `GET`
- 路径: `/api/tags/{id}`
- 认证: 是

### 创建标签（管理员）
- 方法: `POST`
- 路径: `/api/tags`
- 认证: 是（`MANAGE_TAGS`）
- Body:
```json
{
  "name": "vip",
  "title": "VIP用户",
  "background_color": "#FFD700",
  "text_color": "#000000",
  "description": "VIP尊贵用户标识"
}
```

### 更新标签（管理员）
- 方法: `PUT`
- 路径: `/api/tags/{id}`
- 认证: 是（`MANAGE_TAGS`）
- Body（字段可选）:
```json
{
  "title": "超级VIP",
  "background_color": "#FF6B6B",
  "is_active": true
}
```

### 删除标签（管理员）
- 方法: `DELETE`
- 路径: `/api/tags/{id}`
- 认证: 是（`MANAGE_TAGS`）
- 说明: 软删除，设置 `deleted_at`

### 生成兑换码（管理员）
- 方法: `POST`
- 路径: `/api/tags/generate-codes`
- 认证: 是（`MANAGE_TAGS`）
- Body:
```json
{
  "tag_id": "uuid-of-tag",
  "count": 100,
  "expires_at": "2024-12-31T23:59:59Z"
}
```
- 成功响应:
```json
{
  "success": true,
  "data": {
    "batch_id": "BATCH_1703980800_ABCD1234",
    "tag": { "id": "...", "name": "vip", "title": "VIP用户" },
    "count": 100,
    "codes": [
      {
        "id": "...",
        "code": "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ",
        "tag_id": "...",
        "is_used": false,
        "expires_at": "2024-12-31T23:59:59Z",
        "batch_id": "BATCH_1703980800_ABCD1234",
        "created_at": "..."
      }
    ]
  }
}
```

### 兑换码列表（管理员）
- 方法: `GET`
- 路径: `/api/redemption-codes`
- 认证: 是（`MANAGE_TAGS`）
- 查询参数: `tag_id`, `batch_id`, `used`=`true|false`, `page`, `page_size`

### 兑换码（用户）
- 方法: `POST`
- 路径: `/api/redeem`
- 认证: 是
- Body:
```json
{
  "code": "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"
}
```
- 成功响应:
```json
{
  "success": true,
  "data": {
    "success": true,
    "message": "Tag redeemed successfully",
    "user_tag": {
      "id": "...",
      "user_id": "...",
      "tag_id": "...",
      "obtained_at": "...",
      "is_active": true,
      "tag": {
        "name": "vip",
        "title": "VIP用户",
        "background_color": "#FFD700",
        "text_color": "#000000"
      }
    }
  }
}
```

### 我的标签列表
- 方法: `GET`
- 路径: `/api/my/tags`
- 认证: 是
- 说明: 获取当前用户拥有的所有标签

### 设置活跃标签
- 方法: `POST`
- 路径: `/api/my/tags/{tag_id}/activate`
- 认证: 是
- 说明: 设置某个标签为当前活跃显示标签（一次只能激活一个）

### 带标签的响应示例

**帖子列表带用户标签**:
```json
{
  "success": true,
  "data": {
    "total": 10,
    "items": [
      {
        "id": "post-uuid",
        "author_id": "user-uuid",
        "author_name": "匿名用户",
        "target_name": "小明",
        "content": "表白内容...",
        "image_path": "/uploads/image.jpg",
        "status": 0,
        "is_pinned": false,
        "is_featured": true,
        "created_at": "2024-01-01T12:00:00Z",
        "author_tag": {
          "name": "vip",
          "title": "VIP用户",
          "background_color": "#FFD700",
          "text_color": "#000000"
        }
      }
    ]
  }
}
```

**评论列表带用户标签**:
```json
{
  "success": true,
  "data": {
    "total": 5,
    "items": [
      {
        "id": "comment-uuid",
        "post_id": "post-uuid",
        "user_id": "user-uuid",
        "content": "评论内容...",
        "status": 0,
        "created_at": "2024-01-01T12:30:00Z",
        "user_tag": {
          "name": "member",
          "title": "会员",
          "background_color": "#4CAF50",
          "text_color": "#FFFFFF"
        }
      }
    ]
  }
}
```
