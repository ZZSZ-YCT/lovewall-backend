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
    "permissions": ["MANAGE_POSTS", "MANAGE_FEATURED"]
  },
  "trace_id": "..."
}
```

### 更新个人资料
- 方法: `PATCH`
- 路径: `/api/profile`
- 认证: 是
- Content-Type: `application/json`
- Body（任意字段可选）:
```json
{
  "display_name": "新的显示名称",
  "email": "user@example.com",
  "phone": "13800138000",
  "bio": "这是我的个人简介",
  "avatar_base64": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ..."
}
```
- 头像: 支持 `jpeg/png/webp/gif`，解码后 ≤ 5MB；存储至 `${UPLOAD_DIR}/avatars/{用户ID}-{毫秒时间戳}.{ext}`，访问路径 `${UPLOAD_BASE_URL}/avatars/...`。仅保留当前头像，更新成功后会删除旧头像文件。
- 验证: `display_name`≤100，`bio`≤500，`email` 邮箱格式（唯一），`phone` `^1[3-9]\d{9}$`（唯一）。

### 公共用户信息查询（用于头像/昵称展示）
- 方法: `GET`
- 路径: `/api/users/{id}`
- 认证: 否
- 响应: 用户的公开信息（不包含邮箱/手机号等敏感字段）
```json
{
  "success": true,
  "data": {
    "id": "user-uuid",
    "username": "demo",
    "display_name": "昵称或null",
    "avatar_url": "/uploads/avatars/user-uuid-....jpg",
    "status": 0,
    "created_at": "...",
    "updated_at": "..."
  },
  "trace_id": "..."
}
```

- 方法: `GET`
- 路径: `/api/users/by-username/{username}`
- 认证: 否
- 说明: 与按 `id` 查询同样的返回结构。

### 用户列表（管理员）
- 方法: `GET`
- 路径: `/api/users`
- 认证: 是（`MANAGE_USERS`）
- 查询参数: `q`（用户名/邮箱模糊），`status`，`page`，`page_size`
- 响应: 分页结构，`items` 为用户精简信息，并包含 `permissions` 数组。

### 禁用/解禁用户（管理员）
- 禁用用户
  - 方法: `POST`
  - 路径: `/api/admin/users/{id}/ban`
  - 认证: 是（`MANAGE_USERS` 或超管）
  - Body:
  ```json
  { "reason": "违反社区规则" }
  ```
  - 返回:
  ```json
  { "success": true, "data": { "id": "...", "is_banned": true, "ban_reason": "违反社区规则" }, "trace_id": "..." }
  ```

- 解禁用户
  - 方法: `POST`
  - 路径: `/api/admin/users/{id}/unban`
  - 认证: 是（`MANAGE_USERS` 或超管）
  - 返回:
  ```json
  { "success": true, "data": { "id": "...", "is_banned": false }, "trace_id": "..." }
  ```

### 被禁用户登录提示
- 登录接口若用户被禁用，将返回错误：
```json
{
  "success": false,
  "error": { "code": "BANNED", "message": "违反社区规则" },
  "banned": true,
  "ban_reason": "违反社区规则",
  "trace_id": "..."
}
```

### 被禁用户主页展示
- 公开用户信息接口 `GET /api/users/{id}` 与 `GET /api/users/by-username/{username}`：
  - 若用户被禁用，仅返回：`id`, `username`, `is_banned: true`。
  - 不再返回 `display_name`、`avatar_url`、`bio` 等详细资料。
  - 标签使用原有接口获取：`GET /api/users/{id}/active-tag` 或按用户名版本。

### 更新用户（管理员）
- 方法: `PUT`
- 路径: `/api/users/{id}`
- 认证: 是（自己可更新部分字段；修改他人需 `MANAGE_USERS`。更改 `username` 仅限具备 `MANAGE_USERS` 或超管。）
- Content-Type: `application/json`
- Body（字段可选）:
```json
{
  "username": "newname",           // 仅管理员可改，3-32 字符且唯一
  "display_name": "昵称",
  "email": "user@example.com",
  "phone": "13800138000",
  "bio": "简介...",
  "avatar_base64": "data:image/png;base64,iVBORw0K...", // 可选；保存后覆盖 avatar_url
  "avatar_url": "/uploads/avatars/xxx.png",              // 可选；直接设置 URL
  "password": "NewSecurePass1!",                         // 自己改密码需提供 old_password
  "old_password": "OldPass"                               // 仅当 self 修改密码时必填
}
```
- 响应: 成功返回更新后的用户对象（新增字段 `permissions` 仅在列表接口返回）。

### 设置用户权限（仅超管）
- 方法: `POST`
- 路径: `/api/users/{id}/permissions`
- 认证: 是（仅超级管理员）
- Body:
```json
{ "permissions": ["MANAGE_FEATURED", "MANAGE_POSTS", "MANAGE_USERS", "MANAGE_ANNOUNCEMENTS"] }
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
  - `confessor_mode` `string` 可选，取值：`self` 或 `custom`（默认 `custom`）。
  - `author_name` `string` 当 `confessor_mode=custom` 时必填；`confessor_mode=self` 时可省略（后端将使用当前用户的显示名/用户名）。
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
  - 作者在创建后 15 分钟内可编辑；超时需要 `MANAGE_POSTS` 或超管。

### 删除（硬删）
- 方法: `DELETE`
- 路径: `/api/posts/{id}`
- 认证: 是
- 规则: 作者或具备 `MANAGE_POSTS` 的用户可执行；直接物理删除该帖子及其评论（仅保留操作日志），不可恢复。

### 置顶（管理员）
- 方法: `POST`
- 路径: `/api/posts/{id}/pin`
- 认证: 是（`MANAGE_FEATURED`）
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
- 认证: 是（`MANAGE_FEATURED`）
- Body:
```json
{ "feature": true }
```

### 隐藏（管理员）
- 方法: `POST`
- 路径: `/api/posts/{id}/hide`
- 认证: 是（`MANAGE_POSTS`）
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
- 说明: 直接删除（硬删除）。

## 认证与权限

- 登录后后端签发 JWT（HS256），载荷包含：`sub`（用户ID）、`is_superadmin`、`exp` 等。
- 传递方式：`Authorization: Bearer <token>` 或后端下发 HttpOnly Cookie。
- 超级管理员：`is_superadmin=true`，默认拥有全部权限，且可通过接口覆盖普通用户权限。
- 权限点（建议）：
  - `MANAGE_USERS` 用户管理
  - `MANAGE_POSTS` 帖子审核/隐藏/删除
  - `MANAGE_FEATURED` 置顶/精选帖子
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

- 上传: 仅允许 `image/jpeg`, `image/png`, `image/webp`, `image/gif`，大小由 `MAX_UPLOAD_MB` 限制。
- 时间窗编辑: 作者创建 15 分钟内可直接编辑；超时需 `MANAGE_POSTS` 或超管。
- 帖子删除策略: 通过 `status=2` 标记（不做物理删除）；公共列表默认过滤 `status!=0`。
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
- 响应项附带：`user_display_name`（昵称，若无则为 `username` 回退）、`user_username`（用户名），以及 `user_id`，便于前端按需查询用户头像。

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
- 说明: `hide=true` → `status=1`，`false` → `status=0`。删除为硬删除，无法恢复。

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
- 说明: 直接删除（硬删除）

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
- 查询参数: `tag_id`, `code`, `batch_id`, `used`=`true|false`, `page`, `page_size`
- 返回: 分页结构，`items` 包含 `tag` 与 `user`（使用者）。

### 删除兑换码（管理员）
- 方法: `DELETE`
- 路径: `/api/redemption-codes`
- 认证: 是（`MANAGE_TAGS`）
- Body:
```json
{ "ids": ["id1","id2"], "codes": ["ABCD-..."] }
```
- 说明: 仅删除未使用的兑换码；已使用的会跳过并返回原因；支持批量。
- 返回示例:
```json
{ "success": true, "data": { "deleted": 3, "skipped": [{"id":"...","code":"...","reason":"already used"}] }, "trace_id": "..." }
```

### 兑换码详情（管理员）
- 方法: `GET`
- 路径: `/api/redemption-codes/by-code/{code}`
- 认证: 是（`MANAGE_TAGS`）
- 说明: 返回是否已使用、使用者、关联标签、过期时间等。

### 管理员分配/删除用户标签
- 分配标签给用户
  - 方法: `POST`
  - 路径: `/api/admin/users/{user_id}/tags/{tag_id}`
  - 认证: 是（`MANAGE_TAGS`）
  - Body（可选）:
  ```json
  { "active": true }
  ```
  - 说明: 若 `active=true`，将该标签设为当前活跃标签（会取消该用户其它标签的活跃状态）。若用户已拥有该标签，仅更新活跃状态。

- 删除用户的指定标签
  - 方法: `DELETE`
  - 路径: `/api/admin/users/{user_id}/tags/{tag_id}`
  - 认证: 是（`MANAGE_TAGS`）
  - 说明: 直接删除该用户标签记录（硬删除）。

- 查询用户拥有的标签
  - 方法: `GET`
  - 路径: `/api/admin/users/{user_id}/tags`
  - 认证: 是（`MANAGE_TAGS`）
  - 返回: 与 `GET /api/my/tags?all=true` 相同结构，包含每个标签的 `user_tag_id/tag/obtained_at/is_active/status`。

### 平台指标（管理员）
- 方法: `GET`
- 路径: `/api/admin/metrics/overview`
- 认证: 是（`MANAGE_USERS` 或超管）
- 返回示例:
```json
{
  "total_comments": 12345,
  "today_comments": 67,
  "today_new_users": 10,
  "since": "2025-09-06T00:00:00+08:00"
}
```

## 日志（Logs）

- 日志分类：请求日志（不提供 API 查询）、提交日志（记录用户发布帖子与创建评论）、操作日志（记录管理员操作）。所有日志均持久化到数据库。

### 提交日志列表（仅超管）
- 方法: `GET`
- 路径: `/api/admin/logs/submissions`
- 认证: 是（仅超级管理员）
- 查询参数（可选）: `user_id`, `action`, `object_type`, `object_id`, `from`(RFC3339), `to`(RFC3339), `page`, `page_size`
- 返回: 分页结构，`items` 为提交日志记录。

### 操作日志列表（仅超管）
- 方法: `GET`
- 路径: `/api/admin/logs/operations`
- 认证: 是（仅超级管理员）
- 查询参数（可选）: `admin_id`, `action`, `object_type`, `object_id`, `from`(RFC3339), `to`(RFC3339), `page`, `page_size`
- 返回: 分页结构，`items` 为操作日志记录。

说明：请求日志（每次 HTTP 请求）已持久化，但不对外提供 API 查询。

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
- 行为说明:
  - 成功兑换后，系统会自动将新获得的标签设为活跃（active），并在同一事务内将该用户其它标签的活跃状态全部取消，保证任意时刻只有一个活跃标签。
  - 仍可通过手动激活接口 `POST /api/my/tags/{tag_id}/activate` 切换活跃标签。
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

### 用户活跃标签（公开）
- 方法: `GET`
- 路径:
  - 按ID: `/api/users/{id}/active-tag`
  - 按用户名: `/api/users/by-username/{username}/active-tag`
- 认证: 否（公开）
- 成功响应示例:
```json
{
  "success": true,
  "data": {
    "name": "vip",
    "title": "VIP用户",
    "background_color": "#FFD700",
    "text_color": "#000000",
    "user_deleted": false
  }
}
```
- 响应新增 `user_deleted` 字段：用户处于软删除状态时返回 `true`，前端可在展示层提示“账号已注销/不可访问”。
- 无活跃标签或用户不存在: 返回 `404 NOT_FOUND`

### 我的标签列表
- 方法: `GET`
- 路径: `/api/my/tags`
- 认证: 是
- 说明: 获取当前用户拥有的所有标签

### 我的当前标签状态
- 方法: `GET`
- 路径: `/api/my/tags/current-status`
- 认证: 是
- 返回示例:
```json
{ "success": true, "data": { "has_active": true, "current_tag_enabled": true, "tag": {"id":"...","name":"vip","title":"VIP用户","is_active":true}, "status":"active" }, "trace_id": "..." }
```

### 我的指定标签状态
- 方法: `GET`
- 路径: `/api/my/tags/{tag_id}/status`
- 认证: 是
- 说明: 仅限查询自己拥有的标签；未拥有返回 404。
- 返回示例:
```json
{ "success": true, "data": { "enabled": false, "status": "tag_disabled", "tag": {"id":"...","name":"...","title":"...","is_active":false} }, "trace_id": "..." }
```

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

## 系统通知（HTML 内容）

- `GET /api/notifications` 返回的 `items[].content` 现为 HTML 片段，封装在统一的 `.notification-card` 容器内；前端需要以安全方式渲染（建议白名单渲染或在受信任容器中使用 `innerHTML`）。
- 所有文本字段（帖子内容、原因、操作者姓名等）均已在服务端进行 HTML 转义，默认样式示例：

```html
<div class="notification-card">
  <h3>帖子被隐藏</h3>
  <p><strong>处理人：</strong>管理员昵称</p>
  <p><strong>帖子 ID：</strong>post-uuid</p>
  <p><strong>表白对象：</strong>张三</p>
  <p><strong>发布者：</strong>李四</p>
  <p><strong>处理原因：</strong>AI 检测到敏感词，请修改后重新发布。</p>
  <div class="post-preview">
    <div class="post-preview__label">原始内容</div>
    <pre class="post-preview__body" style="white-space: pre-wrap;">……原帖正文……</pre>
  </div>
  <div class="notification-actions">
    <button class="notification-action-placeholder" data-role="replace-action">等待替换按钮</button>
  </div>
</div>
```

- 占位按钮 `.notification-action-placeholder` 供前端在渲染阶段替换为实际 CTA；可通过 `data-role="replace-action"` 精确定位。
- 人工复核通知额外包含占位链接 `{{acceptLink}}`、`{{rejectLink}}`，分别用于“通过复核”“驳回请求”的按钮 href。

### 新增“理由”字段

以下接口的请求体新增可选字段 `reason`，用于在通知中回显处理原因（旧请求体仍兼容）：

```json
// 置顶 / 取消置顶
POST /api/posts/{id}/pin
{ "pin": true, "reason": "高优质内容" }

// 加精 / 取消加精
POST /api/posts/{id}/feature
{ "feature": false, "reason": "活动已结束" }

// 隐藏 / 取消隐藏
POST /api/posts/{id}/hide
{ "hide": true, "reason": "含有待整改内容" }
```

未传入时后端会提供默认说明；`reason` 将同步出现在通知卡片中，便于用户了解处理背景。
