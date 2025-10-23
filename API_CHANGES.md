# 新增/变更接口说明（lovewall-backend）

本说明补充项目现有 API.md，描述本次改动新增的接口与响应字段变更。

## 系统通知改为 HTML 模板
- `GET /api/notifications` 返回的 `data.items[].content` 现为 HTML 片段，包含 `.notification-card` 结构、原帖内容、处理人、原因以及占位按钮 `data-role="replace-action"`，方便前端直接渲染卡片样式。
- 人工复核通知中的 `{{acceptLink}}` / `{{rejectLink}}` 占位符保留，用于前端替换为实际操作链接。
- 新增可选字段 `reason`：
  - `POST /api/posts/{id}/pin`
  - `POST /api/posts/{id}/feature`
  - `POST /api/posts/{id}/hide`
  请求体可携带 `{ "reason": "字符串" }`，若缺省后端会填充默认说明；该理由将同步展示在通知 HTML 中。
- 403 登录校验新增 `ACCOUNT_DELETED`：持有有效 Token 但账号已被软删除时返回 `{"success":false,"error":{"code":"ACCOUNT_DELETED",...},"is_deleted":true}`，前端可据此提示用户账号状态。

## 管理员帖子列表（含隐藏/已删除）
- 方法: `GET`
- 路径: `/api/posts/moderation`
- 认证: 需要登录；且需具备任意一个权限：`MANAGE_POSTS`（或为超级管理员）。
- 查询参数:
  - `status` = `0|1|2`（可选；默认不过滤，返回所有状态）。
  - `author_id`（可选）
  - `featured` = `true|false`（可选）
  - `pinned` = `true|false`（可选）
  - `page`, `page_size`
- 返回: 分页列表，包含公开、已隐藏（status=1）与已删除（status=2）的帖子；每项附带作者正在启用的用户标签信息。

## 恢复帖子（从已删除 -> 公开）
- 方法: `POST`
- 路径: `/api/posts/{id}/restore`
- 认证: 需要登录；`MANAGE_POSTS` 权限或超级管理员。
- 说明: 仅当帖子当前 `status=2`（已删除）时，恢复为 `status=0`（公开）。

## 管理员评论列表与帖子状态联动
- 接口: 现有 `GET /api/comments`（需 `MANAGE_COMMENTS`）
- 行为变更:
  - 若评论所属帖子为“已删除”（`posts.status = 2`），该评论不会出现在管理员评论列表里。
  - 若评论所属帖子为“已隐藏”（`posts.status = 1`），管理员评论列表仍会显示该评论。

## 评论响应增加昵称字段
- 受影响接口：
  - `GET /api/posts/{id}/comments`
  - `GET /api/my/comments`
  - `GET /api/comments`（管理员）
- 响应项新增字段：
  - `user_display_name`：评论创建者的当前昵称；若用户未设置昵称则回退为其 `username`。
- 设计说明：
  - 评论表仅保存 `user_id`（不可变的用户 UID）。
  - 获取评论列表时根据 `user_id` 动态查询用户表以获得最新昵称，因此当用户修改昵称后，所有评论展示会自动同步，无需迁移历史数据。

示例（评论项，省略无关字段）：
```json
{
  "id": "comment-uuid",
  "post_id": "post-uuid",
  "user_id": "user-uuid",
  "user_display_name": "新的昵称或username回退值",
  "content": "……",
  "status": 0,
  "created_at": "2025-09-01T12:30:00Z",
  "user_tag": {
    "name": "member",
    "title": "会员",
    "background_color": "#4CAF50",
    "text_color": "#FFFFFF"
  }
}
```

## 用户名与昵称机制（已具备）
- 用户具备：
  - 不可变的登录名 `username`
  - 可变的展示昵称 `display_name`
- 相关接口：
  - 获取个人资料：`GET /api/profile`
  - 修改用户资料（含昵称）：`PUT /api/users/{id}`，Body 示例：
    ```json
    { "display_name": "新的昵称" }
    ```

## 现有设计回顾
 - 评论表：仅保存 `user_id`（UID），不冗余昵称，展示时动态查询，满足“昵称修改后评论展示同步变更”的需求。
 - 帖子状态：`status=0` 公开，`1` 隐藏，`2` 已删除。
- 本次新增：管理员帖子列表与恢复接口；管理员评论列表自动排除“所属帖子已删除”的评论；评论响应新增 `user_display_name`。

## 公共用户信息查询（新增）
- 新增公开接口：
  - `GET /api/users/{id}` 按用户ID查询公开信息
  - `GET /api/users/by-username/{username}` 按用户名查询公开信息
- 返回字段：`id`, `username`, `display_name`, `avatar_url`, `status`, `created_at`, `updated_at`
- 隐私：不返回邮箱/手机号等敏感字段。

## 评论列表响应扩展
- 在评论项中增加 `user_username` 字段，配合现有 `user_id` 与 `user_display_name` 便于前端进一步查询头像。

## 更新个人资料（新增）
- 方法: `PATCH`
- 路径: `/api/profile`
- 认证: 是（JWT）
- Content-Type: `application/json`

请求 Body（任意字段可选）:
```json
{
  "display_name": "新的显示名称",
  "email": "user@example.com",
  "phone": "13800138000",
  "bio": "这是我的个人简介",
  "avatar_base64": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ..."
}
```

验证规则:
- `display_name`: 最大 100 字符
- `bio`: 最大 500 字符
- `email`: 邮箱格式（可选，唯一；为空字符串视为清空为 null）
- `phone`: 中国大陆手机号 `^1[3-9]\d{9}$`（可选，唯一；为空字符串视为清空为 null）
- `avatar_base64`: `data:image/{jpeg|png|webp|gif};base64,` 前缀的 Base64 图片，解码后大小 ≤ 5MB

头像处理:
- 仅保留一份当前头像：新头像保存成功并更新数据库后，会删除旧头像文件（如果旧头像位于上传目录下）。
- 存储路径: `${UPLOAD_DIR}/avatars/{用户ID}-{毫秒时间戳}.{ext}`
- 访问 URL: `${UPLOAD_BASE_URL}/avatars/{用户ID}-{毫秒时间戳}.{ext}`（例如：`/uploads/avatars/user-uuid-1640995200000.jpg`）

成功响应（示例）:
```json
{
  "success": true,
  "data": {
    "id": "user-uuid",
    "username": "demo",
    "display_name": "新的显示名称",
    "email": "user@example.com",
    "phone": "13800138000",
    "avatar_url": "/uploads/avatars/user-uuid-1640995200000.jpg",
    "bio": "这是我的个人简介",
    "is_superadmin": false,
    "status": 0,
    "last_login_at": "2024-01-01T10:00:00Z",
    "last_ip": "127.0.0.1",
    "metadata": null,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T12:30:00Z"
  },
  "trace_id": "abc123"
}
```

错误响应（示例）:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Email format is invalid"
  },
  "trace_id": "abc123"
}
```
