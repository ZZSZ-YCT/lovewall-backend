# 新增/变更接口说明（lovewall-backend）

本说明补充项目现有 API.md，描述本次改动新增的接口与响应字段变更。

## 管理员帖子列表（含隐藏/已删除）
- 方法: `GET`
- 路径: `/api/posts/moderation`
- 认证: 需要登录；且需具备任意一个权限：`HIDE_POST` / `DELETE_POST` / `EDIT_POST`（或为超级管理员）。
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
- 认证: 需要登录；`DELETE_POST` 权限或超级管理员。
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
