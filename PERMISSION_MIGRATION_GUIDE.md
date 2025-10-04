# 权限系统重构 - 前端对接文档

## 概述

后端权限系统已从**8个分散权限**重构为**6个颗粒度权限**,实现更清晰的权限管理。

---

## 一、权限变更对照表

| 旧权限 (已废弃) | 新权限 | 说明 |
|----------------|--------|------|
| `HIDE_POST` | `MANAGE_POSTS` | 合并到帖子管理 |
| `DELETE_POST` | `MANAGE_POSTS` | 合并到帖子管理 |
| `EDIT_POST` | `MANAGE_POSTS` | 合并到帖子管理 |
| `PIN_POST` | `MANAGE_FEATURED` | 合并到精华管理 |
| `FEATURE_POST` | `MANAGE_FEATURED` | 合并到精华管理 |
| `MANAGE_COMMENTS` | `MANAGE_COMMENTS` | **保持不变** |
| `MANAGE_USERS` | `MANAGE_USERS` | **保持不变** |
| `MANAGE_ANNOUNCEMENTS` | `MANAGE_ANNOUNCEMENTS` | **保持不变** |
| `MANAGE_TAGS` | `MANAGE_TAGS` | **保持不变** |

---

## 二、新权限体系详解

### 1. `MANAGE_POSTS` - 帖子管理
**功能范围:**
- 审核帖子 (通过/拒绝)
- 删除帖子
- 隐藏帖子
- 查看审核队列

**影响接口:**
```
POST   /api/admin/posts/:id/approve      # 审核通过
POST   /api/admin/posts/:id/reject       # 审核拒绝
POST   /api/posts/:id/hide                # 隐藏帖子
DELETE /api/posts/:id                     # 删除帖子 (管理员)
GET    /api/posts/moderation              # 查看审核队列
POST   /api/posts/:id/restore             # 恢复已删帖子
```

**前端适配:**
- 检查用户是否有 `MANAGE_POSTS` 权限
- 显示"帖子管理"菜单项
- 启用审核/删除/隐藏按钮

---

### 2. `MANAGE_FEATURED` - 精华管理
**功能范围:**
- 置顶帖子
- 设置精华帖子

**影响接口:**
```
POST /api/posts/:id/pin        # 置顶帖子
POST /api/posts/:id/feature    # 精华帖子
```

**前端适配:**
- 检查用户是否有 `MANAGE_FEATURED` 权限
- 显示"精华管理"菜单项
- 启用置顶/精华按钮

---

### 3. `MANAGE_COMMENTS` - 评论管理
**功能范围:**
- 隐藏评论
- 删除评论
- 查看评论审核列表

**影响接口:**
```
POST   /api/comments/:id/hide   # 隐藏评论
DELETE /api/comments/:id         # 删除评论 (管理员)
GET    /api/comments             # 查看所有评论 (审核)
```

**前端适配:**
- 检查用户是否有 `MANAGE_COMMENTS` 权限
- 显示"评论管理"菜单项

---

### 4. `MANAGE_USERS` - 用户管理
**功能范围:**
- 查看用户列表
- 修改用户信息 (头像、昵称、用户名)
- 封禁/解封用户
- 重置用户密码
- **(条件)** 给用户分配标签 (需同时拥有 `MANAGE_TAGS` 权限)

**影响接口:**
```
GET    /api/users                       # 查看用户列表
PUT    /api/users/:id                   # 修改用户信息
PUT    /api/admin/users/:id/password    # 重置密码
POST   /api/admin/users/:id/ban         # 封禁用户
POST   /api/admin/users/:id/unban       # 解封用户
DELETE /api/admin/users/:id             # 删除用户 (仅超管)
GET    /api/admin/metrics/overview      # 数据概览
```

**标签分配特殊规则:**
```
POST   /api/admin/users/:id/tags/:tag_id     # 需要 MANAGE_USERS + MANAGE_TAGS
DELETE /api/admin/users/:id/tags/:tag_id     # 需要 MANAGE_USERS + MANAGE_TAGS
GET    /api/admin/users/:id/tags             # 需要 MANAGE_TAGS
```

**前端适配:**
- 检查用户是否有 `MANAGE_USERS` 权限
- 显示"用户管理"菜单项
- **重要:** 标签分配功能需同时检查 `MANAGE_USERS` 和 `MANAGE_TAGS`

---

### 5. `MANAGE_ANNOUNCEMENTS` - 公告管理
**功能范围:**
- 创建公告
- 修改公告
- 删除公告

**影响接口:**
```
POST   /api/announcements         # 创建公告
PUT    /api/announcements/:id     # 修改公告
DELETE /api/announcements/:id     # 删除公告
```

**前端适配:**
- 检查用户是否有 `MANAGE_ANNOUNCEMENTS` 权限
- 显示"公告管理"菜单项

---

### 6. `MANAGE_TAGS` - 标签管理
**功能范围:**
- 创建/修改/删除标签
- 生成兑换码
- 查看/删除兑换码
- 给用户分配/移除标签

**影响接口:**
```
POST   /api/tags                            # 创建标签
PUT    /api/tags/:id                        # 修改标签
DELETE /api/tags/:id                        # 删除标签
POST   /api/tags/generate-codes             # 生成兑换码
GET    /api/redemption-codes                # 查看兑换码列表
DELETE /api/redemption-codes                # 删除兑换码
POST   /api/admin/users/:id/tags/:tag_id    # 给用户分配标签
DELETE /api/admin/users/:id/tags/:tag_id    # 移除用户标签
GET    /api/admin/users/:id/tags            # 查看用户标签
```

**前端适配:**
- 检查用户是否有 `MANAGE_TAGS` 权限
- 显示"标签管理"和"兑换码管理"菜单项

---

## 三、前端代码修改指南

### 3.1 权限常量定义 (建议统一管理)

```typescript
// src/constants/permissions.ts
export const PERMISSIONS = {
  MANAGE_POSTS: 'MANAGE_POSTS',           // 帖子管理
  MANAGE_FEATURED: 'MANAGE_FEATURED',     // 精华管理
  MANAGE_COMMENTS: 'MANAGE_COMMENTS',     // 评论管理
  MANAGE_USERS: 'MANAGE_USERS',           // 用户管理
  MANAGE_ANNOUNCEMENTS: 'MANAGE_ANNOUNCEMENTS', // 公告管理
  MANAGE_TAGS: 'MANAGE_TAGS',             // 标签管理
} as const;

// 废弃权限 (仅用于迁移提示)
export const DEPRECATED_PERMISSIONS = {
  HIDE_POST: 'HIDE_POST',         // → MANAGE_POSTS
  DELETE_POST: 'DELETE_POST',     // → MANAGE_POSTS
  EDIT_POST: 'EDIT_POST',         // → MANAGE_POSTS
  PIN_POST: 'PIN_POST',           // → MANAGE_FEATURED
  FEATURE_POST: 'FEATURE_POST',   // → MANAGE_FEATURED
};
```

---

### 3.2 权限检查工具函数

```typescript
// src/utils/permissions.ts
import { PERMISSIONS } from '@/constants/permissions';

interface User {
  is_superadmin: boolean;
  permissions: string[];
}

export function hasPermission(user: User | null, permission: string): boolean {
  if (!user) return false;
  if (user.is_superadmin) return true; // 超管拥有所有权限
  return user.permissions?.includes(permission) ?? false;
}

export function hasAnyPermission(user: User | null, permissions: string[]): boolean {
  if (!user) return false;
  if (user.is_superadmin) return true;
  return permissions.some(perm => user.permissions?.includes(perm));
}

export function hasAllPermissions(user: User | null, permissions: string[]): boolean {
  if (!user) return false;
  if (user.is_superadmin) return true;
  return permissions.every(perm => user.permissions?.includes(perm));
}
```

---

### 3.3 替换旧权限检查

#### 示例 1: 帖子管理按钮
```typescript
// ❌ 旧代码
const canHidePost = hasAnyPermission(user, ['HIDE_POST', 'DELETE_POST', 'EDIT_POST']);
const canDeletePost = hasPermission(user, 'DELETE_POST');

// ✅ 新代码
const canManagePosts = hasPermission(user, PERMISSIONS.MANAGE_POSTS);

// UI 渲染
{canManagePosts && (
  <>
    <Button onClick={handleApprove}>审核通过</Button>
    <Button onClick={handleReject}>审核拒绝</Button>
    <Button onClick={handleHide}>隐藏</Button>
    <Button onClick={handleDelete}>删除</Button>
  </>
)}
```

#### 示例 2: 精华/置顶按钮
```typescript
// ❌ 旧代码
const canPin = hasPermission(user, 'PIN_POST');
const canFeature = hasPermission(user, 'FEATURE_POST');

// ✅ 新代码
const canManageFeatured = hasPermission(user, PERMISSIONS.MANAGE_FEATURED);

// UI 渲染
{canManageFeatured && (
  <>
    <Button onClick={handlePin}>置顶</Button>
    <Button onClick={handleFeature}>精华</Button>
  </>
)}
```

#### 示例 3: 用户标签分配 (需要双权限)
```typescript
// ✅ 新代码: 需要同时拥有 MANAGE_USERS 和 MANAGE_TAGS
const canAssignTags = hasAllPermissions(user, [
  PERMISSIONS.MANAGE_USERS,
  PERMISSIONS.MANAGE_TAGS
]);

// UI 渲染
{canAssignTags && (
  <Button onClick={handleAssignTag}>分配标签</Button>
)}
```

---

### 3.4 菜单/路由权限配置

```typescript
// src/config/menu.ts
import { PERMISSIONS } from '@/constants/permissions';

export const adminMenus = [
  {
    key: 'posts',
    title: '帖子管理',
    icon: 'FileText',
    path: '/admin/posts',
    permission: PERMISSIONS.MANAGE_POSTS, // 替换旧的 HIDE_POST
  },
  {
    key: 'featured',
    title: '精华管理',
    icon: 'Star',
    path: '/admin/featured',
    permission: PERMISSIONS.MANAGE_FEATURED, // 替换旧的 PIN_POST/FEATURE_POST
  },
  {
    key: 'comments',
    title: '评论管理',
    icon: 'MessageSquare',
    path: '/admin/comments',
    permission: PERMISSIONS.MANAGE_COMMENTS,
  },
  {
    key: 'users',
    title: '用户管理',
    icon: 'Users',
    path: '/admin/users',
    permission: PERMISSIONS.MANAGE_USERS,
  },
  {
    key: 'announcements',
    title: '公告管理',
    icon: 'Bell',
    path: '/admin/announcements',
    permission: PERMISSIONS.MANAGE_ANNOUNCEMENTS,
  },
  {
    key: 'tags',
    title: '标签管理',
    icon: 'Tag',
    path: '/admin/tags',
    permission: PERMISSIONS.MANAGE_TAGS,
  },
];

// 菜单过滤函数
export function getAccessibleMenus(user: User | null) {
  return adminMenus.filter(menu => hasPermission(user, menu.permission));
}
```

---

### 3.5 权限分配界面

后端接口 `POST /api/users/:id/permissions` 保持不变,前端需更新可选权限列表:

```typescript
// src/pages/admin/UserPermissions.tsx
const availablePermissions = [
  { value: 'MANAGE_POSTS', label: '帖子管理', description: '审核、删除、隐藏帖子' },
  { value: 'MANAGE_FEATURED', label: '精华管理', description: '置顶、精华帖子' },
  { value: 'MANAGE_COMMENTS', label: '评论管理', description: '隐藏、删除评论' },
  { value: 'MANAGE_USERS', label: '用户管理', description: '修改信息、封禁用户' },
  { value: 'MANAGE_ANNOUNCEMENTS', label: '公告管理', description: '创建、修改、删除公告' },
  { value: 'MANAGE_TAGS', label: '标签管理', description: '标签CRUD + 兑换码管理' },
];

// 发送请求
const updatePermissions = (userId: string, permissions: string[]) => {
  return axios.post(`/api/users/${userId}/permissions`, { permissions });
};
```

---

## 四、数据库迁移

### 4.1 迁移脚本执行

```bash
# 执行迁移 (已生成脚本: scripts/migrate_permissions.sql)
sqlite3 lovewall.db < scripts/migrate_permissions.sql
```

### 4.2 迁移逻辑说明

1. 自动备份现有权限到 `user_permissions_backup` 表
2. 将拥有 `HIDE_POST/DELETE_POST/EDIT_POST` 的用户授予 `MANAGE_POSTS`
3. 将拥有 `PIN_POST/FEATURE_POST` 的用户授予 `MANAGE_FEATURED`
4. 软删除旧权限记录 (设置 `deleted_at`)

### 4.3 迁移后验证

```sql
-- 查看用户当前权限
SELECT user_id, GROUP_CONCAT(permission, ', ') as permissions
FROM user_permissions
WHERE deleted_at IS NULL
GROUP BY user_id;

-- 检查是否还有旧权限
SELECT COUNT(*) FROM user_permissions
WHERE permission IN ('HIDE_POST', 'DELETE_POST', 'EDIT_POST', 'PIN_POST', 'FEATURE_POST')
  AND deleted_at IS NULL;
-- 应该返回 0
```

---

## 五、兼容性处理

### 5.1 后端兼容性
- ✅ 后端已完全移除旧权限,不存在兼容问题
- ✅ 所有接口权限检查已更新

### 5.2 前端兼容性建议

如果前端需要平滑过渡,可临时映射:

```typescript
// src/utils/permissionCompat.ts (可选,仅用于过渡期)
function normalizePermission(oldPermission: string): string {
  const mapping: Record<string, string> = {
    'HIDE_POST': 'MANAGE_POSTS',
    'DELETE_POST': 'MANAGE_POSTS',
    'EDIT_POST': 'MANAGE_POSTS',
    'PIN_POST': 'MANAGE_FEATURED',
    'FEATURE_POST': 'MANAGE_FEATURED',
  };
  return mapping[oldPermission] ?? oldPermission;
}

// 使用示例
export function hasPermissionCompat(user: User | null, permission: string): boolean {
  const normalizedPerm = normalizePermission(permission);
  return hasPermission(user, normalizedPerm);
}
```

---

## 六、常见问题 FAQ

### Q1: 为什么要合并权限?
**A:** 旧系统的5个帖子权限(`HIDE_POST`, `DELETE_POST`, `EDIT_POST`, `PIN_POST`, `FEATURE_POST`)过于分散,实际使用中很少需要细分到"只能隐藏但不能删除"的程度。新系统按功能模块划分更清晰。

### Q2: 超级管理员还有所有权限吗?
**A:** 是的。`is_superadmin: true` 的用户无需任何权限记录,自动拥有所有权限。

### Q3: 如何给用户分配标签?
**A:** 必须同时拥有 `MANAGE_USERS` 和 `MANAGE_TAGS` 权限才能调用 `POST /api/admin/users/:id/tags/:tag_id` 接口。

### Q4: 旧权限的数据会丢失吗?
**A:** 不会。迁移脚本会软删除(设置 `deleted_at`),并在 `user_permissions_backup` 表中备份。

### Q5: 前端需要重新登录吗?
**A:** 不需要。用户的权限在数据库中已更新,下次刷新页面时会获取新权限列表。

---

## 七、总结检查清单

前端开发者请逐项确认:

- [ ] 已更新权限常量定义 (`PERMISSIONS`)
- [ ] 已替换所有旧权限检查逻辑
- [ ] 已更新管理后台菜单配置
- [ ] 已更新权限分配界面的可选项
- [ ] 已测试"帖子管理"功能 (`MANAGE_POSTS`)
- [ ] 已测试"精华管理"功能 (`MANAGE_FEATURED`)
- [ ] 已测试用户标签分配的双权限校验
- [ ] 已删除代码中所有对废弃权限的引用
- [ ] 已更新相关文档/注释

---

## 联系方式

如有疑问,请联系后端开发团队或查看:
- 后端迁移脚本: `scripts/migrate_permissions.sql`
- 权限检查中间件: `internal/http/middleware/middleware.go`
- API 路由定义: `cmd/server/main.go`
