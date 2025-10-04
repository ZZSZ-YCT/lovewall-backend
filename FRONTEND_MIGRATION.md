# 权限系统重构 - 前端修改指南

## ✅ 后端已完成

权限系统已从 **8个分散权限** 重构为 **6个颗粒度权限**,并实现**自动迁移**。

---

## 一、权限变更对照表

| 旧权限 (已废弃) | 新权限 | 功能说明 |
|----------------|--------|----------|
| `HIDE_POST`<br>`DELETE_POST`<br>`EDIT_POST` | `MANAGE_POSTS` | **帖子管理**: 审核、删除、隐藏帖子 |
| `PIN_POST`<br>`FEATURE_POST` | `MANAGE_FEATURED` | **精华管理**: 置顶、精华帖子 |
| `MANAGE_COMMENTS` | `MANAGE_COMMENTS` | **评论管理**: 隐藏、删除评论 ✅保持不变 |
| `MANAGE_USERS` | `MANAGE_USERS` | **用户管理**: 封禁、修改信息 ✅保持不变 |
| `MANAGE_ANNOUNCEMENTS` | `MANAGE_ANNOUNCEMENTS` | **公告管理**: 创建、修改、删除公告 ✅保持不变 |
| `MANAGE_TAGS` | `MANAGE_TAGS` | **标签管理**: 标签CRUD + 兑换码管理 ✅保持不变 |

---

## 二、前端必须修改的代码

### 1️⃣ 更新权限常量定义

**文件位置**: `src/constants/permissions.ts` (或类似位置)

```typescript
// ✅ 新权限常量
export const PERMISSIONS = {
  MANAGE_POSTS: 'MANAGE_POSTS',              // 帖子管理
  MANAGE_FEATURED: 'MANAGE_FEATURED',        // 精华管理
  MANAGE_COMMENTS: 'MANAGE_COMMENTS',        // 评论管理
  MANAGE_USERS: 'MANAGE_USERS',              // 用户管理
  MANAGE_ANNOUNCEMENTS: 'MANAGE_ANNOUNCEMENTS', // 公告管理
  MANAGE_TAGS: 'MANAGE_TAGS',                // 标签管理
} as const;

// ❌ 删除这些旧常量
// HIDE_POST, DELETE_POST, EDIT_POST, PIN_POST, FEATURE_POST
```

---

### 2️⃣ 替换所有权限检查逻辑

#### 示例 1: 帖子管理按钮

```typescript
// ❌ 旧代码 (删除)
const canHidePost = hasPermission(user, 'HIDE_POST');
const canDeletePost = hasPermission(user, 'DELETE_POST');
const canEditPost = hasPermission(user, 'EDIT_POST');

// ✅ 新代码 (统一使用 MANAGE_POSTS)
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

#### 示例 2: 置顶/精华按钮

```typescript
// ❌ 旧代码 (删除)
const canPin = hasPermission(user, 'PIN_POST');
const canFeature = hasPermission(user, 'FEATURE_POST');

// ✅ 新代码 (统一使用 MANAGE_FEATURED)
const canManageFeatured = hasPermission(user, PERMISSIONS.MANAGE_FEATURED);

// UI 渲染
{canManageFeatured && (
  <>
    <Button onClick={handlePin}>置顶</Button>
    <Button onClick={handleFeature}>精华</Button>
  </>
)}
```

---

### 3️⃣ 更新管理后台菜单配置

```typescript
// src/config/menu.ts
import { PERMISSIONS } from '@/constants/permissions';

export const adminMenus = [
  {
    key: 'posts',
    title: '帖子管理',
    icon: 'FileText',
    path: '/admin/posts',
    permission: PERMISSIONS.MANAGE_POSTS, // ✅ 替换旧的 HIDE_POST
  },
  {
    key: 'featured',
    title: '精华管理',
    icon: 'Star',
    path: '/admin/featured',
    permission: PERMISSIONS.MANAGE_FEATURED, // ✅ 替换旧的 PIN_POST/FEATURE_POST
  },
  {
    key: 'comments',
    title: '评论管理',
    icon: 'MessageSquare',
    path: '/admin/comments',
    permission: PERMISSIONS.MANAGE_COMMENTS, // ✅ 保持不变
  },
  {
    key: 'users',
    title: '用户管理',
    icon: 'Users',
    path: '/admin/users',
    permission: PERMISSIONS.MANAGE_USERS, // ✅ 保持不变
  },
  {
    key: 'announcements',
    title: '公告管理',
    icon: 'Bell',
    path: '/admin/announcements',
    permission: PERMISSIONS.MANAGE_ANNOUNCEMENTS, // ✅ 保持不变
  },
  {
    key: 'tags',
    title: '标签管理',
    icon: 'Tag',
    path: '/admin/tags',
    permission: PERMISSIONS.MANAGE_TAGS, // ✅ 保持不变
  },
];

// 菜单过滤函数
export function getAccessibleMenus(user: User | null) {
  return adminMenus.filter(menu => hasPermission(user, menu.permission));
}
```

---

### 4️⃣ 更新权限分配界面

后端接口 `POST /api/users/:id/permissions` 保持不变,前端需更新可选权限列表:

```typescript
// src/pages/admin/UserPermissions.tsx
const availablePermissions = [
  {
    value: 'MANAGE_POSTS',
    label: '帖子管理',
    description: '审核、删除、隐藏帖子'
  },
  {
    value: 'MANAGE_FEATURED',
    label: '精华管理',
    description: '置顶、精华帖子'
  },
  {
    value: 'MANAGE_COMMENTS',
    label: '评论管理',
    description: '隐藏、删除评论'
  },
  {
    value: 'MANAGE_USERS',
    label: '用户管理',
    description: '修改信息、封禁用户'
  },
  {
    value: 'MANAGE_ANNOUNCEMENTS',
    label: '公告管理',
    description: '创建、修改、删除公告'
  },
  {
    value: 'MANAGE_TAGS',
    label: '标签管理',
    description: '标签CRUD + 兑换码管理'
  },
];

// 发送请求
const updatePermissions = (userId: string, permissions: string[]) => {
  return axios.post(`/api/users/${userId}/permissions`, { permissions });
};
```

---

### 5️⃣ 特殊规则: 用户标签分配需要双权限

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

**工具函数实现**:

```typescript
// src/utils/permissions.ts
export function hasAllPermissions(user: User | null, permissions: string[]): boolean {
  if (!user) return false;
  if (user.is_superadmin) return true; // 超管拥有所有权限
  return permissions.every(perm => user.permissions?.includes(perm));
}
```

---

## 三、全局搜索替换建议

使用 IDE 全局搜索替换以下内容:

| 搜索内容 | 替换为 | 说明 |
|---------|-------|------|
| `'HIDE_POST'` | `PERMISSIONS.MANAGE_POSTS` | 隐藏帖子权限 |
| `'DELETE_POST'` | `PERMISSIONS.MANAGE_POSTS` | 删除帖子权限 |
| `'EDIT_POST'` | `PERMISSIONS.MANAGE_POSTS` | 编辑帖子权限 |
| `'PIN_POST'` | `PERMISSIONS.MANAGE_FEATURED` | 置顶权限 |
| `'FEATURE_POST'` | `PERMISSIONS.MANAGE_FEATURED` | 精华权限 |

⚠️ **注意**: 如果有多个权限的 `OR` 检查,需要合并为单个新权限:

```typescript
// ❌ 旧代码
if (hasAnyPermission(user, ['HIDE_POST', 'DELETE_POST', 'EDIT_POST'])) {
  // ...
}

// ✅ 新代码
if (hasPermission(user, PERMISSIONS.MANAGE_POSTS)) {
  // ...
}
```

---

## 四、迁移自动执行 (无需手动操作)

✅ **后端已实现自动迁移逻辑** (`internal/db/db.go`)

- 服务启动时自动检查是否有旧权限
- 自动将旧权限转换为新权限
- 旧权限软删除 (不会丢失数据)

**无需执行任何 SQL 脚本**,重启服务即可完成迁移。

---

## 五、验证迁移成功

### 后端验证 (可选)

```bash
# 检查是否还有旧权限 (应该返回 0)
sqlite3 lovewall.db "SELECT COUNT(*) FROM user_permissions WHERE permission IN ('HIDE_POST', 'DELETE_POST', 'EDIT_POST', 'PIN_POST', 'FEATURE_POST') AND deleted_at IS NULL;"
```

### 前端验证

1. 登录管理后台
2. 检查用户权限列表是否显示新权限名称
3. 测试权限分配功能是否正常
4. 验证各管理菜单是否正常显示/隐藏

---

## 六、总结检查清单

前端开发者请逐项确认:

- [ ] 已更新权限常量定义 (`PERMISSIONS`)
- [ ] 已删除所有旧权限常量引用 (`HIDE_POST`, `DELETE_POST`, `EDIT_POST`, `PIN_POST`, `FEATURE_POST`)
- [ ] 已替换所有权限检查逻辑
- [ ] 已更新管理后台菜单配置
- [ ] 已更新权限分配界面的可选项
- [ ] 已测试"帖子管理"功能 (`MANAGE_POSTS`)
- [ ] 已测试"精华管理"功能 (`MANAGE_FEATURED`)
- [ ] 已测试用户标签分配的双权限校验
- [ ] 已验证超级管理员权限正常

---

## 七、API 变更说明

**✅ 所有 API 接口保持不变,仅权限检查逻辑变化**

| API | 旧权限 | 新权限 |
|-----|-------|-------|
| `POST /api/posts/:id/hide` | `HIDE_POST` | `MANAGE_POSTS` |
| `DELETE /api/posts/:id` | `DELETE_POST` | `MANAGE_POSTS` |
| `POST /api/posts/:id/pin` | `PIN_POST` | `MANAGE_FEATURED` |
| `POST /api/posts/:id/feature` | `FEATURE_POST` | `MANAGE_FEATURED` |
| `POST /api/admin/posts/:id/approve` | 5个权限之一 | `MANAGE_POSTS` |
| `POST /api/admin/posts/:id/reject` | 5个权限之一 | `MANAGE_POSTS` |
| `GET /api/posts/moderation` | 5个权限之一 | `MANAGE_POSTS` |

---