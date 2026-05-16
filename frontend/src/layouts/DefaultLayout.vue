<template>
  <el-container style="height: 100vh; overflow: hidden;">
    <el-header height="60px" class="header">
      <div class="header-left">
        <el-button
          type="primary"
          circle
          plain
          @click="toggleSidebar"
          style="margin-right: 20px;"
        >
          <el-icon v-if="!isSidebarCollapsed"><Menu /></el-icon>
          <el-icon v-else><Close /></el-icon>
        </el-button>
        <div class="system-logo">
          <el-icon size="24"><Key /></el-icon>
        </div>
        <h1 class="system-title">PAM 特权账号管理系统</h1>
      </div>
      <div class="header-right">
        <div class="current-time">
          <el-icon><Clock /></el-icon>
          <span style="margin-left: 8px;">{{ currentTime }}</span>
        </div>
        <el-dropdown>
          <span class="user-info">
            <el-icon><User /></el-icon>
            <span style="margin-left: 8px;">{{ userName }}</span>
            <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item @click="router.push('/profile')">个人中心</el-dropdown-item>
              <el-dropdown-item divided @click="handleLogout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </el-header>

    <el-container>
      <el-aside
        :width="isSidebarCollapsed ? '64px' : '220px'"
        class="sidebar"
        :class="{ 'collapsed': isSidebarCollapsed }"
      >
        <div class="sidebar-logo">PAM 管理系统</div>
        <el-menu
          :default-active="activeMenu"
          class="sidebar-menu"
          @select="handleMenuSelect"
          :collapse="isSidebarCollapsed"
          background-color="#1e293b"
          text-color="#cbd5e1"
          active-text-color="#38bdf8"
        >
          <el-menu-item v-for="item in filteredMenuItems" :key="item.index" :index="item.index">
            <el-icon><component :is="item.icon" /></el-icon>
            <template #title>{{ item.title }}</template>
          </el-menu-item>
        </el-menu>
      </el-aside>

      <el-main class="main-content">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Menu, Monitor, VideoCamera, Clock, Document, DataAnalysis, User, ArrowDown, Close, Key, HomeFilled, CircleCheck, Delete } from '@element-plus/icons-vue'
import { getUser, getRole } from '../utils/auth'

const route = useRoute()
const router = useRouter()
const isSidebarCollapsed = ref(localStorage.getItem('sidebar-collapsed') === 'true')
const currentTime = ref('')
let timeInterval = null

// 侧边栏菜单配置
const menuItems = [
  {
    index: '/dashboard',
    icon: HomeFilled,
    title: '仪表盘',
    roles: ['admin', 'operator', 'auditor']
  },
  {
    index: '/profile',
    icon: User,
    title: '个人中心',
    roles: ['admin', 'operator', 'auditor']
  },
  {
    index: '/assets',
    icon: Monitor,
    title: '资产管理',
    roles: ['admin', 'operator']
  },
  {
    index: '/sessions',
    icon: VideoCamera,
    title: '会话审计',
    roles: ['admin', 'auditor']
  },
  {
    index: '/rotation-history',
    icon: Clock,
    title: '改密历史',
    roles: ['admin', 'operator']
  },
  {
    index: '/recycle-bin',
    icon: Delete,
    title: '回收站',
    roles: ['admin']
  },
  {
    index: '/audit',
    icon: Document,
    title: '审计日志',
    roles: ['admin', 'auditor']
  },
  {
    index: '/compliance',
    icon: CircleCheck,
    title: '合规报告',
    roles: ['admin', 'auditor']
  },
  {
    index: '/settings',
    icon: Key,
    title: '系统设置',
    roles: ['admin']
  }
]

// 根据角色过滤菜单
const filteredMenuItems = computed(() => {
  const role = getRole()
  return menuItems.filter(item => {
    return item.roles.includes(role)
  })
})

// 获取当前用户信息
const userInfo = computed(() => {
  return getUser()
})

// 获取用户名
const userName = computed(() => {
  return userInfo.value?.username || '管理员'
})

const activeMenu = computed(() => {
  return route.path
})

watch(isSidebarCollapsed, (newValue) => {
  localStorage.setItem('sidebar-collapsed', newValue)
})

const toggleSidebar = () => {
  isSidebarCollapsed.value = !isSidebarCollapsed.value
}

const handleMenuSelect = (key) => {
  router.push(key)
}

const handleLogout = () => {
  sessionStorage.removeItem('token')
  sessionStorage.removeItem('user')
  sessionStorage.removeItem('role')
  router.push('/login')
}

const updateCurrentTime = () => {
  const now = new Date()
  currentTime.value = now.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

onMounted(() => {
  updateCurrentTime()
  timeInterval = setInterval(updateCurrentTime, 1000)
})

onUnmounted(() => {
  if (timeInterval) {
    clearInterval(timeInterval)
  }
})
</script>

<style scoped>
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #ffffff;
  color: #1e293b;
  box-shadow: 0 2px 4px rgba(0,0,0,0.05);
  border-bottom: 1px solid #e2e8f0;
}

.header-left {
  display: flex;
  align-items: center;
}

.system-logo {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  background: linear-gradient(135deg, #38bdf8, #0ea5e9);
  border-radius: 10px;
  margin-right: 12px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.system-logo el-icon {
  color: #ffffff;
}

.system-title {
  margin: 0;
  font-size: 16px;
  font-weight: bold;
  letter-spacing: 0.5px;
  color: #1e293b;
}

.header-right {
  margin-right: 20px;
  display: flex;
  align-items: center;
  gap: 20px;
}

.header-right .current-time {
  color: #64748b;
  font-size: 13px;
}

.user-info {
  display: flex;
  align-items: center;
  cursor: pointer;
  color: #64748b;
  padding: 8px 16px;
  border-radius: 6px;
  transition: all 0.3s;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
}

.user-info:hover {
  background: #f1f5f9;
  border-color: #cbd5e1;
}

.sidebar {
  background-color: #1e293b;
  border-right: 1px solid #334155;
  transition: width 0.3s;
  box-shadow: 2px 0 8px rgba(0,0,0,0.1);
}

.sidebar-logo {
  height: 60px;
  line-height: 60px;
  text-align: center;
  font-size: 16px;
  font-weight: bold;
  background: #0f172a;
  color: #ffffff;
  border-bottom: 1px solid #334155;
}

.sidebar.collapsed {
  overflow: hidden;
}

.sidebar-menu {
  height: calc(100% - 60px);
  border-right: none;
  background-color: #1e293b;
}

.sidebar-menu:not(.el-menu--collapse) {
  width: 220px;
}

.main-content {
  background-color: #f1f5f9;
  padding: 20px;
  overflow: auto;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>