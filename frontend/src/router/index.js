import { createRouter, createWebHistory } from 'vue-router'
import { getRole, getUser } from '../utils/auth'
import WebPowerShell from '../views/WebPowerShell.vue'

const routes = [
  {
    path: '/',
    component: () => import('../layouts/DefaultLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        redirect: '/dashboard'
      },
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('../components/Dashboard.vue'),
        meta: {
          title: '仪表盘',
          icon: 'DataAnalysis',
          requiresAuth: true,
          roles: ['admin', 'operator', 'auditor']
        }
      },
      {
        path: 'assets',
        name: 'Assets',
        component: () => import('../components/AssetList.vue'),
        meta: {
          title: '资产管理',
          icon: 'Monitor',
          requiresAuth: true,
          roles: ['admin', 'operator']
        }
      },
      {
        path: 'sessions',
        name: 'Sessions',
        component: () => import('../views/SessionPlayback.vue'),
        meta: {
          title: '会话审计',
          icon: 'VideoCamera',
          requiresAuth: true,
          roles: ['admin', 'auditor']
        }
      },
      {
        path: 'rotation-history/:assetId?',
        name: 'RotationHistory',
        component: () => import('../components/RotationHistory.vue'),
        meta: {
          title: '改密历史',
          icon: 'Clock',
          requiresAuth: true,
          roles: ['admin', 'operator']
        }
      },
      {
        path: 'recycle-bin',
        name: 'RecycleBin',
        component: () => import('../components/RecycleBin.vue'),
        meta: {
          title: '回收站',
          icon: 'Delete',
          requiresAuth: true,
          roles: ['admin']
        }
      },
      {
        path: 'audit',
        name: 'Audit',
        component: () => import('../components/AuditLog.vue'),
        meta: {
          title: '审计日志',
          icon: 'Document',
          requiresAuth: true,
          roles: ['admin', 'auditor']
        }
      },
      {
        path: 'compliance',
        name: 'Compliance',
        component: () => import('../components/ComplianceReport.vue'),
        meta: {
          title: '合规报告',
          icon: 'CircleCheck',
          requiresAuth: true,
          roles: ['admin', 'auditor']
        }
      },
      {
        path: 'settings',
        name: 'SystemSettings',
        component: () => import('../views/SystemSettings.vue'),
        meta: {
          title: '系统设置',
          icon: 'Setting',
          requiresAuth: true,
          roles: ['admin']
        }
      },
      {
        path: 'profile',
        name: 'Profile',
        component: () => import('../views/Profile.vue'),
        meta: {
          title: '个人中心',
          icon: 'User',
          requiresAuth: true,
          roles: ['admin', 'operator', 'auditor']
        }
      },
      {
        path: 'winrm/:assetId',
        name: 'WebPowerShell',
        component: WebPowerShell,
        props: true,
        meta: {
          title: 'Web PowerShell',
          requiresAuth: true,
          roles: ['admin', 'operator']
        }
      }
    ]
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    meta: {
      title: '登录',
      requiresAuth: false,
      layout: 'blank'
    }
  },
  {
    path: '/mfa-setup',
    name: 'MfaSetup',
    component: () => import('../views/MfaSetup.vue'),
    meta: {
      title: 'MFA设置',
      requiresAuth: true,
      layout: 'blank'
    }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from, next) => {
  document.title = `${to.meta.title || 'PAM系统'} - PAM 特权账号管理系统`

  // 确保 localStorage 可用
  let token = null
  try {
    token = sessionStorage.getItem('token') || localStorage.getItem('token')
  } catch (error) {
    console.error('Error reading localStorage:', error)
  }
  
  const requiresAuth = to.meta.requiresAuth !== false
  const user = getUser()
  const role = getRole()
  
  // 增加更详细的日志，便于追踪 token 状态
  console.log('[Router] to:', to.path, 'token:', !!token, 'user:', user, 'role:', role);
  
  if (requiresAuth && !token) {
    console.log('Redirecting to login (no token)')
    next('/login')
  } else if (to.path === '/login' && token) {
    console.log('Redirecting to dashboard (already authenticated)')
    next('/dashboard')
  } else if (to.path === '/mfa-setup' && token) {
    // 已登录且有token的用户访问MFA设置页面
    if (user && user.totp_enabled) {
      console.log('MFA already enabled, redirecting to dashboard')
      next('/dashboard')
    } else {
      console.log('Proceeding to mfa-setup')
      next()
    }
  } else if (requiresAuth) {
    // 检查角色权限
    if (to.meta.roles) {
      console.log('Checking role:', { role, required: to.meta.roles })
      if (!to.meta.roles.includes(role)) {
        console.log('Role not allowed, redirecting to dashboard')
        next('/dashboard')
        return
      }
    }
    
    // 检查MFA绑定状态，增加容错
    if (to.path !== '/mfa-setup') {
      console.log('Checking MFA status:', { totp_enabled: user?.totp_enabled })
      // 仅当用户存在且 totp_enabled 明确为 false 时才重定向
      if (user && user.totp_enabled === false) {
        console.log('[Router] MFA not enabled, redirecting to /mfa-setup')
        next('/mfa-setup')
        return
      }
    }
    
    console.log('Proceeding to', to.path)
    next()
  } else {
    console.log('Proceeding to', to.path)
    next()
  }
})

export default router