import axios from 'axios'
import { ElMessage } from 'element-plus'
import router from '../router'

const request = axios.create({
  baseURL: '/api',
  timeout: 30000
})

request.interceptors.request.use(
  config => {
    const token = sessionStorage.getItem('token') || localStorage.getItem('token')
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`
    }
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

request.interceptors.response.use(
  response => {
    return response.data
  },
  error => {
    if (error.response) {
      const { status, data } = error.response
      const requestPath = error.config.url

      if (status === 401) {
        if (data.message && data.message.includes('SM2')) {
          return Promise.reject(error)
        }
        if (requestPath !== '/auth/login') {
          localStorage.removeItem('token')
          localStorage.removeItem('user')
        }
        ElMessage.error(data.message || '认证失败，请重新登录')
        if (router.currentRoute.value.path !== '/login') {
          router.push('/login')
        }
      } else if (status === 403) {
        // 仅对写操作(POST/PUT/DELETE)显示权限提示，读操作(GET)静默失败
        // 避免 dashboard/proxy 等聚合页面在无权限时弹框干扰
        const method = error.config.method?.toLowerCase() || ''
        if (method !== 'get') {
          ElMessage.warning(data.message || '权限不足')
        }
      } else if (status === 404) {
        ElMessage.error(data.message || '请求的资源不存在')
      } else if (status === 422) {
        ElMessage.error(data.message || '请求参数校验失败')
      } else if (status === 429) {
        ElMessage.error(data.message || '操作过于频繁，请稍后再试')
      } else if (status === 502) {
        ElMessage.error('网络连接失败，请检查后端服务是否启动')
      } else if (status >= 500) {
        ElMessage.error(data.message || '服务器错误，请稍后重试')
      }
    } else if (error.code === 'ECONNABORTED') {
      ElMessage.error('请求超时，请检查网络连接')
    } else {
      ElMessage.error('网络连接失败，请检查后端服务是否启动')
    }

    return Promise.reject(error)
  }
)

export default request
