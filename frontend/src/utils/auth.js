import request from './request'
import { ElMessage } from 'element-plus'

const clearLegacyToken = () => {
  try {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
  } catch (e) {}
}

export const login = async (username, password) => {
  try {
    const response = await request.post('/auth/login', {
      username,
      password
    })

    if (response.code === 200 && response.token) {
      clearLegacyToken()
      sessionStorage.setItem('token', response.token)
      sessionStorage.setItem('user', JSON.stringify(response.user || { username }))
      return true
    } else {
      throw new Error(response.message || '登录失败')
    }
  } catch (error) {
    console.error('Login error:', error)
    throw error
  }
}

export const logout = () => {
  clearLegacyToken()
  sessionStorage.removeItem('token')
  sessionStorage.removeItem('user')
}

export const getToken = () => {
  return sessionStorage.getItem('token') || localStorage.getItem('token')
}

export const getUser = () => {
  const userStr = sessionStorage.getItem('user') || localStorage.getItem('user')
  return userStr ? JSON.parse(userStr) : null
}

export const getRole = () => {
  const user = getUser()
  return user ? user.role : null
}

export const isAuthenticated = () => {
  return !!getToken()
}