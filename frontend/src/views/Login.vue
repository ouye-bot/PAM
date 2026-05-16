<template>
  <div class="login-container">
    <div class="login-background">
      <div class="background-gradient"></div>
      <div class="background-grid"></div>
      <div class="background-glow"></div>
    </div>

    <div class="login-card">
      <div class="login-header">
        <div class="logo-container">
          <div class="logo-glow"></div>
          <el-icon class="logo-icon"><Key /></el-icon>
        </div>
        <h1 class="system-name">PAM 特权账号管理系统</h1>
        <p class="system-subtitle">Privileged Account Management</p>
      </div>

      <!-- 密码登录表单 -->
      <el-form
        v-if="!showMFAStep"
        ref="loginFormRef"
        :model="loginForm"
        :rules="loginRules"
        class="login-form"
        @submit.prevent="handleLogin"
      >
        <el-form-item prop="username">
          <el-input
            v-model="loginForm.username"
            placeholder="请输入用户名"
            size="large"
            :prefix-icon="User"
            clearable
            class="custom-input"
          />
        </el-form-item>

        <el-form-item prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            placeholder="请输入密码"
            size="large"
            :prefix-icon="Lock"
            show-password
            clearable
            @keyup.enter="handleLogin"
            class="custom-input"
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="loading"
            class="login-button"
            @click="handleLogin"
          >
            {{ loading ? '登录中...' : '登 录' }}
          </el-button>
        </el-form-item>

        <div class="device-lost-link">
          <el-button type="text" @click="openRecoveryDialog" class="lost-link-btn">
            设备丢失？
          </el-button>
        </div>
      </el-form>

      <!-- MFA验证表单 -->
      <div v-else class="mfa-form">
        <h3 class="mfa-title">
          <el-icon class="mfa-icon"><Key /></el-icon>
          多因子认证
        </h3>
        <p class="mfa-desc">
          请输入Google Authenticator或Authy生成的6位动态码
        </p>
        
        <el-form
          ref="mfaFormRef"
          :model="mfaForm"
          :rules="mfaRules"
          class="mfa-input-form"
          @submit.prevent
        >
          <el-form-item prop="code">
            <el-input
              v-model="mfaForm.code"
              placeholder="请输入6位动态码"
              size="large"
              maxlength="6"
              type="number"
              @keyup.enter="handleMFA"
              class="custom-input mfa-input"
            />
          </el-form-item>

          <el-form-item>
            <el-button
              type="primary"
              size="large"
              :loading="loading"
              class="login-button"
              @click="handleMFA"
              native-type="button"
            >
              {{ loading ? '验证中...' : '验 证' }}
            </el-button>
          </el-form-item>
        </el-form>

        <div class="mfa-actions">
          <el-button type="text" @click="backToPasswordLogin" class="back-button">
            ← 返回密码登录
          </el-button>
        </div>
      </div>

      <div class="login-footer">
        <div class="footer-divider"></div>
        <p class="security-tips">
          <el-icon class="security-icon"><Lock /></el-icon>
          <span>受保护的特权账号管理系统</span>
        </p>
      </div>
      <div class="version-info">PAM v{{ appVersion }}</div>
    </div>

    <!-- 设备丢失恢复弹窗 -->
    <el-dialog v-model="showRecoveryDialog" title="设备丢失 - SM2密钥恢复" width="420px" :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item label="用户名">
          <el-input v-model="recoveryForm.username" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item label="恢复码">
          <el-input
            v-model="recoveryForm.recoveryCode"
            type="text"
            placeholder="请输入恢复码"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showRecoveryDialog = false">取消</el-button>
        <el-button type="primary" :loading="recoveryLoading" @click="submitRecovery">
          {{ recoveryLoading ? '提交中...' : '确认恢复' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { User, Lock, Key } from '@element-plus/icons-vue'
import request from '../utils/request'
import { getUser, getToken, logout } from '../utils/auth'
import smCrypto from 'sm-crypto'
import bcryptjs from 'bcryptjs'
import { version } from '../../package.json'

const { sm2, sm4 } = smCrypto

const appVersion = version

const router = useRouter()
const loginFormRef = ref()
const mfaFormRef = ref()
const loading = ref(false)
const showMFAStep = ref(false)
const tempToken = ref('')
const sm2SetupLoading = ref(false)

const loginForm = reactive({
  username: '',
  password: ''
})

const mfaForm = reactive({
  code: ''
})

const loginRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' }
  ]
}

const mfaRules = {
  code: [
    { required: true, message: '请输入6位动态码', trigger: 'blur' },
    { len: 6, message: '动态码为6位数字', trigger: 'blur' }
  ]
}

const bytesToHex = (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')

const hexToBase64 = (hex) => {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
  return btoa(String.fromCharCode(...bytes))
}

const deriveSM4Key = async (password, salt) => {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  )
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 128
  )
  return bytesToHex(new Uint8Array(derivedBits))
}

const encryptPrivateKey = async (privateKeyHex, password) => {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const sm4KeyHex = await deriveSM4Key(password, salt)
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const ivHex = bytesToHex(iv)
  const ciphertextHex = sm4.encrypt(privateKeyHex, sm4KeyHex, { iv: ivHex })
  const saltHex = bytesToHex(salt)
  return `${saltHex}:${ivHex}:${ciphertextHex}`
}

const autoSetupSm2Key = async (token, userId) => {
  const encryptedData = localStorage.getItem('sm2_encrypted_private_key')
  if (encryptedData) {
    return
  }

  sm2SetupLoading.value = true
  try {
    const keypair = sm2.generateKeyPairHex()
    const privateKeyHex = keypair.privateKey
    let publicKeyHex = keypair.publicKey
    if (publicKeyHex.length === 130 && publicKeyHex.startsWith('04')) {
      publicKeyHex = publicKeyHex.substring(2)
    }
    const publicKeyBytes = new Uint8Array(publicKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
    const publicKeyB64 = btoa(String.fromCharCode(...publicKeyBytes))

    const encrypted = await encryptPrivateKey(privateKeyHex, loginForm.password)
    localStorage.setItem('sm2_encrypted_private_key', encrypted)

    const uploadRes = await request.put('/me/sm2-key', { public_key: publicKeyB64 })
    if (uploadRes.code !== 200) {
      ElMessage.error('SM2公钥上传失败: ' + (uploadRes.message || '未知错误'))
      return
    }

    const codes = []
    for (let i = 0; i < 10; i++) {
      codes.push(crypto.randomUUID())
    }
    const hashedCodes = await Promise.all(codes.map(c => bcryptjs.hash(c, 10)))
    await request.post('/me/sm2-recovery-codes', { recovery_hashes: hashedCodes })

    localStorage.setItem('sm2_recovery_codes_generated', '1')
    ElMessage.success('SM2密钥已自动配置，设备认证已启用')
  } catch (e) {
    console.warn('SM2密钥自动配置失败:', e)
    ElMessage.warning('SM2密钥自动配置未完成，可在个人中心手动配置')
  } finally {
    sm2SetupLoading.value = false
  }
}

const tryDecryptPrivateKey = async (password, encryptedData) => {
  const [saltHex, ivHex, ciphertextHex] = encryptedData.split(':')
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
  const sm4KeyHex = await deriveSM4Key(password, salt)
  return sm4.decrypt(ciphertextHex, sm4KeyHex, { iv: ivHex })
}

const handleLogin = async () => {
  if (!loginFormRef.value) return

  await loginFormRef.value.validate(async (valid) => {
    if (!valid) return

    loading.value = true

    let sm2Available = false
    const encryptedData = localStorage.getItem('sm2_encrypted_private_key')
    if (encryptedData) {
      try {
        await tryDecryptPrivateKey(loginForm.password, encryptedData)
        sm2Available = true
      } catch (e) {
        sm2Available = false
      }
    }

    try {
      const response = await request.post('/auth/login', {
        username: loginForm.username,
        password: loginForm.password,
        sm2_available: sm2Available
      })

      if (response.code === 200) {
        if (response.require_mfa) {
          if (response.sm2_auto_configured && response.encrypted_private_key) {
            localStorage.setItem('sm2_encrypted_private_key', response.encrypted_private_key)
          }
          tempToken.value = response.temp_token
          showMFAStep.value = true
        } else if (response.require_sm2 && response.challenge) {
          let privateKey
          try {
            privateKey = await tryDecryptPrivateKey(loginForm.password, encryptedData)
          } catch (e) {
            ElMessage.error('SM2私钥解密失败')
            loading.value = false
            return
          }
          let signature
          try {
            const signatureHex = sm2.doSignature(response.challenge, privateKey, { hash: true })
            signature = hexToBase64(signatureHex)
          } finally {
            privateKey = null
          }
          try {
            const sm2Response = await request.post('/auth/sm2/verify', {
              sm2_token: response.sm2_token,
              signature: signature
            })
            if (sm2Response.code === 200) {
              if (sm2Response.require_mfa) {
                tempToken.value = sm2Response.temp_token
                showMFAStep.value = true
              } else {
                sessionStorage.setItem('token', sm2Response.token)
                sessionStorage.setItem('user', JSON.stringify(sm2Response.user))
                ElMessage.success('登录成功')
                await autoSetupSm2Key(sm2Response.token, sm2Response.user?.id)
                if (sm2Response.user && !sm2Response.user.totp_enabled) {
                  router.push('/mfa-setup')
                } else {
                  router.push('/dashboard')
                }
              }
            } else {
              // SM2验证失败（密钥可能已过期），清除旧密钥并重试
              localStorage.removeItem('sm2_encrypted_private_key')
              ElMessage.warning('SM2密钥已过期，正在重新认证...')
              loading.value = false
              await handleLogin()
              return
            }
          } catch (error) {
            // SM2请求失败，清除旧密钥并重试
            localStorage.removeItem('sm2_encrypted_private_key')
            ElMessage.warning('SM2认证失败，正在重新认证...')
            loading.value = false
            await handleLogin()
            return
          }
        } else {
          sessionStorage.setItem('token', response.token)
          sessionStorage.setItem('user', JSON.stringify(response.user))
          if (response.sm2_auto_configured && response.encrypted_private_key) {
            localStorage.setItem('sm2_encrypted_private_key', response.encrypted_private_key)
          }
          ElMessage.success('登录成功')
          await autoSetupSm2Key(response.token, response.user?.id)

          if (response.user && !response.user.totp_enabled) {
            router.push('/mfa-setup')
          } else {
            router.push('/dashboard')
          }
        }
      } else {
        ElMessage.error(response.message || '登录失败')
      }
    } catch (error) {
      const errMsg = error.response?.data?.message || ''
      if (errMsg.includes('当前设备未绑定SM2私钥') || errMsg.includes('设备丢失')) {
        ElMessageBox.confirm(
          '当前设备未绑定SM2私钥，是否进行设备恢复？',
          '设备丢失',
          { confirmButtonText: '设备恢复', cancelButtonText: '取消', type: 'warning' }
        ).then(() => {
          openRecoveryDialog()
        }).catch(() => {})
      } else {
        ElMessage.error(errMsg || '登录失败，请稍后重试')
      }
      console.error('Login error:', error)
    } finally {
      loading.value = false
    }
  })
}

const handleMFA = async () => {
  if (!mfaFormRef.value) return

  await mfaFormRef.value.validate(async (valid) => {
    if (!valid) return

    loading.value = true
    try {
      const response = await request.post('/auth/mfa/login', {
        temp_token: tempToken.value,
        code: mfaForm.code
      })

      if (response.code === 200) {
        if (!response.token || !response.user) {
          ElMessage.error('登录响应格式错误')
          loading.value = false
          return
        }

        sessionStorage.clear()
        sessionStorage.setItem('token', response.token)
        const userData = { ...response.user, totp_enabled: true }
        sessionStorage.setItem('user', JSON.stringify(userData))
        sessionStorage.setItem('role', response.user.role)

        ElMessage.success('登录成功')
        await autoSetupSm2Key(response.token, response.user?.id)

        setTimeout(() => {
          router.push('/dashboard')
        }, 200)
      } else {
        ElMessage.error(response.message || '验证失败')
      }
    } catch (error) {
      ElMessage.error('验证失败，请稍后重试')
    } finally {
      loading.value = false
    }
  })
}

// 返回密码登录
const backToPasswordLogin = () => {
  showMFAStep.value = false
  tempToken.value = ''
  mfaForm.code = ''
}

// 设备丢失恢复弹窗
const showRecoveryDialog = ref(false)
const recoveryForm = reactive({
  username: '',
  recoveryCode: ''
})
const recoveryLoading = ref(false)

const openRecoveryDialog = () => {
  recoveryForm.username = loginForm.username
  recoveryForm.recoveryCode = ''
  showRecoveryDialog.value = true
}

const submitRecovery = async () => {
  if (!recoveryForm.username.trim()) {
    ElMessage.warning('请输入用户名')
    return
  }
  if (!recoveryForm.recoveryCode.trim()) {
    ElMessage.warning('请输入恢复码')
    return
  }
  recoveryLoading.value = true
  try {
    const response = await request.post('/auth/sm2/reset', {
      username: recoveryForm.username,
      recovery_code: recoveryForm.recoveryCode
    })
    if (response.code === 200) {
      ElMessage.success('SM2密钥已重置，请重新登录')
      showRecoveryDialog.value = false
    } else {
      ElMessage.error(response.message || '恢复失败')
    }
  } catch (error) {
    ElMessage.error('恢复请求失败，请稍后重试')
  } finally {
    recoveryLoading.value = false
  }
}
</script>

<style scoped>
.login-container {
  width: 100vw;
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  overflow: hidden;
}

.login-background {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 0;
}

.background-gradient {
  position: absolute;
  width: 100%;
  height: 100%;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
}

.background-grid {
  position: absolute;
  width: 100%;
  height: 100%;
  background-image:
    linear-gradient(rgba(56, 189, 248, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(56, 189, 248, 0.04) 1px, transparent 1px);
  background-size: 60px 60px;
}

.background-glow {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 800px;
  height: 800px;
  background: radial-gradient(circle, rgba(14, 165, 233, 0.08) 0%, transparent 70%);
  animation: glowPulse 8s ease-in-out infinite;
}

@keyframes glowPulse {
  0%, 100% {
    opacity: 0.6;
    transform: translate(-50%, -50%) scale(1);
  }
  50% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1.1);
  }
}

.login-card {
  position: relative;
  z-index: 1;
  width: 440px;
  padding: 48px 44px;
  background: rgba(30, 41, 59, 0.85);
  border-radius: 24px;
  border: 1px solid rgba(56, 189, 248, 0.15);
  backdrop-filter: blur(40px);
  box-shadow:
    0 0 60px rgba(14, 165, 233, 0.15),
    0 0 100px rgba(14, 165, 233, 0.08),
    0 25px 50px rgba(0, 0, 0, 0.5),
    0 10px 30px rgba(0, 0, 0, 0.3),
    inset 0 1px 0 rgba(255, 255, 255, 0.05),
    inset 0 -1px 0 rgba(0, 0, 0, 0.2);
  animation: cardFloat 6s ease-in-out infinite;
}

@keyframes cardFloat {
  0%, 100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-8px);
  }
}

.login-header {
  text-align: center;
  margin-bottom: 40px;
}

.logo-container {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 80px;
  height: 80px;
  background: linear-gradient(145deg, #38bdf8, #0ea5e9);
  border-radius: 22px;
  margin-bottom: 24px;
  box-shadow:
    0 8px 32px rgba(56, 189, 248, 0.4),
    0 4px 16px rgba(56, 189, 248, 0.3),
    inset 0 2px 4px rgba(255, 255, 255, 0.3),
    inset 0 -2px 4px rgba(0, 0, 0, 0.2);
  animation: logoBreath 3s ease-in-out infinite;
}

.logo-glow {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 100px;
  height: 100px;
  background: radial-gradient(circle, rgba(56, 189, 248, 0.3) 0%, transparent 70%);
  animation: logoGlow 3s ease-in-out infinite;
  z-index: -1;
}

@keyframes logoBreath {
  0%, 100% {
    box-shadow:
      0 8px 32px rgba(56, 189, 248, 0.4),
      0 4px 16px rgba(56, 189, 248, 0.3),
      inset 0 2px 4px rgba(255, 255, 255, 0.3),
      inset 0 -2px 4px rgba(0, 0, 0, 0.2);
  }
  50% {
    box-shadow:
      0 8px 40px rgba(56, 189, 248, 0.5),
      0 4px 20px rgba(56, 189, 248, 0.4),
      inset 0 2px 4px rgba(255, 255, 255, 0.35),
      inset 0 -2px 4px rgba(0, 0, 0, 0.2);
  }
}

@keyframes logoGlow {
  0%, 100% {
    opacity: 0.6;
    transform: translate(-50%, -50%) scale(1);
  }
  50% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1.2);
  }
}

.logo-icon {
  font-size: 40px;
  color: white;
  filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.2));
}

.system-name {
  margin: 0;
  font-size: 26px;
  font-weight: bold;
  color: #f8fafc;
  letter-spacing: 2px;
  text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

.system-subtitle {
  margin: 10px 0 0;
  font-size: 13px;
  color: rgba(148, 163, 184, 0.8);
  letter-spacing: 3px;
}

.login-form {
  margin-top: 8px;
}

.login-form :deep(.el-form-item) {
  margin-bottom: 20px;
}

.login-form :deep(.el-input__wrapper) {
  padding: 14px 18px;
  border-radius: 14px;
  background: rgba(15, 23, 42, 0.6);
  border: 1px solid rgba(56, 189, 248, 0.1);
  box-shadow:
    inset 0 2px 4px rgba(0, 0, 0, 0.2),
    inset 0 1px 2px rgba(0, 0, 0, 0.1),
    0 1px 0 rgba(255, 255, 255, 0.02);
  transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

.login-form :deep(.el-input__wrapper:hover) {
  border-color: rgba(56, 189, 248, 0.3);
  background: rgba(15, 23, 42, 0.7);
  transform: translateY(-1px);
  box-shadow:
    inset 0 2px 4px rgba(0, 0, 0, 0.2),
    0 4px 12px rgba(14, 165, 233, 0.1);
}

.login-form :deep(.el-input__wrapper.is-focus) {
  border-color: rgba(56, 189, 248, 0.5);
  background: rgba(15, 23, 42, 0.8);
  box-shadow:
    inset 0 2px 4px rgba(0, 0, 0, 0.2),
    0 0 0 3px rgba(56, 189, 248, 0.15),
    0 4px 20px rgba(14, 165, 233, 0.2);
  transform: translateY(-2px);
}

.login-form :deep(.el-input__inner) {
  font-size: 15px;
  color: #e2e8f0;
}

.login-form :deep(.el-input__inner::placeholder) {
  color: rgba(148, 163, 184, 0.5);
}

.login-form :deep(.el-input__prefix .el-icon) {
  color: rgba(56, 189, 248, 0.6);
  font-size: 16px;
}

.login-button {
  width: 100%;
  height: 52px;
  font-size: 16px;
  font-weight: bold;
  letter-spacing: 6px;
  border-radius: 14px;
  background: linear-gradient(135deg, #38bdf8, #0ea5e9);
  border: none;
  color: white;
  position: relative;
  overflow: hidden;
  box-shadow:
    0 4px 20px rgba(56, 189, 248, 0.4),
    0 2px 8px rgba(56, 189, 248, 0.3),
    inset 0 1px 0 rgba(255, 255, 255, 0.2),
    inset 0 -1px 0 rgba(0, 0, 0, 0.1);
  transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

.login-button::before {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle, rgba(255, 255, 255, 0.3) 0%, transparent 60%);
  transform: translate(-50%, -50%) scale(0);
  opacity: 0;
  transition: all 0.6s ease;
}

.login-button:hover {
  transform: translateY(-3px);
  box-shadow:
    0 8px 30px rgba(56, 189, 248, 0.5),
    0 4px 12px rgba(56, 189, 248, 0.4),
    inset 0 1px 0 rgba(255, 255, 255, 0.25),
    inset 0 -1px 0 rgba(0, 0, 0, 0.1);
  animation: buttonPulse 2s ease-in-out infinite;
}

@keyframes buttonPulse {
  0%, 100% {
    box-shadow:
      0 8px 30px rgba(56, 189, 248, 0.5),
      0 4px 12px rgba(56, 189, 248, 0.4),
      inset 0 1px 0 rgba(255, 255, 255, 0.25),
      inset 0 -1px 0 rgba(0, 0, 0, 0.1);
  }
  50% {
    box-shadow:
      0 8px 40px rgba(56, 189, 248, 0.6),
      0 4px 16px rgba(56, 189, 248, 0.5),
      inset 0 1px 0 rgba(255, 255, 255, 0.3),
      inset 0 -1px 0 rgba(0, 0, 0, 0.1);
  }
}

.login-button:hover::before {
  transform: translate(-50%, -50%) scale(1);
  opacity: 1;
}

.login-button:active {
  transform: translateY(0);
  box-shadow:
    0 2px 10px rgba(56, 189, 248, 0.3),
    0 1px 4px rgba(56, 189, 248, 0.2),
    inset 0 1px 0 rgba(255, 255, 255, 0.15),
    inset 0 2px 4px rgba(0, 0, 0, 0.1);
}

.login-button:disabled {
  background: linear-gradient(135deg, #475569, #334155);
  box-shadow: none;
}

.login-footer {
  margin-top: 36px;
  text-align: center;
}

.footer-divider {
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.2), transparent);
  margin-bottom: 20px;
}

.security-tips {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: rgba(148, 163, 184, 0.6);
  font-size: 12px;
  transition: all 0.3s ease;
}

.security-tips:hover {
  color: rgba(148, 163, 184, 0.8);
  transform: translateY(-1px);
}

.security-icon {
  font-size: 12px;
  color: rgba(56, 189, 248, 0.5);
  animation: iconBreath 2s ease-in-out infinite;
}

@keyframes iconBreath {
  0%, 100% {
    opacity: 0.5;
  }
  50% {
    opacity: 0.8;
  }
}

/* MFA 相关样式 */
.mfa-form {
  margin-top: 8px;
}

.mfa-title {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  color: #f8fafc;
  font-size: 20px;
  font-weight: 600;
  margin-bottom: 12px;
}

.mfa-icon {
  color: #38bdf8;
  font-size: 20px;
}

.mfa-desc {
  color: rgba(148, 163, 184, 0.8);
  font-size: 14px;
  text-align: center;
  margin-bottom: 24px;
}

.mfa-input-form :deep(.el-form-item) {
  margin-bottom: 20px;
}

.mfa-input {
  text-align: center;
  font-size: 18px;
  letter-spacing: 2px;
}

.mfa-actions {
  margin-top: 16px;
  text-align: center;
}

.back-button {
  color: rgba(56, 189, 248, 0.8);
  transition: all 0.3s ease;
}

.back-button:hover {
  color: rgba(56, 189, 248, 1);
  transform: translateX(-2px);
}

.device-lost-link {
  text-align: right;
  margin-top: -12px;
  margin-bottom: 4px;
}

.lost-link-btn {
  color: rgba(148, 163, 184, 0.6);
  font-size: 12px;
  transition: all 0.3s ease;
}

.lost-link-btn:hover {
  color: rgba(56, 189, 248, 0.8);
}
.version-info {
  position: absolute;
  bottom: 16px;
  width: 100%;
  text-align: center;
  color: #999;
  font-size: 13px;
  letter-spacing: 1px;
}
</style>
