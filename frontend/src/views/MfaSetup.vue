<template>
  <div class="mfa-setup-container">
    <div class="mfa-card">
      <h2>MFA 多因子认证设置</h2>
      
      <div v-if="loading" class="loading-container">
        <el-icon class="is-loading"><Loading /></el-icon>
        <span>正在生成二维码...</span>
      </div>
      
      <div v-else class="mfa-content">
        <div class="qr-code-container">
          <h3>扫描二维码</h3>
          <div class="qr-code">
            <img v-if="qrBase64" :src="qrBase64" alt="MFA QR Code" />
            <div v-else class="qr-placeholder">
              <el-icon><View /></el-icon>
              <span>二维码加载失败</span>
            </div>
          </div>
          <p class="instructions">
            请使用 Google Authenticator 或 Authy 等TOTP应用扫描上方二维码
          </p>
        </div>
        
        <div class="verification-container">
          <h3>验证动态码</h3>
          <el-input
            v-model="verificationCode"
            placeholder="请输入6位动态码"
            maxlength="6"
            type="number"
            @keyup.enter="verifyMFA"
            class="code-input"
          />
          <el-button type="primary" @click="verifyMFA" :loading="verifying" class="verify-button">
            验证并启用
          </el-button>
        </div>
      </div>
      
      <div v-if="message" class="message" :class="messageType">
        {{ message }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElIcon } from 'element-plus'
import { Loading, View } from '@element-plus/icons-vue'
import request from '@/utils/request'
import { getUser } from '@/utils/auth'

const router = useRouter()

const loading = ref(true)
const verifying = ref(false)
const qrBase64 = ref('')
const verificationCode = ref('')
const message = ref('')
const messageType = ref('')

// 获取MFA设置信息
const getMFASetup = async () => {
  try {
    const response = await request.get('/auth/mfa/setup')
    if (response.code === 200) {
      qrBase64.value = response.qr_base64
      loading.value = false
    } else if (response.code === 400 && response.message === 'MFA already enabled') {
      // MFA已启用，直接跳转到仪表盘（先确保sessionStorage正确）
      updateSessionUser()
      showMessage('MFA已启用', 'info')
      setTimeout(() => {
        router.push('/dashboard')
      }, 1000)
    } else {
      showMessage(response.message, 'error')
      loading.value = false
    }
  } catch (error) {
    showMessage('获取MFA设置信息失败', 'error')
    loading.value = false
  }
}

// 更新 sessionStorage 中的用户 totp_enabled 状态，供 router guard 使用
const updateSessionUser = () => {
  try {
    const user = getUser()
    if (user) {
      user.totp_enabled = true
      sessionStorage.setItem('user', JSON.stringify(user))
    }
  } catch (error) {
    console.error('Error updating session user:', error)
  }
}

// 验证MFA动态码
const verifyMFA = async () => {
  if (!verificationCode.value || verificationCode.value.length !== 6) {
    showMessage('请输入6位动态码', 'warning')
    return
  }

  verifying.value = true
  try {
    const response = await request.post('/auth/mfa/verify', {
      code: verificationCode.value
    })

    if (response.code === 200) {
      showMessage('MFA已成功启用', 'success')

      // 更新 sessionStorage — router guard 依赖此值判断是否需要 MFA 设置
      updateSessionUser()

      // 跳转到仪表盘（使用 router.push 避免整页刷新）
      setTimeout(() => {
        router.push('/dashboard')
      }, 1500)
    } else {
      showMessage(response.message, 'error')
    }
  } catch (error) {
    showMessage('验证失败，请重试', 'error')
  } finally {
    verifying.value = false
  }
}

// 显示消息
const showMessage = (text, type = 'info') => {
  message.value = text
  messageType.value = type
  setTimeout(() => {
    message.value = ''
  }, 3000)
}

// 页面加载时获取MFA设置
onMounted(() => {
  // 检查用户是否已经启用MFA（使用 sessionStorage，与 router guard 一致）
  const user = getUser()
  if (user && user.totp_enabled) {
    router.push('/dashboard')
    return
  }

  // 未启用MFA，获取设置信息
  getMFASetup()
})
</script>

<style scoped>
.mfa-setup-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
  padding: 20px;
}

.mfa-card {
  background: rgba(255, 255, 255, 0.95);
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
  padding: 30px;
  width: 100%;
  max-width: 500px;
  text-align: center;
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.2);
}

.mfa-card h2 {
  color: #1e3c72;
  margin-bottom: 20px;
  font-size: 24px;
  font-weight: 600;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 40px 0;
  color: #1e3c72;
}

.loading-container .el-icon {
  font-size: 48px;
  margin-bottom: 10px;
}

.mfa-content {
  display: flex;
  flex-direction: column;
  gap: 30px;
}

.qr-code-container h3,
.verification-container h3 {
  color: #2a5298;
  margin-bottom: 15px;
  font-size: 18px;
  font-weight: 500;
}

.qr-code {
  display: flex;
  justify-content: center;
  margin: 20px 0;
  padding: 20px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.qr-code img {
  max-width: 200px;
  max-height: 200px;
}

.qr-placeholder {
  width: 200px;
  height: 200px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: #f5f7fa;
  border-radius: 8px;
  color: #909399;
}

.qr-placeholder .el-icon {
  font-size: 48px;
  margin-bottom: 10px;
}

.instructions {
  color: #606266;
  font-size: 14px;
  line-height: 1.5;
  margin-top: 10px;
}

.code-input {
  width: 200px;
  margin: 0 auto 20px;
  font-size: 18px;
  text-align: center;
}

.verify-button {
  width: 100%;
  padding: 12px;
  font-size: 16px;
  background: linear-gradient(135deg, #409eff, #66b1ff);
  border: none;
  transition: all 0.3s ease;
}

.verify-button:hover {
  background: linear-gradient(135deg, #66b1ff, #409eff);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(64, 158, 255, 0.4);
}

.message {
  margin-top: 20px;
  padding: 10px;
  border-radius: 4px;
  font-size: 14px;
  text-align: center;
}

.message.success {
  background: #f0f9eb;
  color: #67c23a;
  border: 1px solid #e1f3d8;
}

.message.error {
  background: #fef0f0;
  color: #f56c6c;
  border: 1px solid #fbc4c4;
}

.message.warning {
  background: #fdf6ec;
  color: #e6a23c;
  border: 1px solid #fde2a8;
}

@media (max-width: 768px) {
  .mfa-card {
    padding: 20px;
  }
  
  .qr-code img {
    max-width: 150px;
    max-height: 150px;
  }
  
  .qr-placeholder {
    width: 150px;
    height: 150px;
  }
}
</style>
