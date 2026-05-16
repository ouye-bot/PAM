<template>
  <div class="profile-container">
    <h2 class="page-title">个人中心</h2>

    <el-card class="profile-card">
      <template #header>
        <div class="card-header">
          <span>账户信息</span>
        </div>
      </template>
      <el-descriptions :column="1" border>
        <el-descriptions-item label="用户名">{{ userInfo.username }}</el-descriptions-item>
        <el-descriptions-item label="角色">{{ userInfo.role }}</el-descriptions-item>
        <el-descriptions-item label="SM2 公钥状态">
          <el-tag v-if="hasSm2Key" type="success">已配置</el-tag>
          <el-tag v-else type="danger">未配置</el-tag>
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card class="profile-card">
      <template #header>
        <div class="card-header">
          <span>SM2 密钥管理</span>
          <el-tag type="warning" size="small">安全认证</el-tag>
        </div>
      </template>

      <div v-if="hasSm2Key" class="key-status">
        <el-alert
          title="SM2 公钥已注册"
          type="success"
          :closable="false"
          show-icon
          description="您的 SM2 公钥已注册到系统，可用于终端会话的二次身份认证。"
        />
        <div v-if="!hasLocalPrivateKey" style="margin-top: 16px;">
          <el-alert
            title="本地私钥未找到"
            type="warning"
            :closable="false"
            show-icon
            description="检测到您未在本地浏览器中保存 SM2 私钥的加密副本，无法进行 Windows 资产堡垒机认证。请重新生成密钥对并确认账户密码。"
          />
          <el-button type="primary" style="margin-top: 12px;" @click="generateNewKeyWithPassword">
            生成新的密钥对
          </el-button>
        </div>
        <div class="public-key-display">
          <p class="key-label">当前公钥：</p>
          <el-input
            :model-value="maskedPublicKey"
            readonly
            type="textarea"
            :rows="2"
          />
        </div>
        <el-divider />
        <div class="recovery-status">
          <span class="key-label">恢复码状态：</span>
          <el-tag v-if="hasRecoveryCodes" type="success">已生成</el-tag>
          <el-tag v-else type="info">未生成</el-tag>
          <span class="recovery-hint" v-if="hasRecoveryCodes">恢复码在初次配置 SM2 密钥时展示</span>
          <span class="recovery-hint" v-else>重新生成密钥对时将生成恢复码</span>
        </div>
        <el-divider />
        <p class="regenerate-warning">重新生成密钥对将使旧密钥失效，旧私钥加密的所有会话将无法验证。</p>
        <el-button type="warning" @click="confirmRegenerate">重新生成密钥对</el-button>
      </div>

      <div v-else class="key-setup">
        <el-alert
          title="SM2 密钥未配置"
          type="warning"
          :closable="false"
          show-icon
          description="SM2 二次认证可增强终端会话安全性。请生成您的 SM2 密钥对，并妥善保管私钥。"
        />
        <div style="margin-top: 20px;">
          <el-button type="primary" size="large" @click="generateKeyPair" :loading="generating">
            生成 SM2 密钥对
          </el-button>
        </div>
      </div>

      <el-dialog
        v-model="showPrivateKeyDialog"
        title="SM2 私钥"
        width="560px"
        :close-on-click-modal="false"
      >
        <el-alert
          title="请立即保存您的私钥"
          type="danger"
          :closable="false"
          show-icon
          description="私钥仅显示一次，关闭后将无法再次查看。请立即复制并妥善保管（推荐使用密码管理器）。私钥是您身份的唯一凭证，泄露可能导致他人假冒您的身份。"
        />
        <div class="private-key-box">
          <el-input
            :model-value="generatedPrivateKey"
            readonly
            type="textarea"
            :rows="4"
          />
          <el-button type="primary" class="copy-btn" @click="copyPrivateKey">
            复制私钥
          </el-button>
        </div>
        <template #footer>
          <el-checkbox v-model="privateKeySaved" style="margin-bottom: 12px;">
            我已安全保存私钥
          </el-checkbox>
          <div>
            <el-button type="primary" :disabled="!privateKeySaved" @click="confirmKeySaved">
              确认完成
            </el-button>
          </div>
        </template>
      </el-dialog>

      <el-dialog
        v-model="showPasswordDialog"
        title="确认账户密码"
        width="420px"
        :close-on-click-modal="false"
        :close-on-press-escape="false"
        :show-close="false"
      >
        <p style="font-size: 14px; color: #475569; margin-bottom: 16px;">
          请输入您的账户密码，用于加密存储 SM2 私钥：
        </p>
        <el-form label-position="top">
          <el-form-item label="账户密码">
            <el-input v-model="resetPassword" type="password" show-password placeholder="请输入当前登录密码" @keydown.enter.prevent="confirmResetPassword" />
          </el-form-item>
        </el-form>
        <div v-if="resetPasswordError" style="color: #dc2626; font-size: 13px; padding: 8px 12px; background: #fef2f2; border-radius: 6px;">{{ resetPasswordError }}</div>
        <template #footer>
          <el-button @click="cancelResetPassword">取消</el-button>
          <el-button type="primary" :loading="verifyingPassword" @click="confirmResetPassword">生成密钥对</el-button>
        </template>
      </el-dialog>
    </el-card>

    <el-card class="profile-card">
      <template #header>
        <div class="card-header">
          <span>使用说明</span>
        </div>
      </template>
      <div class="usage-guide">
        <el-steps :active="3" direction="vertical">
          <el-step
            title="生成 SM2 密钥对"
            description="在此页面点击「生成 SM2 密钥对」，系统将生成一对 SM2 密钥。"
          />
          <el-step
            title="保存私钥"
            description="私钥仅显示一次，请立即复制并使用密码管理器或加密文件妥善保存。公钥将自动注册到系统。"
          />
          <el-step
            title="使用私钥认证"
            description="打开 Web PowerShell 终端时，输入此私钥完成 SM2 二次认证，方可建立会话。"
          />
        </el-steps>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getToken, getUser } from '../utils/auth'
import request from '../utils/request'
import smCrypto from 'sm-crypto'
import bcryptjs from 'bcryptjs'

const { sm2, sm4 } = smCrypto

const userInfo = ref(getUser() || { username: '未知', role: '未知' })
const hasSm2Key = ref(false)
const hasLocalPrivateKey = ref(false)
const hasRecoveryCodes = ref(false)
const publicKey = ref('')
const generating = ref(false)
const showPrivateKeyDialog = ref(false)
const generatedPrivateKey = ref('')
const privateKeySaved = ref(false)

const maskedPublicKey = ref('')

const showPasswordDialog = ref(false)
const resetPassword = ref('')
const resetPasswordError = ref('')
const verifyingPassword = ref(false)

const bytesToHex = (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')

const deriveKeyFromPassword = async (password, salt) => {
  const encoder = new TextEncoder()
  const actualSalt = salt || crypto.getRandomValues(new Uint8Array(16))
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'])
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: actualSalt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 128
  )
  return { salt: actualSalt, sm4KeyHex: bytesToHex(new Uint8Array(derivedBits)) }
}

const encryptPrivateKey = async (privateKeyHex, password) => {
  const { salt, sm4KeyHex } = await deriveKeyFromPassword(password)
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const ivHex = bytesToHex(iv)
  const ciphertextHex = sm4.encrypt(privateKeyHex, sm4KeyHex, { iv: ivHex })
  const saltHex = bytesToHex(salt)
  return `${saltHex}:${ivHex}:${ciphertextHex}`
}

const fetchSm2Status = async () => {
  try {
    const encryptedKey = localStorage.getItem('sm2_encrypted_private_key')
    hasLocalPrivateKey.value = !!encryptedKey
    hasRecoveryCodes.value = !!localStorage.getItem('sm2_recovery_codes_generated')

    const res = await request.get('/me/sm2-key')
    if (res.code === 200 && res.data && res.data.public_key) {
      hasSm2Key.value = true
      publicKey.value = res.data.public_key
      const raw = res.data.public_key
      maskedPublicKey.value = raw.length > 40 ? raw.substring(0, 20) + '...' + raw.substring(raw.length - 20) : raw
    } else {
      hasSm2Key.value = false
    }
  } catch (e) {
    hasSm2Key.value = false
  }
}

const generateKeyPair = async () => {
  generating.value = true
  try {
    const keypair = sm2.generateKeyPairHex()
    const privateKeyHex = keypair.privateKey
    let publicKeyHex = keypair.publicKey
    if (publicKeyHex.length === 130 && (publicKeyHex.startsWith('04') || publicKeyHex.startsWith('04'))) {
      publicKeyHex = publicKeyHex.substring(2)
    }

    const publicKeyBytes = new Uint8Array(publicKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
    const publicKeyB64 = btoa(String.fromCharCode(...publicKeyBytes))

    const res = await request.put('/me/sm2-key', {
      public_key: publicKeyB64
    })

    if (res.code === 200) {
      hasSm2Key.value = true
      publicKey.value = publicKeyB64
      const raw = publicKeyB64
      maskedPublicKey.value = raw.length > 40 ? raw.substring(0, 20) + '...' + raw.substring(raw.length - 20) : raw

      if (resetPassword.value) {
        const encryptedData = await encryptPrivateKey(privateKeyHex, resetPassword.value)
        localStorage.setItem('sm2_encrypted_private_key', encryptedData)
        hasLocalPrivateKey.value = true
      }

      const codes = []
      for (let i = 0; i < 10; i++) {
        codes.push(crypto.randomUUID())
      }
      try {
        const hashedCodes = await Promise.all(codes.map(c => bcryptjs.hash(c, 10)))
        await request.post('/me/sm2-recovery-codes', { recovery_hashes: hashedCodes })
        ElMessage.success('恢复码已保存')
      } catch (e) {
        console.warn('恢复码上传失败', e)
      }
      localStorage.setItem('sm2_recovery_codes_generated', '1')
      hasRecoveryCodes.value = true

      generatedPrivateKey.value = privateKeyHex
      privateKeySaved.value = false
      showPrivateKeyDialog.value = true
      ElMessage.success('SM2 密钥对生成成功，公钥已注册到系统')
    } else {
      ElMessage.error(res.message || '公钥注册失败')
    }
  } catch (e) {
    ElMessage.error('密钥生成失败: ' + (e.message || '未知错误'))
  } finally {
    generating.value = false
  }
}

const copyPrivateKey = async () => {
  try {
    await navigator.clipboard.writeText(generatedPrivateKey.value)
    ElMessage.success('私钥已复制到剪贴板')
    privateKeySaved.value = true
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = generatedPrivateKey.value
    document.body.appendChild(textarea)
    textarea.select()
    document.execCommand('copy')
    document.body.removeChild(textarea)
    ElMessage.success('私钥已复制到剪贴板')
    privateKeySaved.value = true
  }
}

const confirmKeySaved = () => {
  generatedPrivateKey.value = ''
  showPrivateKeyDialog.value = false
  ElMessage.success('SM2 密钥配置完成。打开 Web PowerShell 时请使用此私钥进行认证。')
}

const confirmRegenerate = () => {
  ElMessageBox.confirm(
    '重新生成密钥对将使旧密钥失效，旧私钥加密的所有会话将无法验证。确定继续？',
    '确认操作',
    {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    }
  ).then(() => {
    resetPassword.value = ''
    resetPasswordError.value = ''
    showPasswordDialog.value = true
  }).catch(() => {})
}

const validateResetPassword = () => {
  if (!resetPassword.value) return '请输入账户密码'
  return ''
}

const verifyPasswordWithServer = async (password) => {
  try {
    const res = await request.post('/auth/verify-password', { password })
    return res.valid === true
  } catch (e) {
    return false
  }
}

const confirmResetPassword = async () => {
  const pwError = validateResetPassword()
  if (pwError) {
    resetPasswordError.value = pwError
    return
  }
  resetPasswordError.value = ''
  verifyingPassword.value = true
  
  try {
    const valid = await verifyPasswordWithServer(resetPassword.value)
    if (!valid) {
      resetPasswordError.value = '密码错误，请重新输入'
      verifyingPassword.value = false
      return
    }
    
    showPasswordDialog.value = false
    await generateKeyPair()
    ElMessage.success('密钥对已重置。')
  } finally {
    verifyingPassword.value = false
  }
}

const cancelResetPassword = () => {
  showPasswordDialog.value = false
  resetPassword.value = ''
  resetPasswordError.value = ''
}

const generateNewKeyWithPassword = async () => {
  resetPassword.value = ''
  resetPasswordError.value = ''
  showPasswordDialog.value = true
}

onMounted(() => {
  fetchSm2Status()
})
</script>

<style scoped>
.profile-container {
  max-width: 800px;
  margin: 0 auto;
}

.page-title {
  font-size: 22px;
  margin-bottom: 24px;
  color: #1e293b;
}

.profile-card {
  margin-bottom: 20px;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-weight: bold;
}

.key-status, .key-setup {
  padding: 8px 0;
}

.public-key-display {
  margin-top: 16px;
}

.key-label {
  font-size: 13px;
  color: #64748b;
  margin-bottom: 8px;
}

.recovery-status {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.recovery-hint {
  font-size: 12px;
  color: #94a3b8;
}

.regenerate-warning {
  color: #dc2626;
  font-size: 13px;
  margin-bottom: 12px;
}

.private-key-box {
  margin-top: 16px;
  position: relative;
}

.copy-btn {
  margin-top: 8px;
}

.usage-guide {
  padding: 8px 0;
}
</style>