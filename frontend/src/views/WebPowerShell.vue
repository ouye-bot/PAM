<template>
  <div class="web-powershell-container">
    <div class="powershell-header">
      <div class="header-left">
        <h3>Web PowerShell - {{ assetName }}</h3>
        <el-tag v-if="connectionStatus" :type="connectionStatusType" size="small" class="status-tag">
          <span class="status-dot" :class="connectionStatusType"></span>
          {{ connectionStatus }}
        </el-tag>
      </div>
      <el-button type="danger" size="small" @click="closeTerminal">关闭会话</el-button>
    </div>
    <el-empty v-if="!sessionId"
              description="请先选择 Windows 资产建立连接"
              :image-size="120" />
    <div v-show="sessionId" class="terminal-placeholder">
      <span>Windows PowerShell | {{ assetName }}</span>
    </div>
    <div v-show="sessionId" ref="terminalContainer" class="terminal-container"></div>

    <el-dialog v-model="signDialogVisible" title="高危操作确认" width="420px" :close-on-click-modal="false" :close-on-press-escape="false" :show-close="false">
      <div>
        <p style="color:#dc2626;font-weight:bold;margin-bottom:12px;">此操作为高危命令，需要进行数字签名确认</p>
        <p style="color:#666;font-size:13px;margin-bottom:16px;">命令: {{ signCommand }}</p>
        <p style="color:#666;font-size:13px;margin-bottom:12px;">请登录密码以进行数字签名：</p>
        <el-input v-model="signPassword" type="password" show-password placeholder="请输入账户密码" @keydown.enter.prevent="submitSignPassword" />
        <div v-if="signError" style="color:#dc2626;font-size:12px;margin-top:8px;">{{ signError }}</div>
      </div>
      <template #footer>
        <el-button @click="cancelSign">取消</el-button>
        <el-button type="danger" :disabled="!signPassword.trim()" @click="submitSignPassword">确认签名</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, watch, onMounted, onUnmounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { io } from 'socket.io-client'
import { Terminal } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { sm2, sm4 } from 'sm-crypto'
import 'xterm/css/xterm.css'

const router = useRouter()

let isCleaningUp = false

const props = defineProps({
  assetId: {
    type: [Number, String],
    required: true
  },
  assetName: {
    type: String,
    default: 'Unknown'
  }
})

const terminalContainer = ref(null)
const terminal = ref(null)
const fitAddon = ref(null)
const socket = ref(null)
const sessionId = ref(null)
const connectionStatus = ref('正在连接...')
const connectionStatusType = ref('warning')
const commandHistory = ref([])
const historyIndex = ref(-1)
const signDialogVisible = ref(false)
const signPassword = ref('')
const signError = ref('')
const signCommand = ref('')
const signChallenge = ref(null)
const signAttempts = ref(0)
const signResolve = ref(null)

const updateStatus = (status, type = 'warning') => {
  connectionStatus.value = status
  connectionStatusType.value = type
}

const deriveSM4Key = async (password, salt) => {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'])
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 128)
  return Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('')
}

const submitSignPassword = async () => {
  const password = signPassword.value.trim()
  if (!password) return

  const encryptedData = localStorage.getItem('sm2_encrypted_private_key')
  if (!encryptedData) {
    signError.value = '未找到加密的SM2私钥，请先配置SM2密钥'
    return
  }

  try {
    const [saltHex, ivHex, ciphertextHex] = encryptedData.split(':')
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
    const sm4KeyHex = await deriveSM4Key(password, salt)
    const privateKey = sm4.decrypt(ciphertextHex, sm4KeyHex, { iv: ivHex })

    const challenge = JSON.stringify(signChallenge.value)
    const signatureHex = sm2.doSignature(challenge, privateKey, { hash: true })
    const signatureBytes = new Uint8Array(signatureHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
    const signatureB64 = btoa(String.fromCharCode(...signatureBytes))

    socket.value.emit('dangerous_command_signature', {
      nonce: signChallenge.value.nonce,
      signature: signatureB64,
      cancelled: false
    })

    signDialogVisible.value = false
    signPassword.value = ''
    signError.value = ''
    signAttempts.value = 0
    signChallenge.value = null
  } catch (e) {
    signAttempts.value++
    if (signAttempts.value >= 3) {
      signError.value = '密码错误已达3次，操作已取消'
      socket.value.emit('dangerous_command_signature', {
        nonce: signChallenge.value.nonce,
        cancelled: true
      })
      setTimeout(() => {
        signDialogVisible.value = false
      }, 2000)
    } else {
      signError.value = `密码错误，请重试（剩余${3 - signAttempts.value}次）`
    }
  }
}

const cancelSign = () => {
  socket.value.emit('dangerous_command_signature', {
    nonce: signChallenge.value.nonce,
    cancelled: true
  })
  signDialogVisible.value = false
  signPassword.value = ''
  signError.value = ''
  signAttempts.value = 0
  signChallenge.value = null
}

const closeTerminal = () => {
  if (isCleaningUp) return
  isCleaningUp = true

  window.removeEventListener('resize', handleResize)

  if (socket.value) {
    try {
      socket.value.removeAllListeners()
      socket.value.disconnect()
    } catch (e) {
      console.error('[WebPowerShell] Error cleaning socket:', e)
    } finally {
      socket.value = null
    }
  }

  if (terminal.value) {
    try {
      terminal.value.dispose()
    } catch (e) {
      console.warn('[WebPowerShell] Error disposing terminal:', e)
    } finally {
      terminal.value = null
    }
  }

  fitAddon.value = null
  sessionId.value = null
  router.push('/assets')
}

const handleResize = () => {
  if (fitAddon.value && terminal.value) {
    fitAddon.value.fit()
  }
}

const setupTerminal = () => {
  if (terminal.value) {
    try { terminal.value.dispose() } catch (e) {}
    terminal.value = null
  }

  if (fitAddon.value) {
    fitAddon.value = null
  }

  if (terminalContainer.value) {
    terminalContainer.value.innerHTML = ''
  }

  terminal.value = new Terminal({
    fontSize: 14,
    fontFamily: 'Cascadia Code, Consolas, "Courier New", monospace',
    theme: {
      background: '#012456',
      foreground: '#e0e0e0',
      cursor: '#ffffff'
    },
    cursorBlink: true,
    cursorStyle: 'block',
    allowProposedApi: true
  })

  fitAddon.value = new FitAddon()
  terminal.value.loadAddon(fitAddon.value)

  terminal.value.open(terminalContainer.value)
  nextTick(() => {
    if (fitAddon.value) {
      fitAddon.value.fit()
    }
    if (terminal.value) {
      terminal.value.focus()
    }
  })

  const emitInput = (data) => {
    if (socket.value && sessionId.value) {
      socket.value.emit('winrm_input', {
        session_id: sessionId.value,
        input: data
      })
    }
  }

  let currentInput = ''

  terminal.value.onKey(({ key, domEvent }) => {
    if (domEvent.ctrlKey && key === '\x03') {
      emitInput('^C\r\n')
      if (socket.value && sessionId.value) {
        socket.value.emit('command', {
          session_id: sessionId.value,
          cmd: String.fromCharCode(3)
        })
      }
      return
    }

    if (domEvent.keyCode === 13) {
      if (currentInput.trim()) {
        commandHistory.value.push(currentInput.trim())
        historyIndex.value = commandHistory.value.length
        if (socket.value && sessionId.value) {
          socket.value.emit('command', {
            session_id: sessionId.value,
            cmd: currentInput.trim()
          })
        }
      }
      currentInput = ''
      if (terminal.value) {
        terminal.value.write('\r\n')
      }
      return
    }

    if (domEvent.keyCode === 38) {
      if (historyIndex.value > 0) {
        historyIndex.value--
        currentInput = commandHistory.value[historyIndex.value] || ''
        if (terminal.value) {
          terminal.value.write('\r\x1b[K')
          terminal.value.write('PS C:\\Users\\Administrator> ' + currentInput)
        }
      }
      return
    }

    if (domEvent.keyCode === 40) {
      if (historyIndex.value < commandHistory.value.length - 1) {
        historyIndex.value++
        currentInput = commandHistory.value[historyIndex.value] || ''
      } else {
        historyIndex.value = commandHistory.value.length
        currentInput = ''
      }
      if (terminal.value) {
        terminal.value.write('\r\x1b[K')
        terminal.value.write('PS C:\\Users\\Administrator> ' + currentInput)
      }
      return
    }

    if (domEvent.keyCode === 8) {
      if (currentInput.length > 0) {
        currentInput = currentInput.slice(0, -1)
        if (terminal.value) {
          terminal.value.write('\b \b')
        }
        emitInput('\b \b')
      }
      return
    }

    if (key && key.length === 1) {
      currentInput += key
      if (terminal.value) {
        terminal.value.write(key)
      }
      emitInput(key)
    }
  })
}

const setupSocket = () => {
  if (socket.value) {
    try {
      socket.value.removeAllListeners()
      socket.value.disconnect()
    } catch (e) {}
    socket.value = null
  }

  const token = sessionStorage.getItem('token') || localStorage.getItem('token')

  const wsBase = import.meta.env.VITE_API_TARGET || 'http://localhost:5000'
  socket.value = io(wsBase, {
    path: '/socket.io',
    transports: ['websocket', 'polling'],
    query: { token: token }
  })

  socket.value.on('connect', () => {
    updateStatus('已连接，正在建立WinRM会话...', 'warning')
    socket.value.emit('winrm_connect', { asset_id: props.assetId })
  })

  socket.value.on('connect_error', (error) => {
    updateStatus('连接失败', 'danger')
    if (terminal.value) {
      terminal.value.write('\r\n\x1b[31m连接错误: ' + error.message + '\x1b[0m\r\n')
    }
  })

  socket.value.on('disconnect', () => {
    updateStatus('已断开', 'info')
  })

  socket.value.on('winrm_connected', (data) => {
    sessionId.value = data.session_id
    updateStatus('WinRM已连接', 'success')
  })

  socket.value.on('dangerous_command_challenge', (data) => {
    signCommand.value = data.challenge.command
    signChallenge.value = data.challenge
    signPassword.value = ''
    signError.value = ''
    signAttempts.value = 0
    signDialogVisible.value = true
  })

  socket.value.on('output', (data) => {
    if (data.stdout) {
      if (terminal.value) {
        terminal.value.write(data.stdout)
      }
    }
    if (data.stderr) {
      if (terminal.value) {
        if (data.exit_code !== 0) {
          terminal.value.write('\x1b[31m' + data.stderr + '\x1b[0m')
        } else {
          terminal.value.write(data.stderr)
        }
      }
    }
    if (data.exit_code === 0) {
      if (terminal.value) {
        terminal.value.write('\r\nPS C:\\Users\\Administrator> ')
      }
    } else {
      if (terminal.value) {
        terminal.value.write('\r\n\x1b[31mPS C:\\Users\\Administrator>\x1b[0m ')
      }
    }
  })

  socket.value.on('error', (data) => {
    updateStatus('错误', 'danger')
    if (terminal.value) {
      terminal.value.write('\r\n\x1b[31m错误: ' + data.message + '\x1b[0m\r\n')
    }
  })
}

watch(sessionId, (newVal) => {
  if (newVal) {
    nextTick(() => {
      setupTerminal()
    })
  }
})

onMounted(() => {
  try {
    setupSocket()
    window.addEventListener('resize', handleResize)
  } catch (error) {
    console.error('[WebPowerShell] Mount error:', error)
    if (terminal.value) {
      try { terminal.value.dispose() } catch (e) {}
      terminal.value = null
    }
    if (terminalContainer.value) {
      terminalContainer.value.innerHTML = ''
    }
    updateStatus('初始化失败', 'danger')
  }
})

onUnmounted(() => {
  isCleaningUp = true
  window.removeEventListener('resize', handleResize)

  if (socket.value) {
    try {
      socket.value.removeAllListeners()
      socket.value.disconnect()
    } catch (e) {}
    socket.value = null
  }

  if (terminal.value) {
    try { terminal.value.dispose() } catch (e) {}
    terminal.value = null
  }

  fitAddon.value = null

  if (terminalContainer.value) {
    terminalContainer.value.innerHTML = ''
  }

  isCleaningUp = false
})
</script>

<style scoped>
.web-powershell-container {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border-light);
  border-radius: var(--border-radius-md);
  overflow: hidden;
  box-shadow: var(--shadow-md);
}

.powershell-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 20px;
  background-color: #f8fafc;
  border-bottom: 1px solid var(--border-light);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.powershell-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: bold;
  color: var(--text-primary);
}

.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 4px;
}

.status-dot.warning {
  background-color: #e6a23c;
}

.status-dot.success {
  background-color: #67c23a;
}

.status-dot.danger {
  background-color: #f56c6c;
}

.status-dot.info {
  background-color: #909399;
}

.terminal-placeholder {
  color: #4ade80;
  margin-bottom: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid #334155;
  display: flex;
  align-items: center;
  gap: 8px;
  background: rgba(74, 222, 128, 0.05);
  border-left: 3px solid #4ade80;
}

.terminal-container {
  flex: 1;
  width: 100%;
  overflow: hidden;
  padding: 16px;
  background-color: #012456;
}

:deep(.xterm) {
  width: 100%;
  height: 100%;
  font-family: "Cascadia Code", Consolas, "Courier New", monospace;
  font-size: 14px;
}

:deep(.xterm-viewport) {
  background-color: #012456 !important;
}
</style>