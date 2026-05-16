<template>
  <div class="web-ssh-container">
    <div class="web-ssh-header">
      <h3>Web SSH - {{ assetName }}</h3>
      <el-tag v-if="connectionStatus" :type="connectionStatusType">{{ connectionStatus }}</el-tag>
      <el-button type="danger" size="small" @click="closeTerminal">关闭会话</el-button>
    </div>
    <div class="terminal-placeholder">
      <el-icon><Connection /></el-icon>
      <span>远程会话 | {{ assetName }}</span>
    </div>
    <div ref="terminalContainer" class="terminal-container"></div>

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
import { ref, onMounted, onUnmounted, nextTick } from 'vue';
import { io } from 'socket.io-client';
import { Connection } from '@element-plus/icons-vue';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { Unicode11Addon } from 'xterm-addon-unicode11';
import { sm2, sm4 } from 'sm-crypto';
import 'xterm/css/xterm.css';

// 清理状态锁
let isCleaningUp = false;

const props = defineProps({
  assetId: {
    type: Number,
    required: true
  },
  assetName: {
    type: String,
    default: 'Unknown'
  }
});

const emit = defineEmits(['close']);

const terminalContainer = ref(null);
const terminal = ref(null);
const fitAddon = ref(null);
const socket = ref(null);
const sessionId = ref(null);
const connectionStatus = ref('正在连接...');
const connectionStatusType = ref('warning');
const signDialogVisible = ref(false);
const signPassword = ref('');
const signError = ref('');
const signCommand = ref('');
const signChallenge = ref(null);
const signAttempts = ref(0);
const signResolve = ref(null);

const updateStatus = (status, type = 'warning') => {
  connectionStatus.value = status;
  connectionStatusType.value = type;
};

const deriveSM4Key = async (password, salt) => {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 128);
  return Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
};

const submitSignPassword = async () => {
  const password = signPassword.value.trim();
  if (!password) return;

  const encryptedData = localStorage.getItem('sm2_encrypted_private_key');
  if (!encryptedData) {
    signError.value = '未找到加密的SM2私钥，请先配置SM2密钥';
    return;
  }

  try {
    const [saltHex, ivHex, ciphertextHex] = encryptedData.split(':');
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const sm4KeyHex = await deriveSM4Key(password, salt);
    const privateKey = sm4.decrypt(ciphertextHex, sm4KeyHex, { iv: ivHex });

    const challenge = JSON.stringify(signChallenge.value);
    const signatureHex = sm2.doSignature(challenge, privateKey, { hash: true });
    const signatureBytes = new Uint8Array(signatureHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const signatureB64 = btoa(String.fromCharCode(...signatureBytes));

    socket.value.emit('dangerous_command_signature', {
      nonce: signChallenge.value.nonce,
      signature: signatureB64,
      cancelled: false
    });

    signDialogVisible.value = false;
    signPassword.value = '';
    signError.value = '';
    signAttempts.value = 0;
    signChallenge.value = null;
  } catch (e) {
    signAttempts.value++;
    if (signAttempts.value >= 3) {
      signError.value = '密码错误已达3次，操作已取消';
      socket.value.emit('dangerous_command_signature', {
        nonce: signChallenge.value.nonce,
        cancelled: true
      });
      setTimeout(() => {
        signDialogVisible.value = false;
      }, 2000);
    } else {
      signError.value = `密码错误，请重试（剩余${3 - signAttempts.value}次）`;
    }
  }
};

const cancelSign = () => {
  socket.value.emit('dangerous_command_signature', {
    nonce: signChallenge.value.nonce,
    cancelled: true
  });
  signDialogVisible.value = false;
  signPassword.value = '';
  signError.value = '';
  signAttempts.value = 0;
  signChallenge.value = null;
};

const closeTerminal = () => {
  // 防止重复清理
  if (isCleaningUp) return;
  isCleaningUp = true;
  
  console.log('[WebSSH] Closing terminal and cleaning resources');
  
  // 1. 先断开 socket
  if (socket.value) {
    try {
      socket.value.removeAllListeners();
      socket.value.disconnect();
      console.log('[WebSSH] Socket disconnected and listeners removed');
    } catch (error) {
      console.error('[WebSSH] Error cleaning socket:', error);
    } finally {
      socket.value = null;
    }
  }
  
  // 2. 再 dispose terminal
  if (terminal.value) {
    try {
      terminal.value.dispose();
      console.log('[WebSSH] Terminal disposed');
    } catch (error) {
      console.warn('[WebSSH] Error disposing terminal (ignored):', error);
    } finally {
      terminal.value = null;
    }
  }
  
  // 3. 最后置空 fitAddon（不调用 dispose）
  if (fitAddon.value) {
    fitAddon.value = null;
  }
  
  if (sessionId.value) {
    sessionId.value = null;
  }
  
  console.log('[WebSSH] Resources cleaned');
  emit('close');
};

const handleResize = () => {
  if (fitAddon.value && terminal.value) {
    fitAddon.value.fit();
    if (sessionId.value && socket.value) {
      socket.value.emit('ssh_resize', {
        session_id: sessionId.value,
        rows: terminal.value.rows,
        cols: terminal.value.cols
      });
    }
  }
};

const setupTerminal = () => {
  console.log('[WebSSH] Setting up terminal');

  // 销毁旧终端实例
  if (terminal.value) {
    try {
      terminal.value.dispose();
    } catch (e) {
      console.warn('[WebSSH] Error disposing old terminal:', e);
    }
    terminal.value = null;
  }

  // 释放fitAddon引用
  if (fitAddon.value) {
    fitAddon.value = null;
  }

  // 清除容器中的残留DOM
  if (terminalContainer.value) {
    terminalContainer.value.innerHTML = '';
  }

  // 创建新终端
  terminal.value = new Terminal({
    fontSize: 14,
    fontFamily: 'Consolas, Monaco, "Courier New", monospace',
    theme: {
      background: '#1e1e1e',
      foreground: '#d4d4d4',
      cursor: '#ffffff',
      italic: 'normal' // 强制斜体显示为正常字体
    },
    cursorBlink: true,
    cursorStyle: 'block',
    allowProposedApi: true
  });

  fitAddon.value = new FitAddon();
  terminal.value.loadAddon(fitAddon.value);

  const unicode11Addon = new Unicode11Addon();
  terminal.value.loadAddon(unicode11Addon);
  terminal.value.unicode.activeVersion = '11';

  terminal.value.open(terminalContainer.value);
  nextTick(() => {
    if (fitAddon.value) {
      fitAddon.value.fit();
    }
    if (terminal.value) {
      terminal.value.focus();
    }
  });

  terminal.value.onData((data) => {
    console.log('[WebSSH] Terminal input:', JSON.stringify(data));
    if (socket.value && sessionId.value) {
      socket.value.emit('ssh_input', {
        session_id: sessionId.value,
        input: data
      });
    }
  });

  terminal.value.onResize((size) => {
    console.log('[WebSSH] Terminal resized:', size);
    if (socket.value && sessionId.value) {
      socket.value.emit('ssh_resize', {
        session_id: sessionId.value,
        rows: size.rows,
        cols: size.cols
      });
    }
  });

  console.log('[WebSSH] Terminal setup complete');
};

const setupSocket = () => {
  console.log('[WebSSH] Setting up socket connection');

  // 销毁旧socket实例
  if (socket.value) {
    try {
      socket.value.removeAllListeners();
      socket.value.disconnect();
      socket.value = null;
    } catch (e) {
      console.warn('[WebSSH] cleanup socket error:', e);
    }
  }

  // 从 sessionStorage 获取 token（兼容旧版本 localStorage）
  const token = sessionStorage.getItem('token') || localStorage.getItem('token');
  
  const wsBase = import.meta.env.VITE_API_TARGET || 'http://localhost:5000'
  socket.value = io(wsBase, {
    path: '/socket.io',
    transports: ['websocket'],
    query: { token: token }
  });

  socket.value.on('connect', () => {
    console.log('[WebSSH] Socket connected, sid:', socket.value.id);
    updateStatus('连接成功，准备SSH...', 'warning');

    console.log('[WebSSH] Sending ssh_connect with asset_id:', props.assetId);
    socket.value.emit('ssh_connect', {
      asset_id: props.assetId
    });
  });

  socket.value.on('connect_error', (error) => {
    console.error('[WebSSH] Connection error:', error);
    updateStatus('连接失败: ' + error.message, 'danger');
    if (terminal.value) {
      terminal.value.write(`\r\n\x1b[31m连接错误: ${error.message}\x1b[0m\r\n`);
    }
  });

  socket.value.on('disconnect', () => {
    console.log('[WebSSH] Socket disconnected');
    updateStatus('已断开连接', 'info');
  });

  socket.value.on('ssh_connected', (data) => {
    console.log('[WebSSH] SSH connected:', data);
    sessionId.value = data.session_id;
    updateStatus('SSH已连接', 'success');
    if (terminal.value) {
      terminal.value.write('\r\n\x1b[32mSSH连接成功\x1b[0m\r\n');
    }
  });

  socket.value.on('dangerous_command_challenge', (data) => {
    signCommand.value = data.challenge.command;
    signChallenge.value = data.challenge;
    signPassword.value = '';
    signError.value = '';
    signAttempts.value = 0;
    signDialogVisible.value = true;
  });

  socket.value.on('ssh_output', (data) => {
    console.log('[WebSSH] Received output:', data.output ? data.output.length : 0, 'bytes');
    if (terminal.value && data.output) {
      terminal.value.write(data.output);
    }
  });

  socket.value.on('error', (data) => {
    console.error('[WebSSH] SSH error:', data.message);
    updateStatus('错误: ' + data.message, 'danger');
    if (terminal.value) {
      terminal.value.write(`\r\n\x1b[31m错误: ${data.message}\x1b[0m\r\n`);
    }
  });
};

onMounted(() => {
  console.log('[WebSSH] Component mounted');
  try {
    setupTerminal();
    setupSocket();
    window.addEventListener('resize', handleResize);
  } catch (error) {
    console.error('[WebSSH] Mount error:', error);
    if (terminal.value) {
      try { terminal.value.dispose(); } catch (e) {}
      terminal.value = null;
    }
    if (fitAddon.value) {
      fitAddon.value = null;
    }
    if (terminalContainer.value) {
      terminalContainer.value.innerHTML = '';
    }
    updateStatus('连接失败', 'danger');
  }
});

onUnmounted(() => {
  isCleaningUp = true;
  console.log('[WebSSH] Component unmounting');
  window.removeEventListener('resize', handleResize);
  
  // 强化清理逻辑
  if (socket.value) {
    try {
      socket.value.removeAllListeners();
      socket.value.disconnect();
      socket.value = null;
    } catch (e) {
      console.warn('[WebSSH] Error cleaning socket:', e);
    }
  }
  
  if (terminal.value) {
    try {
      terminal.value.dispose();
    } catch (e) {
      console.warn('[WebSSH] Error disposing terminal:', e);
    }
    terminal.value = null;
  }
  
  fitAddon.value = null;
  
  // 彻底清空DOM容器
  if (terminalContainer.value) {
    terminalContainer.value.innerHTML = '';
  }
  
  // 重置清理状态
  isCleaningUp = false;
  
  console.log('[WebSSH] All resources cleaned');
});
</script>

<style scoped>
.web-ssh-container {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border-light);
  border-radius: var(--border-radius-md);
  overflow: hidden;
  box-shadow: var(--shadow-md);
}

.web-ssh-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 20px;
  background-color: #f8fafc;
  border-bottom: 1px solid var(--border-light);
}

.web-ssh-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: bold;
  color: var(--text-primary);
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
  background-color: #1e293b;
}

:deep(.xterm) {
  width: 100%;
  height: 100%;
  font-family: "Courier New", monospace;
  font-size: 14px;
}

:deep(.xterm-viewport) {
  background-color: #1e293b !important;
}
</style>