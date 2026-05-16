<template>
  <div class="session-playback">
    <h2>会话录像回放</h2>

    <el-table :data="sessions" style="width: 100%" border>
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="target_asset" label="资产标识" />
      <el-table-column prop="asset_name" label="资产名称" />
      <el-table-column prop="start_time" label="开始时间" />
      <el-table-column prop="end_time" label="结束时间" />
      <el-table-column prop="duration" label="会话时长" />
      <el-table-column prop="operator" label="操作人" />
      <el-table-column label="操作" width="150">
        <template #default="scope">
          <el-button
            type="primary"
            size="small"
            @click="playSession(scope.row)"
          >
            回放
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-empty v-if="sessions.length === 0"
              description="暂无活跃会话"
              :image-size="120" />

    <!-- 回放对话框 -->
    <el-dialog
      v-model="playbackDialogVisible"
      :title="`会话回放 - ${currentSession?.target_asset}`"
      width="80%"
      height="80%"
      destroy-on-close
    >
      <div class="playback-container">
        <div class="xterm-container">
          <div class="playback-controls">
            <el-button type="primary" @click="startPlayback" :disabled="isPlaying">开始</el-button>
            <el-button type="warning" @click="pausePlayback" :disabled="!isPlaying">暂停</el-button>
            <el-button type="danger" @click="stopPlayback" :disabled="!isPlaying">停止</el-button>
            <el-select v-model="playbackSpeed" size="small" style="margin-left: 20px" @change="updatePlaybackSpeed">
              <el-option label="0.5x" :value="0.5" />
              <el-option label="1x" :value="1" />
              <el-option label="2x" :value="2" />
              <el-option label="3x" :value="3" />
            </el-select>
            <el-slider
              v-model="playbackProgress"
              :min="0"
              :max="playbackTotalSteps"
              @change="seekPlayback"
              style="width: 300px; margin-left: 20px"
            />
            <span style="margin-left: 10px">{{ currentStep + 1 }} / {{ playbackTotalSteps }}</span>
            <span style="margin-left: 10px">{{ formatTime(playbackData[currentStep]?.time || 0) }} / {{ formatTime(totalDuration) }}</span>
          </div>
          <div class="playback-terminal-wrapper">
            <div ref="playbackTerminal" class="playback-terminal"></div>
            <div class="watermark-overlay" v-if="watermarkText">
              <span class="watermark-item pos-tl">{{ watermarkText }}</span>
              <span class="watermark-item pos-tc">{{ watermarkText }}</span>
              <span class="watermark-item pos-tr">{{ watermarkText }}</span>
              <span class="watermark-item pos-bl">{{ watermarkText }}</span>
              <span class="watermark-item pos-bc">{{ watermarkText }}</span>
              <span class="watermark-item pos-br">{{ watermarkText }}</span>
            </div>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick, computed } from 'vue';
import request from '../utils/request';
import { ElMessage } from 'element-plus';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';

const sessions = ref([]);
const playbackDialogVisible = ref(false);
const currentSession = ref(null);
const terminal = ref(null);
const fitAddon = ref(null);
const playbackData = ref([]);
const isPlaying = ref(false);
const playbackInterval = ref(null);
const currentStep = ref(0);
const playbackProgress = ref(0);
const playbackTotalSteps = ref(0);
const playbackTerminal = ref(null);
const playbackSpeed = ref(1);
const totalDuration = ref(0);
const currentTimeStr = ref('')

const getUserFromToken = () => {
  try {
    const stored = sessionStorage.getItem('user') || localStorage.getItem('user')
    if (stored) {
      const parsed = JSON.parse(stored)
      return parsed.username || 'unknown'
    }
  } catch {}
  return 'unknown'
}

const watermarkText = computed(() => {
  const user = getUserFromToken()
  return `${user} | ${currentTimeStr.value || new Date().toLocaleString()}`
})

const getSessions = () => {
  request.get('/sessions')
    .then(response => {
      if (response.code === 200) {
        sessions.value = response.data;
      }
    })
    .catch(error => {
      console.error('获取会话列表失败:', error);
    });
};

const parseAsciinemaFormat = (content) => {
  try {
    const lines = content.split('\n').filter(line => line.trim() !== '');
    const frames = [];
    
    if (lines.length === 0) {
      return frames;
    }
    
    let header;
    try {
      header = JSON.parse(lines[0]);
      if (!header.version || !header.timestamp) {
        throw new Error('无效的asciinema头部');
      }
    } catch (e) {
      console.warn('无效的asciinema头部，按旧格式处理:', e.message);
      return content.split('\n').filter(line => line.trim());
    }
    
    for (let i = 1; i < lines.length; i++) {
      try {
        const parsed = JSON.parse(lines[i]);
        if (Array.isArray(parsed) && parsed.length >= 2) {
          const time = parseFloat(parsed[0]);
          const text = String(parsed[1]);
          if (text) {
            frames.push({ time, text });
          }
        }
      } catch (e) {
        continue;
      }
    }
    
    return frames;
  } catch (error) {
    console.error('解析 asciinema 格式失败:', error);
    return [];
  }
};

const playSession = (session) => {
  currentSession.value = session;
  playbackDialogVisible.value = true;
  currentTimeStr.value = new Date().toLocaleString()

  request.get(`/sessions/${session.id}/playback`)
    .then(response => {
      if (response.code === 200) {
        const content = response.data.content;
        
        let frames;
        if (content.startsWith('{')) {
          frames = parseAsciinemaFormat(content);
        } else {
          frames = content.split('\n').filter(line => line.trim()).map(line => ({ time: 0, text: line }));
        }
        
        frames = mergeConsecutiveFrames(frames, 0.01);
         
         playbackData.value = frames;
         playbackTotalSteps.value = frames.length;
         totalDuration.value = frames.length > 0 ? frames[frames.length - 1].time : 0;
         playbackProgress.value = 0;
        currentStep.value = 0;
        
        nextTick(() => {
          setupTerminal();
        });
      }
    })
    .catch(error => {
      console.error('获取会话录像失败:', error);
    });
};

const setupTerminal = () => {
  console.log('[SessionPlayback] Setting up terminal');

  if (terminal.value) {
    console.log('[SessionPlayback] Cleaning existing terminal');
    try {
      terminal.value.dispose();
      console.log('[SessionPlayback] Existing terminal disposed');
    } catch (error) {
      console.warn('[SessionPlayback] Error disposing existing terminal (ignored):', error);
    } finally {
      terminal.value = null;
    }
  }

  if (fitAddon.value) {
    fitAddon.value = null;
  }

  terminal.value = new Terminal({
    fontSize: 14,
    fontFamily: 'Consolas, Monaco, "Courier New", monospace',
    theme: {
      background: '#000000',
      foreground: '#d4d4d4',
      cursor: '#ffffff',
    },
    allowTransparency: false,
  });

  fitAddon.value = new FitAddon();
  terminal.value.loadAddon(fitAddon.value);

  terminal.value.open(playbackTerminal.value);
  fitAddon.value.fit();
  console.log('[SessionPlayback] Terminal setup complete');
};

const mergeConsecutiveFrames = (frames, threshold) => {
  if (frames.length === 0) return frames;
  const merged = [frames[0]];
  for (let i = 1; i < frames.length; i++) {
    const last = merged[merged.length - 1];
    if (frames[i].time - last.time < threshold) {
      last.text += frames[i].text;
    } else {
      merged.push(frames[i]);
    }
  }
  return merged;
};

const restoreAnsi = (text) => {
  if (!text) return text;
  return text
    .replace(/\\x1[bB]\[/g, '\x1b[')
    .replace(/\\u001[bB]\[/g, '\x1b[')
    .replace(/\\033\[/g, '\x1b[')
    .replace(/\\x1[bB]/g, '\x1b')
    .replace(/\\u001[bB]/g, '\x1b')
    .replace(/\\033/g, '\x1b')
    .replace(/\\x07/g, '\x07')
    .replace(/\\u0007/g, '\x07');
};

const startPlayback = () => {
  if (isPlaying.value) return;
  if (!terminal.value || playbackData.value.length === 0) return;

  isPlaying.value = true;
  playbackProgress.value = 0;

  const frames = playbackData.value;
  let frameIndex = 0;

  const writeFrame = () => {
    if (frameIndex >= frames.length) {
      stopPlayback();
      return;
    }
    
    const frame = frames[frameIndex];
    currentStep.value = frameIndex;
    playbackProgress.value = frameIndex;
    
    let content = frame.text;
    const hasLiteralSeq = content.includes('\\x1b') || content.includes('\\u001') || content.includes('\\033');
    if (hasLiteralSeq) {
      content = restoreAnsi(content);
    }
    content = content.replace(/\x1b\[3m/g, '').replace(/\x1b\[23m/g, '');
    
    if (content && terminal.value) {
      terminal.value.write(content);
    }
    
    frameIndex++;
    
    if (frameIndex < frames.length) {
      const delay = (frames[frameIndex].time - frames[frameIndex - 1].time) * 1000 / playbackSpeed.value;
      const clampedDelay = Math.max(10, Math.min(delay, 2000));
      playbackInterval.value = setTimeout(writeFrame, clampedDelay);
    } else {
      stopPlayback();
    }
  };
  
  writeFrame();
};

const pausePlayback = () => {
  if (!isPlaying.value) return;

  isPlaying.value = false;
  clearInterval(playbackInterval.value);
};

const stopPlayback = () => {
  isPlaying.value = false;

  if (playbackInterval.value) {
    try {
      clearTimeout(playbackInterval.value);
    } catch {
    } finally {
      playbackInterval.value = null;
    }
  }

  currentStep.value = 0;
  playbackProgress.value = 0;

  if (terminal.value) {
    try {
      terminal.value.clear();
    } catch {
    }
  }
};

const seekPlayback = () => {
  if (playbackInterval.value) {
    clearTimeout(playbackInterval.value);
    playbackInterval.value = null;
  }
  currentStep.value = playbackProgress.value;
  if (terminal.value) {
    terminal.value.clear();
    for (let i = 0; i <= playbackProgress.value; i++) {
      const frame = playbackData.value[i];
      if (frame && frame.text) {
        let content = frame.text;
        const hasLiteralSeq = content.includes('\\x1b') || content.includes('\\u001') || content.includes('\\033');
        if (hasLiteralSeq) content = restoreAnsi(content);
        content = content.replace(/\x1b\[3m/g, '').replace(/\x1b\[23m/g, '');
        if (content) terminal.value.write(content);
      }
    }
  }
  if (isPlaying.value) {
    isPlaying.value = false;
    setTimeout(() => startPlayback(), 16);
  }
};

const updatePlaybackSpeed = () => {
  if (isPlaying.value) {
    clearInterval(playbackInterval.value);
    startPlayback();
  }
};

const formatTime = (seconds) => {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
};

const handleResize = () => {
  if (fitAddon.value && terminal.value) {
    fitAddon.value.fit();
  }
};

onMounted(() => {
  getSessions();
  window.addEventListener('resize', handleResize);
});

onUnmounted(() => {
  if (playbackInterval.value) {
    clearTimeout(playbackInterval.value);
  }
  if (terminal.value) {
    terminal.value = null;
  }
  window.removeEventListener('resize', handleResize);
});

watch(playbackDialogVisible, (newVal) => {
  if (newVal) {
  } else {
    if (isPlaying.value) {
      stopPlayback();
    }

    if (playbackInterval.value) {
      try {
        clearTimeout(playbackInterval.value);
      } catch {
      } finally {
        playbackInterval.value = null;
      }
    }

    if (terminal.value) {
      terminal.value = null;
    }

    if (fitAddon.value) {
      fitAddon.value = null;
    }

    if (playbackData.value) {
      playbackData.value = [];
    }

    currentStep.value = 0;
    playbackProgress.value = 0;
    playbackTotalSteps.value = 0;
    totalDuration.value = 0;
    playbackSpeed.value = 1;
  }
});
</script>

<style scoped>
.session-playback {
  padding: var(--spacing-lg);
  color: var(--dark-text-primary);
}

h2 {
  margin-bottom: var(--spacing-lg);
  color: var(--dark-text-primary);
  font-size: 20px;
  font-weight: 600;
}

.playback-container {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
}

.xterm-container {
  flex: 1;
  width: 100%;
  display: flex;
  flex-direction: column;
}

.playback-controls {
  display: flex;
  align-items: center;
  padding: var(--spacing-md);
  background-color: rgba(30, 30, 30, 0.9);
  border-bottom: 1px solid var(--dark-border);
  margin-bottom: var(--spacing-sm);
  border-radius: var(--border-radius-md) var(--border-radius-md) 0 0;
  box-shadow: var(--shadow-sm);
  position: sticky;
  top: 0;
  z-index: 10;
}

.playback-terminal-wrapper {
  flex: 1;
  width: 100%;
  position: relative;
  overflow: hidden;
}

.playback-terminal {
  width: 100%;
  height: 100%;
  overflow: hidden;
  background: #000000;
  border-radius: 0 0 var(--border-radius-md) var(--border-radius-md);
}

.playback-terminal :deep(.xterm-screen),
.playback-terminal :deep(.xterm-rows) {
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', 'Source Code Pro', 'Courier New', monospace !important;
  font-size: 14px;
  line-height: 1.2;
  font-style: normal !important;
}

:deep(.xterm) {
  width: 100%;
  height: 100%;
}

.watermark-overlay {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 5;
}

.watermark-item {
  position: absolute;
  color: rgba(255, 255, 255, 0.12);
  font-size: 12px;
  font-family: 'Consolas', monospace;
  white-space: nowrap;
  user-select: none;
  transform: rotate(-15deg);
}

.pos-tl { top: 8px; left: 8px; }
.pos-tc { top: 8px; left: 50%; transform: translateX(-50%) rotate(-15deg); }
.pos-tr { top: 8px; right: 8px; }
.pos-bl { bottom: 8px; left: 8px; }
.pos-bc { bottom: 8px; left: 50%; transform: translateX(-50%) rotate(-15deg); }
.pos-br { bottom: 8px; right: 8px; }
</style>