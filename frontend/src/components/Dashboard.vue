<template>
  <div class="dashboard-container">
    <h2 class="page-title">系统概览</h2>

    <div class="card-grid">
      <div class="stat-card stat-asset">
        <div class="card-icon">
          <el-icon size="32"><Monitor /></el-icon>
        </div>
        <div class="card-info">
          <div class="card-value">{{ assetCount }}</div>
          <div class="card-label">资产总数</div>
        </div>
      </div>
      <div class="stat-card stat-info" :class="{ 'has-alerts': offlineCount > 0 }">
        <div class="card-icon">
          <el-icon size="32"><Connection /></el-icon>
          <div class="card-icon-actions">
            <el-button 
              type="text" 
              size="small" 
              @click="refreshAssets"
              :loading="refreshing"
              title="刷新资产状态"
            >
              <el-icon><Refresh /></el-icon>
            </el-button>
          </div>
        </div>
        <div class="card-info">
          <div class="card-value">{{ onlineRate }}%</div>
          <div class="card-label">资产在线率</div>
          <div class="card-sub" v-if="assetCount > 0">
            <span class="online-text">在线{{ onlineCount }}</span> / <span class="offline-text">离线{{ offlineCount }}</span>
          </div>
        </div>
      </div>
      <div class="stat-card stat-success">
        <div class="card-icon">
          <el-icon size="32"><CircleCheck /></el-icon>
        </div>
        <div class="card-info">
          <div class="card-value">{{ rotationSuccessCount }}</div>
          <div class="card-label">今日改密成功</div>
        </div>
      </div>
      <div class="stat-card stat-warning">
        <div class="card-icon">
          <el-icon size="32"><Clock /></el-icon>
        </div>
        <div class="card-info">
          <div class="card-value">{{ rotationPendingCount }}</div>
          <div class="card-label">待执行改密</div>
        </div>
      </div>
      <div class="stat-card stat-danger" :class="{ 'has-alerts': bypassAlertCount > 0 }">
        <div class="card-icon">
          <el-icon size="32"><Warning /></el-icon>
          <div class="card-icon-actions">
            <el-button 
              type="text" 
              size="small" 
              @click="refreshBypassDetect"
              :loading="refreshingBypass"
              title="刷新绕行检测"
            >
              <el-icon><Refresh /></el-icon>
            </el-button>
          </div>
        </div>
        <div class="card-info">
          <div class="card-value">{{ bypassAlertCount }}</div>
          <div class="card-label">绕行告警</div>
        </div>
      </div>
    </div>

    <div class="chart-wrapper">
      <div class="chart-card">
        <div class="card-title">密码轮换趋势</div>
        <div class="chart-container">
          <v-chart class="chart" :option="rotationTrendOption" />
        </div>
      </div>
      <div class="chart-card">
        <div class="card-title">资产类型分布</div>
        <div class="chart-container">
          <v-chart class="chart" :option="assetTypeOption" />
        </div>
      </div>
    </div>

    <div class="panel-wrapper">
      <div class="chart-card">
        <div class="card-title warning-title">
          <el-icon><Warning /></el-icon>
          <span>绕行登录告警</span>
          <el-button type="text" size="small" class="view-all-btn">查看全部</el-button>
        </div>
        <div v-if="bypassAlerts.length > 0" class="timeline-container">
          <el-timeline>
            <el-timeline-item
              v-for="(alert, index) in bypassAlerts"
              :key="index"
              :timestamp="alert.time"
              type="danger"
              placement="top"
            >
              <div class="timeline-item-content">
                <div class="timeline-item-title">{{ alert.message }}</div>
                <div class="timeline-item-meta">{{ alert.asset }}</div>
              </div>
            </el-timeline-item>
          </el-timeline>
        </div>
        <el-empty v-else description="暂无绕行告警，系统运行正常" />
      </div>

      <div class="chart-card key-card">
        <div class="card-title">
          <el-icon><Key /></el-icon>
          <span>密钥版本管理</span>
          <el-button v-if="role === 'admin'" type="primary" size="small" @click="showRotateKeyConfirm" :loading="rotatingKey">
            手动轮换密钥
          </el-button>
        </div>
        <div class="key-status-container">
          <div class="key-status-item">
            <span class="key-status-label">当前活跃密钥</span>
            <span class="key-status-value">v{{ keyStatus.active_key_id || 0 }}</span>
          </div>
          <div class="key-status-item">
            <span class="key-status-label">创建时间</span>
            <span class="key-status-value">{{ keyStatus.active_key_created || '暂无' }}</span>
          </div>
          <div class="key-status-item">
            <span class="key-status-label">已加密凭证</span>
            <span class="key-status-value">{{ keyStatus.encrypted_credentials_count || 0 }} 个</span>
          </div>
          <div class="key-status-item">
            <span class="key-status-label">历史版本</span>
            <span class="key-status-value">{{ keyStatus.total_key_versions || 0 }} 个</span>
          </div>
        </div>
      </div>

      <div class="chart-card">
        <div class="card-title">最近操作日志</div>
        <div class="log-list">
          <div class="log-item" v-for="(item, index) in recentActivities" :key="index">
            <span class="log-time">{{ item.time }}</span>
            <span class="log-content">{{ item.message }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="chart-card" style="margin-top: 20px">
      <div class="card-title">
        系统通知
        <el-button type="primary" size="small">查看全部</el-button>
      </div>
      <div v-if="systemNotices.length > 0" class="timeline-container">
        <el-timeline>
          <el-timeline-item
            v-for="(notice, index) in systemNotices"
            :key="index"
            :timestamp="notice.time"
            type="primary"
            placement="top"
          >
            <div class="timeline-item-content">
              <div class="timeline-item-title">{{ notice.message }}</div>
            </div>
          </el-timeline-item>
        </el-timeline>
      </div>
      <el-empty v-else description="暂无系统通知" />
    </div>

    <el-dialog v-model="showSm2Guide" title="Windows资产安全认证 — SM2密钥配置" width="520px" :close-on-click-modal="false" :close-on-press-escape="false" :show-close="false">
      <div v-if="guideStep === 1" class="guide-step">
        <div class="guide-icon">&#128274;</div>
        <p class="guide-desc">
          为了增强Windows资产堡垒机访问的安全性，系统使用SM2国密签名进行双因子认证。
        </p>
        <p class="guide-desc">配置过程仅需两步：</p>
        <ol class="guide-list">
          <li>生成 SM2 密钥对</li>
          <li>用账户密码加密私钥</li>
        </ol>
        <p class="guide-note">私钥将用您的账户密码加密后存储在浏览器本地，不会上传到服务器。</p>
        <div class="guide-footer">
          <el-button @click="dismissGuide">暂不配置</el-button>
          <el-button type="primary" @click="guideStep = 2">开始配置</el-button>
        </div>
      </div>

      <div v-if="guideStep === 2" class="guide-step">
        <p class="guide-desc">请输入您的账户密码，用于加密存储 SM2 私钥：</p>
        <el-form label-position="top" class="guide-form">
          <el-form-item label="账户密码">
            <el-input v-model="guidePassword" type="password" show-password placeholder="请输入当前登录密码" @keydown.enter.prevent="generateAndEncrypt" />
          </el-form-item>
        </el-form>
        <div v-if="guideError" class="guide-error">{{ guideError }}</div>
        <div class="guide-footer">
          <el-button @click="guideStep = 1">返回上一步</el-button>
          <el-button type="primary" :loading="guideGenerating" @click="generateAndEncrypt">生成密钥对</el-button>
        </div>
      </div>

      <div v-if="guideStep === 3" class="guide-step">
        <div class="guide-success-icon guide-center">&#10003;</div>
        <p class="guide-success-text guide-center">SM2 密钥配置成功！</p>
        <div class="recovery-codes-section">
          <el-alert
            title="请立即保存恢复码"
            type="warning"
            :closable="false"
            show-icon
            description="恢复码用于在遗忘保护口令时重置密钥。每个恢复码仅在此展示一次，关闭后不可复现。"
          />
          <div class="recovery-codes-box">
            <div v-for="(code, index) in guideRecoveryCodes" :key="index" class="recovery-code-item">
              <span class="recovery-code-index">{{ index + 1 }}.</span>
              <code class="recovery-code-value">{{ code }}</code>
            </div>
          </div>
          <el-button type="primary" class="copy-recovery-btn" @click="copyRecoveryCodes">
            复制所有恢复码
          </el-button>
        </div>
        <el-checkbox v-model="recoveryCodesSaved" style="margin-top: 16px;">
          我已安全保存恢复码（关闭后将无法再次查看）
        </el-checkbox>
        <div class="guide-footer">
          <el-button type="primary" :disabled="!recoveryCodesSaved" @click="confirmRecoveryCodesSaved">
            确认完成
          </el-button>
        </div>
      </div>

      <div v-if="guideStep === 4" class="guide-step guide-center">
        <div class="guide-error-icon">&#10007;</div>
        <p class="guide-error-text">密钥上传失败</p>
        <p class="guide-error-desc">{{ guideUploadError }}</p>
        <div class="guide-footer guide-center-footer">
          <el-button type="primary" :loading="guideGenerating" @click="retryUpload">重试上传</el-button>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import request from '../utils/request'
import { Monitor, CircleCheck, Clock, Warning, ArrowUp, ArrowDown, TrendCharts, DataLine, PieChart as PieChartIcon, Bell, Key, Connection, Refresh } from '@element-plus/icons-vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart as EChartsPieChart, LineChart as EChartsLineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import { ElMessageBox, ElMessage, ElLoading } from 'element-plus'
import { useKeyManagement } from '../composables/useKeyManagement'
import { getRole } from '../utils/auth'
import { sm2, sm4 } from 'sm-crypto'
import bcryptjs from 'bcryptjs'

use([EChartsPieChart, EChartsLineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])


const rotationSuccessCount = ref(0)
const rotationPendingCount = ref(0)
const bypassAlertCount = ref(0)
const bypassAlerts = ref([])
const systemNotices = ref([])
const lastRotationTime = ref('')
const recentActivities = ref([])
const assetTypeData = ref([])
const rotationTrendData = ref([])
const { keyStatus, rotatingKey, fetchKeyStatus, rotateKey } = useKeyManagement()
const role = computed(() => getRole())
const assetListData = ref([])
const refreshing = ref(false)
const refreshingBypass = ref(false)

const showSm2Guide = ref(false)
const guideStep = ref(1)
const guidePassword = ref('')
const guideError = ref('')
const guideGenerating = ref(false)
const guideUploadError = ref('')
let guideGeneratedPublicKey = null
let guideGeneratedPrivateKey = null
const guideRecoveryCodes = ref([])
const recoveryCodesSaved = ref(false)

const onlineCount = computed(() => {
  return assetListData.value.filter(a => a.status === 'active' && a.connectivity === 'online').length
})

const offlineCount = computed(() => {
  return assetListData.value.filter(a => a.status === 'active' && a.connectivity === 'offline').length
})

const assetCount = computed(() => {
  return assetListData.value.filter(a => a.status === 'active').length
})

const onlineRate = computed(() => {
  if (assetCount.value === 0) return 0
  return Math.round((onlineCount.value / assetCount.value) * 100)
})

const assetTypeOption = computed(() => {
  const data = assetTypeData.value.length > 0 ? assetTypeData.value : [
    { value: 0, name: '暂无数据' }
  ]

  return {
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      left: 'left',
      textStyle: {
        color: '#475569'
      }
    },
    series: [
      {
        name: '资产类型',
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '50%'],
        data: data,
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(56, 189, 248, 0.3)'
          }
        },
        itemStyle: {
          color: function(params) {
            const colors = ['#38bdf8', '#4ade80', '#fbbf24', '#a78bfa']
            return colors[params.dataIndex % colors.length]
          },
          borderRadius: 6,
          borderColor: '#ffffff',
          borderWidth: 2,
          shadowBlur: 5,
          shadowOffsetX: 0,
          shadowColor: 'rgba(0, 0, 0, 0.1)'
        },
        label: {
          color: '#475569'
        },
        labelLine: {
          lineStyle: {
            color: '#e2e8f0'
          }
        }
      }
    ]
  }
})

const rotationTrendOption = computed(() => {
  const dates = rotationTrendData.value.map(item => {
    const date = new Date(item.date)
    return `${date.getMonth() + 1}/${date.getDate()}`
  })
  const counts = rotationTrendData.value.map(item => item.count)

  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'cross',
        label: {
          backgroundColor: '#f8fafc'
        }
      }
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: dates.length > 0 ? dates : ['暂无数据'],
      axisLine: {
        lineStyle: {
          color: '#e2e8f0'
        }
      },
      axisLabel: {
        color: '#64748b'
      }
    },
    yAxis: {
      type: 'value',
      axisLine: {
        lineStyle: {
          color: '#e2e8f0'
        }
      },
      axisLabel: {
        color: '#64748b'
      },
      splitLine: {
        lineStyle: {
          color: '#f1f5f9'
        }
      }
    },
    series: [
      {
        name: '改密成功',
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        lineStyle: {
          width: 2,
          color: '#38bdf8'
        },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(56, 189, 248, 0.2)' },
              { offset: 1, color: 'rgba(56, 189, 248, 0.02)' }
            ]
          }
        },
        itemStyle: {
          color: '#38bdf8'
        },
        emphasis: {
          focus: 'series'
        },
        data: counts.length > 0 ? counts : [0]
      }
    ]
  }
})

const animateValue = (ref, target, duration = 2000) => {
  const start = 0
  const increment = target / (duration / 16)
  let current = start

  const timer = setInterval(() => {
    current += increment
    if (current >= target) {
      ref.value = Math.round(target)
      clearInterval(timer)
    } else {
      ref.value = Math.round(current)
    }
  }, 16)
}

const getAssetList = () => {
  request.get('/assets')
    .then(res => {
      if (res.code === 200 || Array.isArray(res)) {
        const assets = Array.isArray(res) ? res : res.data || res
        assetListData.value = assets
        console.log('资产列表数据:', assets)
        console.log('在线数:', onlineCount.value)
        console.log('离线数:', offlineCount.value)
        console.log('活跃资产数:', assetCount.value)
      }
    })
    .catch(error => {
      console.error('获取资产列表失败:', error)
    })
}

const refreshAssets = () => {
  refreshing.value = true
  // 先触发后端巡检
  request.post('/assets/check-connectivity')
    .then(res => {
      console.log('巡检触发成功:', res)
      // 巡检完成后获取最新状态
      getAssetList()
    })
    .catch(error => {
      console.error('触发巡检失败:', error)
      // 即使失败也获取当前状态
      getAssetList()
    })
    .finally(() => {
      setTimeout(() => {
        refreshing.value = false
      }, 1000)
    })
}

const refreshBypassDetect = () => {
  refreshingBypass.value = true
  // 触发后端绕行检测
  request.post('/bypass/trigger')
    .then(res => {
      console.log('绕行检测触发成功:', res)
      // 检测完成后更新仪表盘数据
      getSystemOverview()
    })
    .catch(error => {
      console.error('触发绕行检测失败:', error)
      // 即使失败也更新当前状态
      getSystemOverview()
    })
    .finally(() => {
      setTimeout(() => {
        refreshingBypass.value = false
      }, 1000)
    })
}

const getSystemOverview = () => {
  request.get('/dashboard/stats')
    .then(res => {
      if (res.code === 200) {
        const data = res.data

        animateValue(rotationSuccessCount, data.today_rotations || 0)
        animateValue(rotationPendingCount, data.rotation_pending || 0)
        animateValue(bypassAlertCount, data.bypass_alerts_count || 0)

        bypassAlerts.value = data.bypass_alerts || []
        systemNotices.value = data.system_notices || []
        lastRotationTime.value = data.last_rotation_time || '暂无'

        if (data.asset_type_distribution) {
          assetTypeData.value = data.asset_type_distribution.map(item => ({
            name: item.type,
            value: item.count
          }))
        }
      }
    })
    .catch(error => {
      console.error('获取仪表盘数据失败:', error)
    })
}

const getRotationTrend = () => {
  request.get('/dashboard/rotation-trend')
    .then(res => {
      if (res.code === 200) {
        rotationTrendData.value = res.data || []
      }
    })
    .catch(error => {
      console.error('获取改密趋势失败:', error)
    })
}

const loadRecentActivities = () => {
  request.get('/audit/logs', { params: { page: 1, page_size: 10 } })
    .then(res => {
      if (res.code === 200) {
        recentActivities.value = (res.data.items || []).map(item => ({
          message: item.operation_detail || '',
          time: item.created_at || '',
          asset: item.target_asset || '',
          type: getActivityType(item.log_type)
        }))
      }
    })
    .catch(error => {
      console.error('获取最近活动失败:', error)
    })
}

const getKeyStatus = () => {
  request.get('/keys/status')
    .then(res => {
      if (res.code === 200) {
        keyStatus.value = res.data
      }
    })
    .catch(error => {
      console.error('获取密钥状态失败:', error)
    })
}

const showRotateKeyConfirm = async () => {
  try {
    await ElMessageBox.confirm('确定要轮换工作密钥吗？所有密码将使用新密钥重新加密。', '警告', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return
  }

  rotatingKey.value = true
  const loadingInstance = ElLoading.service({
    lock: true,
    text: '正在轮换密钥...',
    background: 'rgba(0, 0, 0, 0.7)'
  })

  try {
    const res = await request.post('/keys/rotate')
    loadingInstance.close()
    if (res.code === 200) {
      ElMessage.success(`密钥已轮换，新版本 v${res.data.new_key_id}`)
      fetchKeyStatus()
      loadRecentActivities()
    } else {
      ElMessage.error(res.message || '密钥轮换失败')
    }
  } catch (error) {
    loadingInstance.close()
    console.error('密钥轮换失败:', error)
  } finally {
    rotatingKey.value = false
  }
}

const getActivityType = (logType) => {
  switch (logType) {
    case 'rotation':
      return 'success'
    case 'bypass_detected':
      return 'danger'
    case 'login':
    case 'password_view':
      return 'info'
    default:
      return 'info'
  }
}

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

const checkSm2Setup = () => {
  // SM2密钥现在在登录时自动配置，不再需要引导弹窗
}

const dismissGuide = () => {
  sessionStorage.setItem('sm2_guide_dismissed', '1')
  showSm2Guide.value = false
}

const validatePassword = () => {
  if (!guidePassword.value) return '请输入账户密码'
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

const encryptPrivateKey = async (privateKeyHex, password) => {
  const { salt, sm4KeyHex } = await deriveKeyFromPassword(password)
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const ivHex = bytesToHex(iv)
  const ciphertextHex = sm4.encrypt(privateKeyHex, sm4KeyHex, { iv: ivHex })
  const saltHex = bytesToHex(salt)
  return `${saltHex}:${ivHex}:${ciphertextHex}`
}

const generateAndEncrypt = async () => {
  const pwError = validatePassword()
  if (pwError) {
    guideError.value = pwError
    return
  }

  guideError.value = ''
  guideGenerating.value = true

  try {
    const valid = await verifyPasswordWithServer(guidePassword.value)
    if (!valid) {
      guideError.value = '密码错误，请重新输入'
      guideGenerating.value = false
      return
    }

    const keypair = sm2.generateKeyPairHex()
    guideGeneratedPrivateKey = keypair.privateKey

    let publicKeyHex = keypair.publicKey
    if (publicKeyHex.length === 130 && (publicKeyHex.startsWith('04') || publicKeyHex.startsWith('04'))) {
      publicKeyHex = publicKeyHex.substring(2)
    }
    const publicKeyBytes = new Uint8Array(publicKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
    guideGeneratedPublicKey = btoa(String.fromCharCode(...publicKeyBytes))

    const encryptedData = await encryptPrivateKey(guideGeneratedPrivateKey, guidePassword.value)

    const res = await request.put('/me/sm2-key', {
      public_key: guideGeneratedPublicKey
    })

    if (res.code === 200) {
      localStorage.setItem('sm2_encrypted_private_key', encryptedData)

      const codes = []
      for (let i = 0; i < 10; i++) {
        codes.push(crypto.randomUUID())
      }
      guideRecoveryCodes.value = codes

      try {
        const hashedCodes = await Promise.all(codes.map(c => bcryptjs.hash(c, 10)))
        await request.post('/me/sm2-recovery-codes', { recovery_hashes: hashedCodes })
      } catch (e) {
        console.warn('恢复码上传失败（后端可能未实现该端点），恢复码仅在本地展示', e)
      }

      localStorage.setItem('sm2_recovery_codes_generated', '1')
      recoveryCodesSaved.value = false
      guideStep.value = 3
    } else {
      guideUploadError.value = res.message || '公钥注册失败'
      guideStep.value = 4
    }
  } catch (e) {
    guideUploadError.value = e.message || '密钥生成失败'
    guideStep.value = 4
  } finally {
    guideGenerating.value = false
    guidePassword.value = ''
  }
}

const retryUpload = async () => {
  guideGenerating.value = true
  try {
    const res = await request.put('/me/sm2-key', {
      public_key: guideGeneratedPublicKey
    })
    if (res.code === 200) {
      recoveryCodesSaved.value = false
      guideStep.value = 3
    } else {
      guideUploadError.value = res.message || '公钥注册失败'
    }
  } catch (e) {
    guideUploadError.value = e.message || '上传失败'
  } finally {
    guideGenerating.value = false
  }
}

const copyRecoveryCodes = async () => {
  const text = guideRecoveryCodes.value.map((c, i) => `${i + 1}. ${c}`).join('\n')
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('恢复码已复制到剪贴板')
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = text
    document.body.appendChild(textarea)
    textarea.select()
    document.execCommand('copy')
    document.body.removeChild(textarea)
    ElMessage.success('恢复码已复制到剪贴板')
  }
}

const confirmRecoveryCodesSaved = () => {
  showSm2Guide.value = false
  guideStep.value = 1
  guidePassword.value = ''
  guideError.value = ''
  ElMessage.success('SM2密钥配置成功！请妥善保管恢复码。')
}

onMounted(() => {
  getAssetList()
  getSystemOverview()
  getRotationTrend()
  loadRecentActivities()
  fetchKeyStatus()
  checkSm2Setup()
})
</script>

<style scoped>
.dashboard-container {
  padding: 0;
}

.page-title {
  margin: 0 0 20px 0;
  font-size: 20px;
  font-weight: 600;
  color: var(--text-primary);
}

.card-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 20px;
  margin-bottom: 20px;
}

.stat-card {
  background: var(--bg-card);
  border-radius: var(--border-radius-md);
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 16px;
  box-shadow: var(--shadow-md);
  transition: transform 0.3s;
  position: relative;
}

.stat-card:hover {
  transform: translateY(-3px);
}

.card-icon {
  width: 50px;
  height: 50px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-size: 24px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
  position: relative;
}

.card-icon-actions {
  position: absolute;
  top: -8px;
  left: -8px;
  display: flex;
  gap: 4px;
}

.card-icon-actions .el-button {
  padding: 2px;
  min-width: auto;
  background: rgba(255, 255, 255, 0.9);
  border-radius: 50%;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
  color: #7c3aed;
}

.card-icon-actions .el-button:hover {
  background: #fff;
  color: #6d28d9;
}

.stat-asset .card-icon {
  background: linear-gradient(135deg, #38bdf8, #0ea5e9);
}

.stat-info .card-icon {
  background: linear-gradient(135deg, #a78bfa, #7c3aed);
}

.stat-success .card-icon {
  background: linear-gradient(135deg, #4ade80, #16a34a);
}

.stat-warning .card-icon {
  background: linear-gradient(135deg, #fbbf24, #f59e0b);
}

.stat-danger .card-icon {
  background: linear-gradient(135deg, #ef4444, #dc2626);
}

.card-info {
  flex: 1;
  position: relative;
}

.card-value {
  font-size: 24px;
  font-weight: bold;
  color: var(--text-primary);
  line-height: 1.2;
}

.card-label {
  font-size: 12px;
  color: var(--text-light);
  margin-top: 4px;
}

.card-sub {
  font-size: 11px;
  margin-top: 2px;
}

.card-actions {
  position: absolute;
  top: 0;
  right: 0;
  display: flex;
  gap: 8px;
}

.online-text {
  color: #4ade80;
}

.offline-text {
  color: #ef4444;
}

.chart-wrapper {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 20px;
  margin-bottom: 20px;
}

.panel-wrapper {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 20px;
}

.chart-card {
  background: var(--bg-card);
  border-radius: var(--border-radius-md);
  padding: 20px;
  box-shadow: var(--shadow-md);
}

.card-title {
  font-size: 16px;
  font-weight: bold;
  color: var(--text-primary);
  margin-bottom: 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.warning-title {
  color: var(--danger-color);
  display: flex;
  align-items: center;
  gap: 8px;
}

.chart-container {
  width: 100%;
  height: 280px;
}

.chart {
  width: 100%;
  height: 100%;
}

.log-list {
  max-height: 280px;
  overflow-y: auto;
}

.log-item {
  padding: 8px 0;
  border-bottom: 1px solid var(--border-light);
  display: flex;
  gap: 12px;
}

.log-time {
  color: var(--text-light);
  font-size: 12px;
  min-width: 50px;
}

.log-content {
  color: var(--text-primary);
  font-size: 13px;
  flex: 1;
}

.timeline-container {
  max-height: 280px;
  overflow-y: auto;
}

.timeline-item-content {
  background: var(--bg-card);
  padding: 16px;
  border-radius: var(--border-radius-sm);
  border-left: 3px solid var(--primary-color);
  margin-left: 8px;
  box-shadow: var(--shadow-sm);
}

.timeline-item-title {
  font-size: 13px;
  color: var(--text-primary);
  margin-bottom: 4px;
}

.timeline-item-meta {
  font-size: 12px;
  color: var(--text-light);
}

.view-all-btn {
  color: var(--primary-color);
  font-size: 12px;
  padding: 0;
}

.view-all-btn:hover {
  color: var(--primary-dark);
  text-decoration: underline;
}

.el-timeline-item__timestamp {
  color: var(--text-light) !important;
  font-size: 11px !important;
  opacity: 0.7;
}

.el-empty__description {
  color: var(--text-light) !important;
}

.el-empty__image svg {
  opacity: 0.5 !important;
}

.key-status-container {
  background: rgba(15, 23, 42, 0.3);
  border: 1px solid rgba(56, 189, 248, 0.2);
  border-radius: var(--border-radius-sm);
  padding: 16px;
  margin-top: 8px;
}

.key-status-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

.key-status-item:last-child {
  border-bottom: none;
}

.key-status-label {
  font-size: 13px;
  color: var(--text-light);
}

.key-status-value {
  font-size: 13px;
  font-weight: 500;
  color: #38bdf8;
  font-family: 'Courier New', Consolas, monospace;
}

.key-card .card-title {
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: 8px;
}

.key-card .el-button--primary {
  background: linear-gradient(135deg, #38bdf8, #0ea5e9);
  border: none;
  box-shadow: 0 4px 12px rgba(56, 189, 248, 0.3);
  transition: all 0.3s;
}

.key-card .el-button--primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(56, 189, 248, 0.4);
}

.guide-step {
  padding: 8px 0;
}

.guide-icon {
  font-size: 36px;
  text-align: center;
  margin-bottom: 12px;
}

.guide-desc {
  font-size: 14px;
  color: #475569;
  line-height: 1.6;
  margin-bottom: 8px;
}

.guide-list {
  margin: 8px 0 12px 20px;
  font-size: 14px;
  color: #475569;
  line-height: 1.8;
}

.guide-note {
  font-size: 12px;
  color: #94a3b8;
  margin-top: 8px;
  padding: 8px 12px;
  background: #f8fafc;
  border-radius: 6px;
}

.guide-form {
  margin: 16px 0;
}

.guide-error {
  color: #dc2626;
  font-size: 13px;
  margin: 8px 0;
  padding: 8px 12px;
  background: #fef2f2;
  border-radius: 6px;
}

.guide-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 20px;
}

.guide-center {
  text-align: center;
  padding: 24px 0;
}

.guide-center-footer {
  justify-content: center;
}

.guide-success-icon {
  font-size: 48px;
  color: #16a34a;
  margin-bottom: 12px;
}

.guide-success-text {
  font-size: 18px;
  font-weight: 600;
  color: #16a34a;
  margin-bottom: 8px;
}

.guide-success-desc {
  font-size: 14px;
  color: #64748b;
}

.guide-error-icon {
  font-size: 48px;
  color: #dc2626;
  margin-bottom: 12px;
}

.guide-error-text {
  font-size: 18px;
  font-weight: 600;
  color: #dc2626;
  margin-bottom: 8px;
}

.guide-error-desc {
  font-size: 14px;
  color: #64748b;
}

.recovery-codes-section {
  margin-top: 16px;
}

.recovery-codes-box {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 12px 16px;
  margin-top: 12px;
  max-height: 320px;
  overflow-y: auto;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px 16px;
  font-family: 'Courier New', Consolas, monospace;
}

.recovery-code-item {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 4px 0;
}

.recovery-code-index {
  color: #94a3b8;
  font-size: 12px;
  min-width: 20px;
}

.recovery-code-value {
  font-size: 12px;
  color: #1e293b;
  background: #ffffff;
  padding: 2px 8px;
  border-radius: 4px;
  border: 1px solid #e2e8f0;
  user-select: all;
  word-break: break-all;
}

.copy-recovery-btn {
  margin-top: 12px;
  width: 100%;
}
</style>

<style>
.echarts-tooltip {
  background: var(--bg-card) !important;
  border: 1px solid var(--border-light) !important;
  border-radius: var(--border-radius-sm) !important;
  color: var(--text-primary) !important;
  font-family: "Microsoft YaHei", -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif !important;
}
</style>