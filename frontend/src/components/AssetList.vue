<template>
  <div class="asset-list-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>资产管理</h2>
          <div class="header-buttons">
            <el-button v-if="role === 'admin'" type="success" @click="openDiscoverDialog">
              <el-icon><Search /></el-icon> 资产发现
            </el-button>
            <el-button v-if="role === 'admin'" type="primary" @click="openAddDialog">
              <el-icon><Plus /></el-icon> 添加资产
            </el-button>
          </div>
        </div>
      </template>

      <el-table
        :data="assets"
        style="width: 100%"
        border
        stripe
        v-loading="loading"
        @selection-change="handleSelectionChange"
      >
        <el-table-column type="selection" width="50" />
        <el-table-column prop="ip" label="IP地址" width="150" />
        <el-table-column prop="hostname" label="主机名" width="150" />
        <el-table-column prop="os_type" label="系统类型" width="130">
          <template #default="scope">
            <el-tag :type="getOsTypeTagType(scope.row.os_type)" effect="plain">
            <span v-if="scope.row.os_type?.toLowerCase() === 'mysql'">🗄️</span>
            <span v-else-if="scope.row.os_type?.toLowerCase() === 'windows'">🖥️</span>
              <span v-else>🖥️</span>
              <span style="margin-left: 4px">{{ scope.row.os_type }}</span>
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="ssh_port" label="端口" width="80" />
        <el-table-column prop="status" label="管理状态" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.status === 'active' ? 'success' : 'info'" effect="dark">
              {{ scope.row.status === 'active' ? '正常' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="connectivity" label="连通性" width="100">
          <template #default="scope">
            <el-tag
              :type="getConnectivityTagType(scope.row.connectivity)"
              effect="dark"
              :title="scope.row.last_check_time ? '最后检测: ' + scope.row.last_check_time : '尚未检测'"
            >
              {{ getConnectivityText(scope.row.connectivity) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_agent_login_time" label="最后登录" width="160" />
        <el-table-column label="操作" fixed="right" width="380">
          <template #default="scope">
            <el-button
              v-if="['admin', 'operator'].includes(role)"
              type="info"
              link
              @click="requestPasswordView(scope.row.id, scope.row.credentials[0]?.id)"
              :loading="scope.row._viewing"
              :disabled="scope.row.credentials.length === 0"
            >
              查看密码
            </el-button>
            <el-button
              v-if="['admin', 'operator'].includes(role) && scope.row.os_type?.toLowerCase() !== 'mysql' && scope.row.os_type?.toLowerCase() !== 'windows'"
              type="primary"
              link
              @click="openWebSSH(scope.row)"
              :disabled="scope.row.credentials.length === 0"
            >
              Web SSH
            </el-button>
            <el-button
              v-if="['admin', 'operator'].includes(role) && scope.row.os_type?.toLowerCase() === 'windows'"
              type="primary"
              link
              @click="openWebPowerShell(scope.row)"
              :disabled="scope.row.credentials.length === 0"
            >
              Web PowerShell
            </el-button>
            <el-button
              v-if="['admin', 'operator'].includes(role)"
              type="success"
              link
              @click="rotatePassword(scope.row)"
              :loading="scope.row._rotating"
              :disabled="scope.row.credentials.length === 0"
            >
              立即改密
            </el-button>
            <el-button
              v-if="['admin', 'operator'].includes(role)"
              type="warning"
              link
              @click="viewRotationHistory(scope.row)"
              :disabled="scope.row.credentials.length === 0"
            >
              改密历史
            </el-button>
            <el-button
              v-if="scope.row.os_type?.toLowerCase() === 'mysql' && ['admin', 'operator'].includes(role)"
              type="warning"
              link
              @click="applyProxyToken(scope.row)"
              :disabled="scope.row.credentials.length === 0"
            >
              申请Token
            </el-button>
            <el-button
              v-if="scope.row.os_type === 'MySQL' && ['admin', 'operator'].includes(role)"
              type="info"
              link
              @click="openInterceptorDialog(scope.row)"
            >
              拦截状态
            </el-button>
            <el-button
              v-if="role === 'admin'"
              type="danger"
              link
              @click="confirmDelete(scope.row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- Batch action bar -->
      <div v-if="selectedAssets.length > 0" style="margin-top: 12px; display: flex; gap: 8px; align-items: center;">
        <span>已选 {{ selectedAssets.length }} 个资产</span>
        <el-button type="primary" :loading="batchTesting" @click="batchTest">批量检测连通性</el-button>
        <el-button v-if="role === 'admin'" type="warning" :loading="batchRotating" @click="batchRotate">批量改密</el-button>
      </div>
    </el-card>

    <!-- 添加资产对话框 -->
    <el-dialog
      v-model="addDialogVisible"
      title="添加资产"
      width="500px"
      top="5vh"
      append-to-body
    >
      <el-form
        ref="addFormRef"
        :model="addForm"
        :rules="addFormRules"
        label-width="100px"
      >
        <el-form-item :label="addForm.os_type === 'mysql' ? '主机地址' : 'IP地址'" prop="ip">
          <el-input v-model="addForm.ip" :placeholder="addForm.os_type === 'mysql' ? '请输入主机地址' : '请输入IP地址'" />
        </el-form-item>
        <el-form-item :label="addForm.os_type === 'mysql' ? '数据库名称' : '主机名'" prop="hostname">
          <el-input v-model="addForm.hostname" :placeholder="addForm.os_type === 'mysql' ? '请输入数据库名称（可选）' : '请输入主机名（可选）'" />
        </el-form-item>
        <el-form-item label="系统类型" prop="os_type">
          <el-select v-model="addForm.os_type" placeholder="请选择系统类型" style="width: 100%">
            <el-option label="Linux (SSH)" value="ssh" />
            <el-option label="Ubuntu" value="ubuntu" />
            <el-option label="Debian" value="debian" />
            <el-option label="CentOS" value="centos" />
            <el-option label="Windows (WinRM)" value="windows" />
            <el-option label="MySQL" value="mysql" />
          </el-select>
        </el-form-item>
        <el-form-item :label="addForm.os_type === 'mysql' ? '端口' : 'SSH端口'" prop="ssh_port">
          <el-input-number v-model="addForm.ssh_port" :min="1" :max="65535" style="width: 100%" />
        </el-form-item>
        <el-form-item :label="addForm.os_type === 'mysql' ? '用户名' : '账号'" prop="account_name">
          <el-input v-model="addForm.account_name" :placeholder="addForm.os_type === 'mysql' ? '请输入MySQL用户名' : '请输入SSH账号'" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="addForm.password" type="password" show-password placeholder="请输入密码" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleAddAsset" :loading="addLoading">确定</el-button>
      </template>
    </el-dialog>

    <!-- 资产发现对话框 -->
    <el-dialog
      v-model="discoverDialogVisible"
      title="资产发现"
      width="800px"
      top="5vh"
      append-to-body
    >
      <div class="discover-container">
        <el-form :model="discoverForm" label-width="120px">
          <el-form-item label="扫描类型">
            <el-select v-model="discoverForm.scan_type" style="width: 200px">
              <el-option label="SSH 扫描" value="ssh" />
              <el-option label="Windows (WinRM) 扫描" value="windows" />
              <el-option label="MySQL 扫描" value="mysql" />
            </el-select>
          </el-form-item>
          <el-form-item label="IP范围">
            <el-input
              v-model="discoverForm.ip_range"
              placeholder="例如：192.168.1.0/24 或单个IP"
              style="width: 300px"
            />
            <span style="margin-left: 10px; color: #909399; font-size: 12px;">
              支持CIDR格式或单个IP地址
            </span>
          </el-form-item>
          <el-form-item :label="discoverForm.scan_type === 'mysql' ? '端口' : '端口'">
            <el-input-number v-model="discoverForm.port" :min="1" :max="65535" />
          </el-form-item>
          <el-form-item :label="discoverForm.scan_type === 'mysql' ? '用户名' : '用户名'">
            <el-input v-model="discoverForm.username" :placeholder="discoverForm.scan_type === 'mysql' ? 'MySQL用户名' : 'SSH用户名'" style="width: 200px" />
          </el-form-item>
          <el-form-item label="密码字典">
            <el-input
              v-model="discoverForm.passwords"
              placeholder="用逗号分隔，如：123456,root,admin"
              style="width: 400px"
            />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="startScan" :loading="scanning">
              <el-icon v-if="!scanning"><Search /></el-icon>
              {{ scanning ? '扫描中...' : '开始扫描' }}
            </el-button>
          </el-form-item>
        </el-form>

        <div v-if="discoveredAssets.length > 0" class="discovered-results">
          <h4>扫描结果（共 {{ discoveredAssets.length }} 台）</h4>
          <el-table :data="discoveredAssets" border stripe max-height="300">
            <el-table-column prop="ip" label="IP地址" width="150" />
            <el-table-column prop="hostname" label="主机名" width="150" />
            <el-table-column prop="os_type" label="系统类型" width="120">
              <template #default="scope">
                <el-tag :type="getOsTypeTagType(scope.row.os_type)" effect="plain">
                  {{ scope.row.os_type }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="ssh_port" label="端口" width="80" />
            <el-table-column prop="account_name" label="账号" width="100" />
            <el-table-column label="操作" width="100">
              <template #default="scope">
                <el-button
                  type="primary"
                  size="small"
                  @click="addDiscoveredAsset(scope.row)"
                  :loading="addingAsset === scope.row.ip"
                >
                  添加
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>

        <el-empty v-else-if="scanCompleted && discoveredAssets.length === 0" description="未发现可用资产" />
      </div>
      <template #footer>
        <el-button @click="discoverDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- 代理Token对话框 -->
    <el-dialog
      v-model="tokenDialogVisible"
      title="数据库代理Token"
      width="620px"
      top="5vh"
      append-to-body
      destroy-on-close
      :close-on-click-modal="false"
      @close="handleTokenDialogClose"
    >
      <div v-if="tokenData" class="token-dialog-container">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="资产IP">{{ tokenData.assetIp }}</el-descriptions-item>
          <el-descriptions-item label="用户名">{{ tokenData.username }}</el-descriptions-item>
          <el-descriptions-item label="Token过期">
            <el-tag :type="tokenExpired ? 'danger' : 'warning'">
              {{ tokenExpired ? '已过期' : `${tokenRemaining}s` }}
            </el-tag>
          </el-descriptions-item>
        </el-descriptions>

        <div v-if="!tokenExpired" class="token-section">
          <div class="pwd-section-header">
            <span class="pwd-section-title">连接命令</span>
            <span class="pwd-section-tip">复制命令在终端执行</span>
          </div>
          <div class="pwd-input-group">
            <div class="pwd-input-field pwd-command-field">
              {{ tokenData.connectCommand }}
            </div>
            <button class="pwd-btn-copy" type="button" @click="handleCopyTokenCommand">复制</button>
          </div>
          <div class="pwd-hint">
            <el-icon :size="14"><InfoFilled /></el-icon>
            <span>Token将在 {{ tokenRemaining }} 秒后过期，关闭后不可复现</span>
          </div>
        </div>

        <div v-if="tokenExpired" class="token-expired-hint">
          <el-alert title="Token已过期，请重新申请" type="error" show-icon :closable="false" />
        </div>
      </div>

      <div v-else class="token-loading">
        <p>正在获取Token...</p>
      </div>

      <template #footer>
        <el-button @click="tokenDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- 代理拦截状态面板 -->
    <el-dialog
      v-model="interceptorDialogVisible"
      title="MySQL代理拦截状态"
      width="700px"
      top="5vh"
      append-to-body
    >
      <div class="interceptor-container" v-loading="interceptorLoading">
        <div class="interceptor-section">
          <h3 class="interceptor-section-title">代理状态</h3>
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="运行状态">
              <el-tag :type="proxyStatus === 'running' ? 'success' : 'danger'" effect="dark" size="small">
                {{ proxyStatus === 'running' ? '运行中' : '已停止' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="活跃Token数">
              <el-tag type="warning" effect="plain" size="small">{{ activeTokens }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="代理端口">{{ proxyPort }}</el-descriptions-item>
          </el-descriptions>
        </div>

        <div class="interceptor-section">
          <h3 class="interceptor-section-title">当前生效的拦截规则</h3>
          <el-table :data="interceptRules" border stripe max-height="200">
            <el-table-column prop="type" label="规则类型" width="180" />
            <el-table-column prop="description" label="描述" />
          </el-table>
        </div>

        <div class="interceptor-section">
          <h3 class="interceptor-section-title">最近被拦截记录（最近5条）</h3>
          <el-table v-if="blockedLogs.length > 0" :data="blockedLogs" border stripe max-height="300">
            <el-table-column prop="created_at" label="时间" width="160" />
            <el-table-column prop="operator" label="操作人" width="100" />
            <el-table-column label="被拦截SQL">
              <template #default="scope">
                {{ truncateSQL(scope.row.operation_detail) }}
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-else description="暂无拦截记录" :image-size="60" />
        </div>
      </div>
      <template #footer>
        <el-button @click="interceptorDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="refreshInterceptorData" :loading="interceptorLoading">刷新</el-button>
      </template>
    </el-dialog>

    <!-- WebSSH对话框 -->
    <el-dialog
      v-model="webSSHDialogVisible"
      title="Web SSH 终端"
      width="90%"
      top="2vh"
      :close-on-click-modal="false"
    >
      <WebSSH
        v-if="webSSHDialogVisible"
        :key="sshDialogKey"
        :assetId="selectedAssetId"
        :assetName="selectedAssetName"
        @close="webSSHDialogVisible = false"
      />
    </el-dialog>

    <!-- 密码查看对话框 -->
    <el-dialog
      v-model="passwordDialogVisible"
      title="密码信息"
      width="540px"
      top="5vh"
      append-to-body
      class="password-dialog"
      :close-on-click-modal="false"
      destroy-on-close
      @close="handlePasswordDialogClose"
    >
      <div class="pwd-dialog-container">
        <div class="pwd-dialog-header">
          <div class="pwd-dialog-icon">
            <el-icon :size="24"><Key /></el-icon>
          </div>
          <div class="pwd-dialog-title">
            <h2>{{ passwordData.isMysql ? 'MySQL 连接信息' : passwordData.isWindows ? 'Windows 连接信息' : '资产连接信息' }}</h2>
            <p>凭据信息</p>
          </div>
        </div>

        <div class="pwd-dialog-body">
          <div class="pwd-info-card">
            <div class="pwd-info-row">
              <span class="pwd-info-label">{{ passwordData.isMysql ? '主机地址' : '资产IP' }}</span>
              <span class="pwd-info-value">{{ passwordData.ip }}</span>
            </div>
            <div class="pwd-info-row">
              <span class="pwd-info-label">{{ passwordData.isMysql ? '端口' : passwordData.isWindows ? 'WinRM 端口' : 'SSH 端口' }}</span>
              <span class="pwd-info-value">{{ passwordData.ssh_port }}</span>
            </div>
            <div class="pwd-info-row">
              <span class="pwd-info-label">用户名</span>
              <span class="pwd-info-value pwd-info-mono">{{ passwordData.account_name }}</span>
            </div>
          </div>

          <div class="pwd-section">
            <div class="pwd-section-header">
              <span class="pwd-section-title">密码</span>
              <span class="pwd-section-tip">点击复制按钮可复制密码</span>
            </div>
            <div class="pwd-input-group">
              <div class="pwd-input-field" title="点击复制" @click="handleCopyPassword">
                {{ passwordFieldVisible ? passwordData.password : '••••••••••••••' }}
              </div>
              <button class="pwd-btn-icon" type="button" @click="handleTogglePassword">
                {{ passwordFieldVisible ? '🙈' : '👁' }}
              </button>
              <button class="pwd-btn-copy" type="button" @click="handleCopyPassword">复制</button>
            </div>
          </div>

          <div v-if="!passwordData.isMysql && !passwordData.isWindows" class="pwd-section">
            <div class="pwd-section-header">
              <span class="pwd-section-title">SSH 连接命令</span>
            </div>
            <div class="pwd-input-group">
              <div class="pwd-input-field pwd-command-field">
                {{ passwordData.sshCommand }}
              </div>
              <button class="pwd-btn-copy" type="button" @click="handleCopyCommand">复制</button>
            </div>
            <div class="pwd-hint">
              <el-icon :size="14"><InfoFilled /></el-icon>
              <span>复制命令后在终端执行，然后输入上述密码即可连接</span>
            </div>
          </div>
          <div v-if="passwordData.isWindows" class="pwd-section">
            <div class="pwd-section-header">
              <span class="pwd-section-title">WinRM 连接命令</span>
            </div>
            <div class="pwd-input-group">
              <div class="pwd-input-field pwd-command-field">
                {{ passwordData.sshCommand }}
              </div>
              <button class="pwd-btn-copy" type="button" @click="handleCopyCommand">复制</button>
            </div>
            <div class="pwd-hint">
              <el-icon :size="14"><InfoFilled /></el-icon>
              <span>复制命令后在 PowerShell 中执行，输入密码即可通过 WinRM 连接</span>
            </div>
          </div>

          <div class="pwd-warning">
            <div class="pwd-warning-icon">
              <el-icon :size="18"><WarningFilled /></el-icon>
            </div>
            <div class="pwd-warning-content">
              <h4>安全提醒</h4>
              <p>请妥善保管密码安全，切勿泄露给他人。密码仅在当前会话中有效。</p>
            </div>
          </div>
        </div>
      </div>
      <template #footer>
        <el-button @click="passwordDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- Re-auth Dialog for password viewing -->
    <el-dialog v-model="reAuthVisible" title="身份验证" width="400px" :close-on-click-modal="false">
      <p style="margin-bottom: 16px;">查看密码需要验证您的身份，请输入当前登录密码</p>
      <el-input v-model="reAuthPassword" type="password" placeholder="请输入当前密码" show-password
                @keyup.enter="confirmReAuth" />
      <template #footer>
        <el-button @click="reAuthVisible = false">取消</el-button>
        <el-button type="primary" :loading="reAuthLoading" @click="confirmReAuth">确认</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import request from '../utils/request'
import { Plus, Search, Connection, Close } from '@element-plus/icons-vue'
import WebSSH from './WebSSH.vue'
import { Key, InfoFilled, WarningFilled } from '@element-plus/icons-vue'
import { getRole } from '../utils/auth'

const role = computed(() => getRole())

const router = useRouter()

const assets = ref([])
const loading = ref(false)
const selectedAssets = ref([])
const batchTesting = ref(false)
const batchRotating = ref(false)
const addDialogVisible = ref(false)
const addLoading = ref(false)
const addFormRef = ref(null)
const addForm = ref({
  ip: '',
  hostname: '',
  os_type: 'ssh',
  ssh_port: 22,
  account_name: 'root',
  password: ''
})
const addFormRules = {
  ip: [{ required: true, message: '请输入IP地址', trigger: 'blur' }],
  os_type: [{ required: true, message: '请选择系统类型', trigger: 'change' }],
  account_name: [{ required: true, message: '请输入账号', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

watch(() => addForm.value.os_type, (newType) => {
  if (newType === 'mysql') {
    addForm.value.ssh_port = 3306
    addForm.value.account_name = 'root'
  } else if (newType === 'windows') {
    addForm.value.ssh_port = 5985
    addForm.value.account_name = 'Administrator'
  } else {
    addForm.value.ssh_port = 22
    addForm.value.account_name = 'root'
  }
})

const discoverDialogVisible = ref(false)
const scanning = ref(false)
const scanCompleted = ref(false)
const discoveredAssets = ref([])
const addingAsset = ref(null)
const discoverForm = ref({
  ip_range: '',
  port: 22,
  username: 'root',
  passwords: '123456,root,admin',
  scan_type: 'ssh'
})

watch(() => discoverForm.value.scan_type, (newType) => {
  if (newType === 'mysql') {
    discoverForm.value.port = 3306
    discoverForm.value.username = 'root'
  } else if (newType === 'windows') {
    discoverForm.value.port = 5985
    discoverForm.value.username = 'Administrator'
  } else {
    discoverForm.value.port = 22
    discoverForm.value.username = 'root'
  }
})

const interceptorDialogVisible = ref(false)
const interceptorLoading = ref(false)
const proxyStatus = ref('')
const activeTokens = ref(0)
const proxyPort = ref(3307)
const interceptRules = ref([
  { type: 'DROP DATABASE', description: '拦截 DROP DATABASE 高危操作' },
  { type: 'TRUNCATE', description: '拦截 TRUNCATE 高危操作' },
  { type: 'DELETE 无限制', description: '拦截无 WHERE/LIMIT 条件的 DELETE 操作' }
])
const blockedLogs = ref([])

const webSSHDialogVisible = ref(false)
const selectedAssetId = ref(null)
const selectedAssetName = ref('')
const sshDialogKey = ref(0)

const passwordDialogVisible = ref(false)
const passwordFieldVisible = ref(false)
const reAuthVisible = ref(false)
const reAuthPassword = ref('')
const reAuthLoading = ref(false)
const pendingViewAssetId = ref(null)
const pendingViewCredentialId = ref(null)
const passwordData = ref({
  ip: '',
  ssh_port: 22,
  account_name: '',
  password: '',
  sshCommand: '',
  isMysql: false
})

const tokenDialogVisible = ref(false)
const tokenData = ref(null)
const tokenExpired = ref(false)
const tokenRemaining = ref(300)
let tokenTimer = null

const getAssets = () => {
  loading.value = true
  request.get('/assets')
    .then(response => {
      if (Array.isArray(response)) {
        assets.value = response
      }
      loading.value = false
    })
    .catch(error => {
      console.error('获取资产列表失败:', error)
      loading.value = false
    })
}

const getConnectivityTagType = (connectivity) => {
  switch (connectivity) {
    case 'online': return 'success'
    case 'offline': return 'danger'
    default: return 'info'
  }
}

const getConnectivityText = (connectivity) => {
  switch (connectivity) {
    case 'online': return '在线'
    case 'offline': return '离线'
    default: return '未知'
  }
}

const openAddDialog = () => {
  addForm.value = {
    ip: '',
    hostname: '',
    os_type: 'ssh',
    ssh_port: 22,
    account_name: 'root',
    password: ''
  }
  addDialogVisible.value = true
}

const handleAddAsset = () => {
  addFormRef.value.validate(valid => {
    if (!valid) return

    addLoading.value = true
    const payload = { ...addForm.value }
    if (payload.os_type === 'mysql') {
      payload.host = payload.ip
      payload.port = payload.ssh_port
      payload.username = payload.account_name
      payload.name = payload.hostname || `mysql_${payload.ip}`
      payload.asset_type = 'mysql'
      delete payload.ip
      delete payload.ssh_port
      delete payload.account_name
      delete payload.hostname
    } else if (payload.os_type === 'windows') {
      payload.host = payload.ip
      payload.port = payload.ssh_port
      payload.username = payload.account_name
      payload.name = payload.hostname || `windows_${payload.ip}`
      payload.asset_type = 'windows'
      delete payload.ip
      delete payload.ssh_port
      delete payload.account_name
      delete payload.hostname
    }
    request.post('/assets', payload)
      .then(response => {
        if (response.code === 200 || response.code === 201) {
          ElMessage.success('添加资产成功')
          addDialogVisible.value = false
          getAssets()
        } else {
          ElMessage.error(response.data?.message || '添加资产失败')
        }
        addLoading.value = false
      })
      .catch(error => {
        console.error('添加资产失败:', error)
        addLoading.value = false
      })
  })
}

const openDiscoverDialog = () => {
  discoverForm.value = {
    ip_range: '',
    port: 22,
    username: 'root',
    passwords: '123456,root,admin',
    scan_type: 'ssh'
  }
  discoveredAssets.value = []
  scanCompleted.value = false
  discoverDialogVisible.value = true
}

const startScan = () => {
  if (!discoverForm.value.ip_range) {
    ElMessage.warning('请输入IP范围')
    return
  }

  scanning.value = true
  scanCompleted.value = false
  discoveredAssets.value = []

  const passwords = discoverForm.value.passwords.split(',').map(p => p.trim())

  request.post('/assets/discover', {
    ip_range: discoverForm.value.ip_range,
    port: discoverForm.value.port,
    username: discoverForm.value.username,
    passwords: passwords,
    scan_type: discoverForm.value.scan_type
  })
    .then(response => {
      scanning.value = false
      scanCompleted.value = true
      if (response.code === 200) {
        discoveredAssets.value = response.data || []
        if (discoveredAssets.value.length === 0) {
          ElMessage.info('未发现可用资产')
        } else {
          ElMessage.success(`发现 ${discoveredAssets.value.length} 台资产`)
        }
      } else {
        ElMessage.error(response.message || '扫描失败')
      }
    })
    .catch(error => {
      scanning.value = false
      scanCompleted.value = true
      console.error('扫描失败:', error)
    })
}

const addDiscoveredAsset = (asset) => {
  addingAsset.value = asset.ip

  const payload = {
    ip: asset.ip,
    hostname: asset.hostname,
    os_type: asset.os_type,
    ssh_port: asset.ssh_port,
    account_name: asset.account_name,
    password: asset.password
  }
  if (asset.os_type === 'mysql') {
    payload.host = asset.ip
    payload.port = asset.ssh_port || 3306
    payload.username = asset.account_name
    payload.name = asset.hostname || `mysql_${asset.ip}`
    payload.asset_type = 'mysql'
    delete payload.ip
    delete payload.ssh_port
    delete payload.account_name
    delete payload.hostname
  } else if (asset.os_type === 'windows') {
    payload.host = asset.ip
    payload.port = asset.ssh_port || 5985
    payload.username = asset.account_name
    payload.name = asset.hostname || `windows_${asset.ip}`
    payload.asset_type = 'windows'
    delete payload.ip
    delete payload.ssh_port
    delete payload.account_name
    delete payload.hostname
  }
  request.post('/assets', payload)
    .then(response => {
      addingAsset.value = null
      if (response.code === 200 || response.code === 201) {
        ElMessage.success(`资产 ${asset.ip} 添加成功`)
        discoveredAssets.value = discoveredAssets.value.filter(a => a.ip !== asset.ip)
        getAssets()
      } else {
        ElMessage.error(response.message || '添加资产失败')
      }
    })
    .catch(error => {
      addingAsset.value = null
      console.error('添加资产失败:', error)
    })
}

const confirmDelete = (asset) => {
  ElMessageBox.confirm(
    `确定要删除资产 ${asset.ip}（${asset.hostname}）吗？资产将被逻辑删除，关联的凭据记录将保留但不再显示。此操作将被记录到审计日志。`,
    '删除确认',
    {
      confirmButtonText: '确定删除',
      cancelButtonText: '取消',
      type: 'warning'
    }
  ).then(() => {
    request.delete(`/assets/${asset.id}`)
      .then(response => {
        if (response.code === 200) {
          ElMessage.success('删除成功')
          getAssets()
        } else {
          ElMessage.error(response.message || '删除失败')
        }
      })
      .catch(error => {
        console.error('删除资产失败:', error)
      })
  }).catch(() => {})
}

const rotatePassword = async (asset) => {
  if (asset.credentials.length === 0) {
    ElMessage.warning('该资产没有关联的凭证')
    return
  }

  try {
    await ElMessageBox.confirm(
      `确定要为资产 ${asset.ip} 执行密码改密吗？此操作将自动生成新密码并更新到系统。`,
      '改密确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return
  }

  asset._rotating = true
  const loading = ElMessage({ text: '正在执行改密操作，请稍候...', duration: 0 })

  try {
    const response = await request.post(`/rotation/trigger/${asset.id}`)
    loading.close()
    if (response.code === 200) {
      ElMessage.success(`资产 ${asset.ip} 改密成功，新密码已通过安全通道下发`)
      getAssets()
    } else {
      ElMessage.error(`改密失败: ${response.message || '未知错误'}`)
    }
  } catch (error) {
    loading.close()
    console.error('改密失败:', error)
  } finally {
    asset._rotating = false
  }
}

const viewRotationHistory = (asset) => {
  if (asset.credentials.length === 0) {
    ElMessage.warning('该资产没有关联的凭证')
    return
  }
  router.push({ name: 'RotationHistory', params: { assetId: asset.id } })
}

const openInterceptorDialog = () => {
  interceptorDialogVisible.value = true
  refreshInterceptorData()
}

const refreshInterceptorData = () => {
  interceptorLoading.value = true
  Promise.all([fetchProxyStatus(), fetchBlockedLogs()])
    .finally(() => {
      interceptorLoading.value = false
    })
}

const fetchProxyStatus = () => {
  return request.get('/proxy/status')
    .then(response => {
      if (response.code === 200) {
        proxyStatus.value = response.status || 'running'
        activeTokens.value = response.active_tokens || 0
        proxyPort.value = response.proxy_port || 3307
      }
    })
    .catch(error => {
      console.error('获取代理状态失败:', error)
    })
}

const fetchBlockedLogs = () => {
  return request.get('/audit/logs', { params: { log_type: 'MYSQL_PROXY_SQL_DENY', page: 1, page_size: 5 } })
    .then(response => {
      if (response.code === 200) {
        blockedLogs.value = response.data?.items || []
      }
    })
    .catch(error => {
      console.error('获取拦截记录失败:', error)
    })
}

const truncateSQL = (sql) => {
  if (!sql) return ''
  return sql.length > 50 ? sql.substring(0, 50) + '...' : sql
}

const getOsTypeTagType = (osType) => {
  const typeMap = {
    'Linux': '',
    'Ubuntu': 'success',
    'Debian': 'success',
    'CentOS': 'warning',
    'windows': 'info',
    'Windows': 'info',
    'MySQL': 'danger',
    'mysql': 'danger'
  }
  return typeMap[osType] || ''
}

const handleTogglePassword = () => {
  passwordFieldVisible.value = !passwordFieldVisible.value
}

const handleCopyPassword = () => {
  navigator.clipboard.writeText(passwordData.value.password)
    .then(() => ElMessage.success('密码已复制，关闭后不可复现'))
    .catch(() => ElMessage.error('复制失败'))
}

const handlePasswordDialogClose = () => {
  const sessionKey = Object.keys(sessionStorage).find(k => k.startsWith('pam_password_'))
  if (sessionKey) {
    sessionStorage.removeItem(sessionKey)
  }
}

const handleCopyCommand = () => {
  navigator.clipboard.writeText(passwordData.value.sshCommand)
    .then(() => ElMessage.success('SSH命令已复制'))
    .catch(() => ElMessage.error('复制失败'))
}

const viewPassword = async (asset) => {
  if (asset.credentials.length === 0) {
    ElMessage.warning('该资产没有关联的凭证')
    return
  }
  const credentialId = asset.credentials[0].id
  const sessionKey = `pam_password_${asset.id}`

  const existing = sessionStorage.getItem(sessionKey)
  if (existing) {
    try {
      const cached = JSON.parse(existing)
      passwordData.value = cached
      passwordFieldVisible.value = false
      passwordDialogVisible.value = true
      return
    } catch (e) {
      sessionStorage.removeItem(sessionKey)
    }
  }

  try {
    await ElMessageBox.confirm('确定要查看该资产的密码吗?', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return
  }

  asset._viewing = true
  try {
    const response = await request.post(`/assets/credentials/${credentialId}/view`)
    if (response.code === 200) {
      const isWindows = asset.os_type?.toLowerCase() === 'windows'
      const data = {
        ip: asset.ip,
        ssh_port: asset.ssh_port,
        account_name: asset.credentials[0].account_name,
        password: response.password,
        isMysql: asset.os_type?.toLowerCase() === 'mysql',
        isWindows: isWindows,
        sshCommand: isWindows
          ? `winrm -r:http://${asset.ip}:${asset.ssh_port}/wsman -u:${asset.credentials[0].account_name}`
          : `ssh ${asset.credentials[0].account_name}@${asset.ip} -p ${asset.ssh_port}`
      }
      sessionStorage.setItem(sessionKey, JSON.stringify(data))
      passwordData.value = data
      passwordFieldVisible.value = false
      passwordDialogVisible.value = true
    } else {
      ElMessage.error(response.message || '查看密码失败')
    }
  } catch (error) {
    console.error('查看密码失败:', error)
    ElMessage.error('查看密码失败')
  } finally {
    asset._viewing = false
  }
}

const requestPasswordView = (assetId, credentialId) => {
  pendingViewAssetId.value = assetId
  pendingViewCredentialId.value = credentialId
  reAuthPassword.value = ''
  reAuthVisible.value = true
}

const confirmReAuth = async () => {
  reAuthLoading.value = true
  try {
    const verifyRes = await request.post('/api/auth/verify-password', { password: reAuthPassword.value })
    if (!verifyRes.valid) {
      ElMessage.error('密码错误')
      return
    }
    const tokenRes = await request.post('/api/auth/password-view-token', {
      asset_id: pendingViewAssetId.value,
      credential_id: pendingViewCredentialId.value
    })
    if (tokenRes.code !== 200) {
      ElMessage.error(tokenRes.message || '获取查看Token失败')
      return
    }
    const viewRes = await request.post(`/api/assets/credentials/${pendingViewCredentialId.value}/view`, {
      view_token: tokenRes.data.view_token
    })
    if (viewRes.code === 200) {
      ElMessage.success(`密码: ${viewRes.password}`)
    }
  } finally {
    reAuthLoading.value = false
    reAuthVisible.value = false
  }
}

const openWebSSH = (asset) => {
  selectedAssetId.value = asset.id
  selectedAssetName.value = `${asset.ip}:${asset.ssh_port}`
  sshDialogKey.value++
  webSSHDialogVisible.value = true
}

const openWebPowerShell = (asset) => {
  router.push({ name: 'WebPowerShell', params: { assetId: asset.id } })
}

const applyProxyToken = (asset) => {
  tokenData.value = null
  tokenExpired.value = false
  tokenRemaining.value = 300
  tokenDialogVisible.value = true

  request.post('/proxy/token', { asset_id: asset.id })
    .then(response => {
      if (response.code === 200) {
        const accountName = asset.credentials.length > 0 ? asset.credentials[0].account_name : 'root'
        const connectCommand = `mysql -h 127.0.0.1 -P 3307 -u ${accountName} --password=${response.token} --default-auth=mysql_native_password`
        tokenData.value = {
          assetIp: asset.ip,
          username: accountName,
          token: response.token,
          expiresIn: response.expires_in,
          connectCommand: connectCommand
        }
        tokenRemaining.value = response.expires_in || 300
        startTokenCountdown()
      } else {
        ElMessage.error(response.message || '获取Token失败')
        tokenDialogVisible.value = false
      }
    })
    .catch(error => {
      console.error('获取Token失败:', error)
      ElMessage.error('获取Token失败')
      tokenDialogVisible.value = false
    })
}

const startTokenCountdown = () => {
  if (tokenTimer) clearInterval(tokenTimer)
  tokenTimer = setInterval(() => {
    tokenRemaining.value--
    if (tokenRemaining.value <= 0) {
      clearInterval(tokenTimer)
      tokenTimer = null
      tokenExpired.value = true
    }
  }, 1000)
}

const handleTokenDialogClose = () => {
  if (tokenTimer) {
    clearInterval(tokenTimer)
    tokenTimer = null
  }
  tokenData.value = null
}

const handleCopyTokenCommand = () => {
  if (tokenData.value) {
    navigator.clipboard.writeText(tokenData.value.connectCommand)
      .then(() => ElMessage.success('连接命令已复制'))
      .catch(() => ElMessage.error('复制失败'))
  }
}

const handleSelectionChange = (selection) => {
  selectedAssets.value = selection
}

const batchTest = async () => {
  batchTesting.value = true
  try {
    const ids = selectedAssets.value.map(a => a.id)
    const res = await request.post('/api/assets/batch/test', { asset_ids: ids })
    if (res.code === 200) {
      const taskId = res.data.task_id
      const poll = setInterval(async () => {
        const r = await request.get(`/api/assets/batch/result/${taskId}`)
        if (r.data.status === 'completed') {
          clearInterval(poll)
          const online = r.data.results.filter(x => x.status === 'online').length
          ElMessage.success(`检测完成: ${online}/${r.data.total} 在线`)
          getAssets()
        }
      }, 2000)
    }
  } finally {
    batchTesting.value = false
  }
}

const batchRotate = async () => {
  await ElMessageBox.confirm(
    `确认为选中的 ${selectedAssets.value.length} 个资产执行改密？`,
    '批量改密确认',
    { type: 'warning' }
  )
  batchRotating.value = true
  try {
    const ids = selectedAssets.value.map(a => a.id)
    const res = await request.post('/api/assets/batch/rotate', { asset_ids: ids })
    ElMessage.success(res.message)
    getAssets()
  } finally {
    batchRotating.value = false
  }
}

onMounted(() => {
  getAssets()
})

onUnmounted(() => {
  if (tokenTimer) {
    clearInterval(tokenTimer)
    tokenTimer = null
  }
})
</script>

<style scoped>
.asset-list-container {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--dark-text-primary);
}

.header-buttons {
  display: flex;
  gap: var(--spacing-md);
}

.discover-container {
  border-radius: var(--border-radius-md);
  border: 1px solid var(--dark-border);
  background: var(--dark-card-bg);
  padding: var(--spacing-lg);
  box-shadow: var(--shadow-md);
}

.discovered-results {
  margin-top: var(--spacing-lg);
  border-top: 1px solid var(--dark-border);
  padding-top: var(--spacing-lg);
}

.discovered-results h4 {
  margin: 0 0 15px 0;
  color: var(--dark-text-primary);
}

:deep(.password-dialog) {
  border-radius: 16px;
  overflow: hidden;
}

:deep(.password-dialog .el-message-box__content) {
  padding: 0;
}

:deep(.password-dialog .el-message-box__status) {
  display: none;
}

.pwd-dialog-container {
  padding: 0;
  font-family: 'Microsoft YaHei', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  color: #e2e8f0;
}

.pwd-dialog-header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 24px 28px;
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.15), rgba(56, 189, 248, 0.08));
  border-bottom: 1px solid rgba(56, 189, 248, 0.15);
}

.pwd-dialog-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 48px;
  height: 48px;
  background: linear-gradient(135deg, #38bdf8, #0ea5e9);
  border-radius: 12px;
  box-shadow: 0 4px 16px rgba(56, 189, 248, 0.3);
  color: white;
}

.pwd-dialog-title h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: #f8fafc;
  letter-spacing: 1px;
}

.pwd-dialog-title p {
  margin: 4px 0 0;
  font-size: 12px;
  color: rgba(148, 163, 184, 0.7);
  letter-spacing: 1px;
}

.pwd-dialog-body {
  padding: 24px 28px;
}

.pwd-info-card {
  background: rgba(15, 23, 42, 0.5);
  border: 1px solid rgba(56, 189, 248, 0.1);
  border-radius: 12px;
  padding: 16px 20px;
  margin-bottom: 20px;
}

.pwd-info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

.pwd-info-row:last-child {
  border-bottom: none;
}

.pwd-info-label {
  font-size: 13px;
  color: rgba(148, 163, 184, 0.8);
}

.pwd-info-value {
  font-size: 14px;
  font-weight: 500;
  color: #f8fafc;
}

.pwd-info-mono {
  font-family: 'Courier New', Consolas, monospace;
  color: #38bdf8;
}

.pwd-section {
  margin-bottom: 20px;
}

.pwd-section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.pwd-section-title {
  font-size: 14px;
  font-weight: 600;
  color: #e2e8f0;
}

.pwd-section-tip {
  font-size: 11px;
  color: rgba(148, 163, 184, 0.5);
}

.pwd-input-group {
  display: flex;
  border: 1px solid rgba(56, 189, 248, 0.2);
  border-radius: 10px;
  overflow: hidden;
  background: rgba(15, 23, 42, 0.6);
  box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2);
}

.pwd-input-field {
  flex: 1;
  padding: 14px 16px;
  font-family: 'Courier New', Consolas, monospace;
  font-size: 14px;
  color: #38bdf8;
  background: transparent;
  cursor: pointer;
  user-select: all;
  letter-spacing: 1px;
}

.pwd-command-field {
  color: rgba(148, 163, 184, 0.9);
  font-size: 13px;
  word-break: break-all;
  user-select: text;
}

.pwd-btn-icon {
  padding: 0 14px;
  background: rgba(56, 189, 248, 0.1);
  border: none;
  border-left: 1px solid rgba(56, 189, 248, 0.2);
  color: rgba(148, 163, 184, 0.7);
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s;
}

.pwd-btn-icon:hover {
  background: rgba(56, 189, 248, 0.2);
  color: #38bdf8;
}

.pwd-btn-copy {
  padding: 0 16px;
  background: linear-gradient(135deg, #38bdf8, #0ea5e9);
  border: none;
  color: white;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.pwd-btn-copy:hover {
  background: linear-gradient(135deg, #0ea5e9, #0284c7);
}

.pwd-hint {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 10px;
  padding: 10px 14px;
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.15);
  border-radius: 8px;
  font-size: 12px;
  color: rgba(148, 163, 184, 0.8);
}

.pwd-hint .el-icon {
  color: #38bdf8;
}

.pwd-warning {
  display: flex;
  gap: 14px;
  padding: 16px 18px;
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: 12px;
  margin-top: 8px;
}

.pwd-warning-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  background: rgba(239, 68, 68, 0.15);
  border-radius: 8px;
  color: #ef4444;
  flex-shrink: 0;
}

.pwd-warning-content h4 {
  margin: 0 0 6px;
  font-size: 14px;
  font-weight: 600;
  color: #f8fafc;
}

.pwd-warning-content p {
  margin: 0;
  font-size: 12px;
  color: rgba(148, 163, 184, 0.7);
  line-height: 1.5;
}

.token-dialog-container {
  padding: 0;
}

.token-section {
  margin-top: 20px;
}

.token-expired-hint {
  margin-top: 20px;
}

.token-loading {
  text-align: center;
  padding: 40px;
  color: rgba(148, 163, 184, 0.8);
}

.interceptor-container {
  min-height: 200px;
}

.interceptor-section {
  margin-bottom: 24px;
}

.interceptor-section:last-child {
  margin-bottom: 0;
}

.interceptor-section-title {
  margin: 0 0 12px 0;
  font-size: 15px;
  font-weight: 600;
  color: var(--dark-text-primary);
  padding-bottom: 8px;
  border-bottom: 1px solid var(--dark-border);
}
</style>
