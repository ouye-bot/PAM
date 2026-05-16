<template>
  <div class="audit-log-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>审计日志</h2>
          <div class="card-header-actions">
            <el-select
              v-model="logTypeFilter"
              placeholder="过滤日志类型"
              clearable
              style="width: 200px; margin-right: 12px;"
              @change="handleFilterChange"
            >
              <el-option label="全部类型" value="" />
              <el-option label="SM2认证" value="SM2_LOGIN_SUCCESS" />
              <el-option label="密码查看" value="password_view" />
              <el-option label="密码改密" value="rotation" />
              <el-option label="密钥轮换" value="key_rotation" />
              <el-option label="SQL拦截" value="MYSQL_PROXY_SQL_DENY" />
              <el-option label="绕行告警" value="bypass_detected" />
              <el-option label="绕行检查" value="bypass_check" />
              <el-option label="会话记录" value="SESSION_START" />
              <el-option label="资产创建" value="asset_create" />
              <el-option label="资产删除" value="asset_delete" />
              <el-option label="系统通知" value="system_notice" />
            </el-select>
            <el-button type="success" @click="verifyChain" :loading="verifying">
              <el-icon><Key /></el-icon> 验证完整性
            </el-button>
          </div>
        </div>
      </template>

      <el-table
        :data="auditLogs"
        style="width: 100%"
        border
        stripe
        v-loading="loading"
      >
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="log_type" label="日志类型" width="140">
          <template #default="scope">
            <el-tag :type="getLogTypeTagType(scope.row.log_type)" effect="dark">
              {{ getLogTypeText(scope.row.log_type) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="operator" label="操作人" width="120" />
        <el-table-column prop="source_ip" label="源IP" width="120" />
        <el-table-column prop="target_asset" label="目标资产" width="140" />
        <el-table-column prop="operation_detail" label="操作详情" min-width="200" />
        <el-table-column prop="result" label="结果" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.result === 'success' ? 'success' : 'danger'" effect="plain">
              {{ scope.row.result === 'success' ? '成功' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="时间" width="160" />
      </el-table>

      <el-empty v-if="auditLogs.length === 0 && !loading"
                description="暂无审计日志，系统运行后将自动记录"
                :image-size="120" />

      <div class="pagination-container">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          :total="total"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <el-dialog
      v-model="showChainDialog"
      title="哈希链完整性验证"
      width="700px"
      top="5vh"
      append-to-body
    >
      <div class="chain-container">
        <div v-if="chainData" class="chain-body">
          <div class="chain-meta">
            <el-tag>总日志数: {{ chainData.total_logs }}</el-tag>
            <el-tag v-if="chainData.latest_timestamp" type="info">
              最新日志: {{ chainData.latest_timestamp }}
            </el-tag>
          </div>

          <div v-if="chainValid" class="chain-section">
            <div class="chain-visual">
              <div
                v-for="(node, i) in chainNodes"
                :key="i"
                class="chain-node"
                :class="{ active: node.lit }"
                :style="{ animationDelay: i * 0.15 + 's' }"
              >
                <span class="chain-dot"></span>
                <span class="chain-label">#{{ node.id }}</span>
              </div>
            </div>
            <el-result icon="success" title="哈希链完整" sub-title="所有审计日志未被篡改" />
          </div>

          <div v-else class="chain-section">
            <div class="chain-visual">
              <div
                v-for="(node, i) in chainNodes"
                :key="i"
                class="chain-node"
                :class="{
                  valid: i < brokenIndex,
                  broken: i === brokenIndex,
                  pending: i > brokenIndex
                }"
              >
                <span class="chain-dot"></span>
                <span class="chain-label">#{{ node.id }}</span>
              </div>
            </div>
            <el-alert
              type="error"
              :title="'哈希链在日志 #' + chainData.broken_at + ' 处断裂'"
              :description="'前一条日志哈希值与 #' + chainData.broken_at + ' 的 previous_hash 不匹配，可能存在篡改'"
              show-icon
              style="margin-top: 16px;"
            />
            <div class="hash-detail" v-if="chainData.expected_hash">
              <p><strong>预期 previous_hash:</strong> <code>{{ chainData.expected_hash }}</code></p>
              <p><strong>实际 previous_hash:</strong> <code>{{ chainData.actual_hash }}</code></p>
            </div>
          </div>
        </div>
        <div v-else class="chain-loading">
          <div class="loading-content">
            <el-icon class="loading-icon"><Loading /></el-icon>
            <span class="loading-text">正在验证哈希链完整性...</span>
          </div>
        </div>
      </div>
      <template #footer>
        <el-button @click="showChainDialog = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onErrorCaptured } from 'vue'
import request from '../utils/request'
import { ElMessage } from 'element-plus'
import { Key, Loading } from '@element-plus/icons-vue'

onErrorCaptured((err, instance, info) => {
  console.error('[AuditLog Error]', err, info)
  return false
})

const auditLogs = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const loading = ref(false)
const logTypeFilter = ref('')

const showChainDialog = ref(false)
const verifying = ref(false)
const chainData = ref(null)
const chainValid = ref(false)
const chainNodes = ref([])
const brokenIndex = ref(-1)

const logTypeMapping = {
  // 认证相关
  'SM2_LOGIN_SUCCESS': { text: 'SM2静默认证', type: 'success' },
  'SM2_LOGIN_FAIL': { text: 'SM2认证失败', type: 'danger' },
  'SM2_LOGIN_MISSING': { text: 'SM2密钥缺失', type: 'warning' },
  'SM2_LOGIN_SKIPPED': { text: 'SM2未配置', type: 'info' },
  'SM2_KEY_AUTO_GENERATED': { text: 'SM2自动配置', type: 'success' },
  'SM2_KEY_AUTO_GEN_FAILED': { text: 'SM2生成失败', type: 'danger' },
  'SM2_KEY_UPLOAD': { text: 'SM2公钥上传', type: 'success' },
  'SM2_AUTH_FAIL': { text: 'SM2验签失败', type: 'danger' },
  // 资产操作
  'asset_create': { text: '资产创建', type: 'success' },
  'asset_delete': { text: '资产删除', type: 'danger' },
  'asset_restore': { text: '资产恢复', type: 'success' },
  // 密码操作
  'password_view': { text: '密码查看', type: 'primary' },
  'PASSWORD_VIEW_MYSQL': { text: '密码查看(MySQL)', type: 'primary' },
  'PASSWORD_VIEW_WINDOWS': { text: '密码查看(WinRM)', type: 'primary' },
  'password_update': { text: '密码更新', type: 'warning' },
  'password_change': { text: '密码变更', type: 'warning' },
  'rotation': { text: '密码改密', type: 'success' },
  'key_rotation': { text: '密钥轮换', type: 'warning' },
  // 会话
  'SESSION_START': { text: 'SSH会话', type: 'info' },
  'session_start': { text: '会话开始', type: 'info' },
  'session_end': { text: '会话结束', type: 'info' },
  'WINRM_SESSION_START': { text: 'WinRM会话', type: 'info' },
  'WINRM_COMMAND_EXEC': { text: 'WinRM命令', type: 'info' },
  // 安全/绕行
  'bypass_check': { text: '绕行检查', type: 'info' },
  'bypass_detected': { text: '绕行告警', type: 'danger' },
  'firewall_block': { text: '防火墙拦截', type: 'danger' },
  // 代理
  'MYSQL_PROXY_CONNECT': { text: '代理连接', type: 'info' },
  'MYSQL_PROXY_AUTH_FAIL': { text: '代理认证失败', type: 'danger' },
  'MYSQL_PROXY_AUTH_SUCCESS': { text: '代理认证成功', type: 'success' },
  'MYSQL_PROXY_SQL_DENY': { text: '高危SQL拦截', type: 'danger' },
  'MYSQL_PROXY_SQL_ERROR': { text: 'SQL执行错误', type: 'warning' },
  // 系统
  'system_notice': { text: '系统通知', type: 'info' },
  'connectivity_test': { text: '连接测试', type: 'info' },
  'user_management': { text: '用户管理', type: 'warning' }
}

const getLogTypeText = (logType) => {
  return logTypeMapping[logType]?.text || logType
}

const getLogTypeTagType = (logType) => {
  return logTypeMapping[logType]?.type || 'info'
}

const getAuditLogs = async () => {
  loading.value = true
  const params = {
    page: currentPage.value,
    page_size: pageSize.value
  }
  if (logTypeFilter.value) {
    params.log_type = logTypeFilter.value
  }
  try {
    const response = await request.get('/audit/logs', { params })
    if (response.code === 200) {
      auditLogs.value = response.data.items
      total.value = response.data.total
    }
  } catch (error) {
    console.error('获取审计日志失败:', error)
  } finally {
    loading.value = false
  }
}

const handleSizeChange = (size) => {
  pageSize.value = size
  getAuditLogs()
}

const handleCurrentChange = (current) => {
  currentPage.value = current
  getAuditLogs()
}

const handleFilterChange = () => {
  currentPage.value = 1
  getAuditLogs()
}

const verifyChain = async () => {
  verifying.value = true
  showChainDialog.value = true
  chainData.value = null
  chainNodes.value = []

  try {
    const res = await request.get('/audit/verify')
    if (res.code === 200) {
      const data = res.data
      chainData.value = data
      chainValid.value = data.valid

      const nodeCount = Math.min(data.total_logs || 20, 15)
      chainNodes.value = Array.from({ length: nodeCount }, (_, i) => ({
        id: i + 1,
        lit: false
      }))

      if (data.valid) {
        for (let i = 0; i < chainNodes.value.length; i++) {
          setTimeout(() => {
            chainNodes.value[i].lit = true
          }, i * 150)
        }
      } else {
        const totalLogs = data.total_logs || chainNodes.value.length
        const ratio = totalLogs > 0 ? chainNodes.value.length / totalLogs : 1
        brokenIndex.value = Math.min(
          Math.floor((data.broken_at - 1) * ratio),
          chainNodes.value.length - 1
        )
      }
    } else {
      ElMessage.error('验证失败')
    }
  } catch (error) {
    console.error('验证失败:', error)
    ElMessage.error('验证请求失败')
  } finally {
    verifying.value = false
  }
}

onMounted(() => {
  getAuditLogs()
})
</script>

<style scoped>
.audit-log-container {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}

.card-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.card-header-actions {
  display: flex;
  align-items: center;
}

.pagination-container {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.chain-container {
  min-height: 200px;
}

.chain-body {
  width: 100%;
}

.chain-meta {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  justify-content: center;
}

.chain-section {
  width: 100%;
}

.chain-visual {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
  padding: 20px;
}

.chain-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}

.chain-dot {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: #ddd;
  transition: background 0.3s, box-shadow 0.3s;
}

.chain-node.active .chain-dot {
  background: #67c23a;
  box-shadow: 0 0 8px #67c23a;
}

.chain-node.valid .chain-dot {
  background: #67c23a;
}

.chain-node.broken .chain-dot {
  background: #f56c6c;
  box-shadow: 0 0 12px #f56c6c;
  animation: pulse-red 1s infinite;
}

.chain-node.pending .chain-dot {
  background: #e0e0e0;
}

.chain-label {
  font-size: 11px;
  color: #909399;
}

.hash-detail {
  margin-top: 12px;
  padding: 12px;
  background: #fdf6ec;
  border-radius: 8px;
  border: 1px solid #e6a23c;
}

.hash-detail p {
  margin: 8px 0;
  word-break: break-all;
}

.hash-detail code {
  font-size: 12px;
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 4px;
  color: #606266;
}

.chain-loading {
  min-height: 150px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.loading-content {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 20px;
  background: rgba(15, 23, 42, 0.2);
  border: 1px solid rgba(56, 189, 248, 0.1);
  border-radius: 12px;
  animation: pulse-bg 1.5s ease-in-out infinite;
}

.loading-icon {
  font-size: 20px;
  color: #38bdf8;
  animation: spin 1.2s linear infinite;
}

.loading-text {
  font-size: 14px;
  color: #606266;
}

@keyframes pulse-red {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.3); }
}

@keyframes pulse-bg {
  0%, 100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.3); }
  50% { box-shadow: 0 0 0 10px rgba(56, 189, 248, 0); }
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>