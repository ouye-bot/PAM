<template>
  <div class="rotation-history-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>改密历史</h2>
          <el-button type="primary" link @click="goBack">
            <el-icon><ArrowLeft /></el-icon> 返回资产列表
          </el-button>
        </div>
      </template>

      <div class="asset-info" v-if="assetInfo">
        <el-descriptions :column="3" border>
          <el-descriptions-item label="资产IP">{{ assetInfo.ip }}</el-descriptions-item>
          <el-descriptions-item label="系统类型">
            <el-tag :type="getOsTypeTagType(assetInfo.os_type)" effect="plain">
              {{ assetInfo.os_type }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="SSH端口">{{ assetInfo.ssh_port }}</el-descriptions-item>
        </el-descriptions>
      </div>

      <el-radio-group v-model="viewMode" size="small" style="margin-top: 20px">
        <el-radio-button value="table">表格</el-radio-button>
        <el-radio-button value="timeline">时间线</el-radio-button>
      </el-radio-group>

      <el-table
        v-if="viewMode === 'table'"
        :data="rotationHistory"
        style="width: 100%; margin-top: 20px"
        border
        stripe
        v-loading="loading"
      >
        <el-table-column prop="id" label="任务ID" width="100" />
        <el-table-column prop="account_name" label="账号" width="120" />
        <el-table-column prop="executed_at" label="执行时间" width="160" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.status === 'success' ? 'success' : 'danger'" effect="dark">
              {{ scope.row.status === 'success' ? '成功' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="error_msg" label="错误信息" min-width="200">
          <template #default="scope">
            <span v-if="scope.row.error_msg" style="color: #F56C6C;">{{ scope.row.error_msg }}</span>
            <span v-else style="color: #67C23A;">-</span>
          </template>
        </el-table-column>
      </el-table>

      <el-timeline v-if="viewMode === 'timeline'" style="margin-top: 20px;">
        <el-timeline-item
          v-for="item in rotationHistory"
          :key="item.id"
          :timestamp="item.executed_at"
          :type="item.status === 'success' ? 'success' : 'danger'"
          :hollow="item.status !== 'success'"
        >
          <h4>{{ item.account_name }}</h4>
          <p>{{ item.status === 'success' ? '改密成功' : '改密失败' }}{{ item.error_msg ? ' - ' + item.error_msg : '' }}</p>
        </el-timeline-item>
      </el-timeline>

      <div v-if="rotationHistory.length === 0 && !loading" class="empty-state">
        <el-empty description="暂无改密记录" />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import request from '../utils/request'
import { ElMessage } from 'element-plus'
import { ArrowLeft } from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()

const rotationHistory = ref([])
const assetInfo = ref(null)
const loading = ref(false)
const viewMode = ref('table')

const getOsTypeTagType = (osType) => {
  const typeMap = {
    'Linux': '',
    'Ubuntu': 'success',
    'Debian': 'success',
    'CentOS': 'warning',
    'MySQL': 'danger',
    'Windows': 'info'
  }
  return typeMap[osType] || ''
}

const getRotationHistory = () => {
  const assetId = route.params.assetId
  if (!assetId) {
    ElMessage.warning('请从资产列表进入改密历史页面')
    return
  }

  loading.value = true
  request.get(`/rotation/history/${assetId}`)
    .then(response => {
      if (response.code === 200) {
        rotationHistory.value = response.data
      } else {
        ElMessage.error(response.message || '获取改密历史失败')
      }
      loading.value = false
    })
    .catch(error => {
      console.error('获取改密历史失败:', error)
      loading.value = false
    })
}

const getAssetInfo = () => {
  const assetId = route.params.assetId
  if (!assetId) return

  request.get('/assets')
    .then(response => {
      if (Array.isArray(response)) {
        const asset = response.find(a => a.id === parseInt(assetId))
        if (asset) {
          assetInfo.value = asset
        }
      }
    })
    .catch(error => {
      console.error('获取资产信息失败:', error)
    })
}

const goBack = () => {
  router.push('/assets')
}

onMounted(() => {
  getRotationHistory()
  getAssetInfo()
})
</script>

<style scoped>
.rotation-history-container {
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

.asset-info {
  margin-bottom: var(--spacing-md);
}

.empty-state {
  padding: 60px 0;
}

/* 错误信息样式 */
:deep(.el-table td span[style*="color: #F56C6C;"]) {
  color: var(--danger-color) !important;
}

:deep(.el-table td span[style*="color: #67C23A;"]) {
  color: var(--success-color) !important;
}

.el-timeline { padding: 20px; }
.el-timeline-item__content h4 { margin: 0 0 4px 0; font-size: 14px; }
.el-timeline-item__content p { margin: 0; color: #909399; font-size: 13px; }
</style>
