<template>
  <div class="recycle-bin-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>回收站</h2>
        </div>
      </template>

      <el-tabs v-model="activeTab" @tab-change="handleTabChange">
        <el-tab-pane label="已删除资产" name="assets">
          <el-table :data="deletedAssets" border stripe v-loading="assetsLoading" style="width: 100%" @selection-change="handleAssetSelectionChange">
            <el-table-column type="selection" width="50" />
            <el-table-column prop="hostname" label="名称" min-width="140" />
            <el-table-column prop="ip" label="IP" width="140" />
            <el-table-column prop="os_type" label="类型" width="100">
              <template #default="s">
                <el-tag>{{ s.row.os_type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="updated_at" label="删除时间" width="180" />
            <el-table-column label="操作" width="200" fixed="right">
              <template #default="s">
                <el-button size="small" type="success" @click="restoreAsset(s.row.id)">恢复</el-button>
                <el-button size="small" type="danger" @click="purgeAsset(s.row.id)">彻底删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="deletedAssets.length === 0 && !assetsLoading"
                    description="回收站为空，删除的资产将出现在这里"
                    :image-size="120" />
          <div class="batch-actions" v-if="deletedAssets.length > 0">
            <el-button type="success" @click="batchRestoreAssets">批量恢复</el-button>
            <el-button type="danger" @click="batchPurgeAssets">批量彻底删除</el-button>
          </div>
          <el-pagination
            v-if="assetTotal > 0"
            v-model:current-page="assetPage"
            v-model:page-size="assetPageSize"
            :total="assetTotal"
            layout="total, prev, pager, next"
            @current-change="loadDeletedAssets"
          />
        </el-tab-pane>

        <el-tab-pane label="已删除日志" name="logs">
          <el-table :data="deletedLogs" border stripe v-loading="logsLoading" style="width: 100%" @selection-change="handleLogSelectionChange">
            <el-table-column type="selection" width="50" />
            <el-table-column prop="id" label="ID" width="70" />
            <el-table-column prop="log_type" label="类型" width="120">
              <template #default="s">
                <el-tag>{{ s.row.log_type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="operator" label="操作人" width="100" />
            <el-table-column prop="operation_detail" label="详情" min-width="200" />
            <el-table-column prop="created_at" label="时间" width="160" />
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="s">
                <el-button size="small" type="success" @click="restoreLog(s.row.id)">恢复</el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="deletedLogs.length === 0 && !logsLoading"
                    description="暂无已删除的日志记录"
                    :image-size="120" />
          <div class="batch-actions" v-if="deletedLogs.length > 0">
            <el-button type="success" @click="batchRestoreLogs">批量恢复</el-button>
          </div>
          <el-pagination
            v-if="logTotal > 0"
            v-model:current-page="logPage"
            v-model:page-size="logPageSize"
            :total="logTotal"
            layout="total, prev, pager, next"
            @current-change="loadDeletedLogs"
          />
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import request from '../utils/request'
import { ElMessage, ElMessageBox } from 'element-plus'

const activeTab = ref('assets')

const deletedAssets = ref([])
const assetsLoading = ref(false)
const assetPage = ref(1)
const assetPageSize = ref(10)
const assetTotal = ref(0)

const deletedLogs = ref([])
const logsLoading = ref(false)
const logPage = ref(1)
const logPageSize = ref(10)
const logTotal = ref(0)

const selectedAssets = ref([])
const selectedLogs = ref([])

const handleAssetSelectionChange = (rows) => {
  selectedAssets.value = rows.map(r => r.id)
}
const handleLogSelectionChange = (rows) => {
  selectedLogs.value = rows.map(r => r.id)
}

const loadDeletedAssets = async () => {
  assetsLoading.value = true
  try {
    const res = await request.get('/assets/deleted', {
      params: { page: assetPage.value, page_size: assetPageSize.value }
    })
    if (res.code === 200) {
      deletedAssets.value = res.data.items
      assetTotal.value = res.data.total
    }
  } catch (err) {
    console.error(err)
    ElMessage.error('加载失败，请检查网络连接')
  } finally {
    assetsLoading.value = false
  }
}

const loadDeletedLogs = async () => {
  logsLoading.value = true
  try {
    const res = await request.get('/audit/logs/deleted', {
      params: { page: logPage.value, page_size: logPageSize.value }
    })
    if (res.code === 200) {
      deletedLogs.value = res.data.items
      logTotal.value = res.data.total
    }
  } catch (err) {
    console.error(err)
    ElMessage.error('加载失败，请检查网络连接')
  } finally {
    logsLoading.value = false
  }
}

const restoreAsset = async (id) => {
  try {
    const res = await request.post(`/assets/${id}/restore`)
    if (res.code === 200) {
      ElMessage.success('资产已恢复')
      loadDeletedAssets()
    }
  } catch (err) {
    ElMessage.error('恢复失败')
  }
}

const purgeAsset = async (id) => {
  try {
    await ElMessageBox.confirm('确定要彻底删除此资产及所有关联数据？此操作不可恢复！', '警告', {
      confirmButtonText: '确认删除', cancelButtonText: '取消', type: 'warning'
    })
    const res = await request.delete('/assets/purge', { data: { ids: [id] } })
    if (res.code === 200) {
      ElMessage.success('已彻底删除')
      loadDeletedAssets()
    }
  } catch (err) {
    if (err !== 'cancel') {
      ElMessage.error('彻底删除失败')
    }
  }
}

const batchRestoreAssets = async () => {
  if (selectedAssets.value.length === 0) {
    ElMessage.warning('请至少选择一项')
    return
  }
  try {
    const res = await request.post('/assets/batch-restore', { ids: selectedAssets.value })
    if (res.code === 200) {
      ElMessage.success(res.message || '批量恢复成功')
      selectedAssets.value = []
      loadDeletedAssets()
    }
  } catch (err) {
    ElMessage.error('批量恢复失败')
  }
}

const batchPurgeAssets = async () => {
  if (selectedAssets.value.length === 0) {
    ElMessage.warning('请至少选择一项')
    return
  }
  try {
    await ElMessageBox.confirm(`确定彻底删除 ${selectedAssets.value.length} 项？此操作不可恢复！`, '警告', {
      confirmButtonText: '确认删除', cancelButtonText: '取消', type: 'warning'
    })
    const res = await request.delete('/assets/purge', { data: { ids: selectedAssets.value } })
    if (res.code === 200) {
      ElMessage.success(res.message || '批量彻底删除成功')
      selectedAssets.value = []
      loadDeletedAssets()
    }
  } catch (err) {
    if (err !== 'cancel') {
      ElMessage.error('批量彻底删除失败')
    }
  }
}

const restoreLog = async (id) => {
  try {
    const res = await request.post(`/audit/logs/${id}/restore`)
    if (res.code === 200) {
      ElMessage.success('日志已恢复')
      loadDeletedLogs()
    }
  } catch (err) {
    ElMessage.error('恢复失败')
  }
}

const batchRestoreLogs = async () => {
  if (selectedLogs.value.length === 0) {
    ElMessage.warning('请至少选择一项')
    return
  }
  try {
    const res = await request.put('/audit/logs/batch-restore', { ids: selectedLogs.value })
    if (res.code === 200) {
      ElMessage.success(res.message || '批量恢复成功')
      selectedLogs.value = []
      loadDeletedLogs()
    }
  } catch (err) {
    ElMessage.error('批量恢复失败')
  }
}

const handleTabChange = (tab) => {
  if (tab === 'logs') loadDeletedLogs()
  if (tab === 'assets') loadDeletedAssets()
}

onMounted(() => {
  loadDeletedAssets()
})
</script>

<style scoped>
.recycle-bin-container { padding: 0; }
.card-header h2 { margin: 0; font-size: 18px; font-weight: 600; }
.batch-actions { margin-top: 16px; display: flex; gap: 12px; }
</style>