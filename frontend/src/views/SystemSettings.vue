<template>
  <div class="system-settings-container">
    <el-tabs v-model="activeTab" type="border-card">
      <!-- Tab 1: 密码策略 -->
      <el-tab-pane label="密码策略" name="policy">
        <el-card shadow="never">
          <template #header>
            <div class="card-header"><h2>密码策略配置</h2></div>
          </template>
          <el-form :model="policyForm" label-width="140px" :rules="rules" ref="policyFormRef">
            <el-form-item label="最小长度" prop="min_length">
              <el-input-number v-model="policyForm.min_length" :min="6" :max="100" :step="1" />
            </el-form-item>
            <el-form-item label="必须包含大写字母" prop="require_upper">
              <el-switch v-model="policyForm.require_upper" />
            </el-form-item>
            <el-form-item label="必须包含小写字母" prop="require_lower">
              <el-switch v-model="policyForm.require_lower" />
            </el-form-item>
            <el-form-item label="必须包含数字" prop="require_digit">
              <el-switch v-model="policyForm.require_digit" />
            </el-form-item>
            <el-form-item label="必须包含特殊字符" prop="require_special">
              <el-switch v-model="policyForm.require_special" />
            </el-form-item>
            <el-form-item label="特殊字符集" prop="special_chars">
              <el-input v-model="policyForm.special_chars" placeholder="输入特殊字符" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="handleSave" :loading="loading">保存策略</el-button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <!-- Tab 2: 定时改密 -->
      <el-tab-pane label="定时改密计划" name="schedules">
        <el-card shadow="never">
          <template #header>
            <div class="card-header">
              <h2>定时改密计划</h2>
              <el-button type="primary" @click="openCreateDialog">新增计划</el-button>
            </div>
          </template>

          <el-table :data="schedules" stripe style="width: 100%" v-loading="scheduleLoading">
            <el-table-column prop="name" label="计划名称" min-width="160" />
            <el-table-column label="目标范围" min-width="200">
              <template #default="{ row }">
                <template v-if="row.asset_ids && row.asset_ids.length">
                  <el-tag v-for="id in row.asset_ids" :key="id" size="small" type="info" style="margin: 2px">
                    {{ getAssetLabel(id) }}
                  </el-tag>
                </template>
                <template v-else-if="row.asset_types && row.asset_types.length">
                  <el-tag v-for="t in row.asset_types" :key="t" size="small" style="margin: 2px">{{ t }}</el-tag>
                </template>
                <span v-else style="color: #909399">全部资产</span>
              </template>
            </el-table-column>
            <el-table-column label="Cron 表达式" width="150">
              <template #default="{ row }">
                <code style="background: #f5f7fa; padding: 2px 6px; border-radius: 3px">{{ row.cron }}</code>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="80">
              <template #default="{ row }">
                <el-switch :model-value="row.enabled" @change="(v) => toggleSchedule(row, v)" :loading="row._toggling" />
              </template>
            </el-table-column>
            <el-table-column label="创建时间" width="170">
              <template #default="{ row }">{{ row.created_at || '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="140" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" size="small" @click="openEditDialog(row)">编辑</el-button>
                <el-button link type="danger" size="small" @click="confirmDelete(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>

      <!-- Tab 3: 密钥管理 -->
      <el-tab-pane label="密钥管理" name="keys">
        <!-- 密钥概览卡片 -->
        <el-row :gutter="20">
          <el-col :span="6">
            <el-card>
              <div class="stat-label">活跃密钥 ID</div>
              <div class="stat-value">{{ keyStatus.active_key_id }}</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card>
              <div class="stat-label">密钥版本总数</div>
              <div class="stat-value">{{ keyStatus.total_key_versions }}</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card>
              <div class="stat-label">已加密凭证数</div>
              <div class="stat-value">{{ keyStatus.encrypted_credentials_count }}</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card>
              <div class="stat-label">轮换状态</div>
              <div class="stat-value">{{ rotationStatLabel }}</div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 轮换进度条（仅在轮换进行中显示）-->
        <div v-if="rotationProgress && rotationProgress.active_rotation" class="rotation-progress">
          <el-alert type="info" title="密钥轮换进行中" :closable="false" />
          <el-progress
            :percentage="rotationProgress.progress_pct"
            :text-inside="true"
            :stroke-width="20"
            status="success"
          />
          <p class="progress-detail">
            已迁移 {{ rotationProgress.migrated_count }} / {{ rotationProgress.total_credentials }} 条凭证，
            剩余 {{ rotationProgress.remaining_count }} 条
          </p>
        </div>

        <!-- 操作按钮 -->
        <el-button type="warning" @click="rotateKey" :loading="rotatingKey">
          手动轮换密钥
        </el-button>
        <el-button @click="refreshKeyStatus" :loading="loadingKeyStatus">
          刷新状态
        </el-button>
      </el-tab-pane>
    </el-tabs>

    <!-- 创建/编辑对话框 -->
    <el-dialog v-model="dialogVisible" :title="isEditing ? '编辑改密计划' : '新增改密计划'" width="560px">
      <el-form :model="form" label-width="110px">
        <el-form-item label="计划名称" required>
          <el-input v-model="form.name" placeholder="例如：每日凌晨SSH改密" maxlength="50" />
        </el-form-item>
        <el-form-item label="资产类型">
          <el-checkbox-group v-model="form.asset_types">
            <el-checkbox label="ubuntu">Ubuntu</el-checkbox>
            <el-checkbox label="centos">CentOS</el-checkbox>
            <el-checkbox label="debian">Debian</el-checkbox>
            <el-checkbox label="rhel">RHEL</el-checkbox>
            <el-checkbox label="linux">Linux</el-checkbox>
            <el-checkbox label="mysql">MySQL</el-checkbox>
            <el-checkbox label="windows">Windows</el-checkbox>
          </el-checkbox-group>
          <span class="form-hint">不选则匹配全部类型</span>
        </el-form-item>
        <el-form-item label="指定资产">
          <el-select v-model="form.asset_ids" multiple filterable placeholder="不选则匹配全部资产" style="width: 100%">
            <el-option v-for="a in assetOptions" :key="a.id" :label="a.label" :value="a.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="Cron 表达式" required>
          <el-input v-model="form.cron" placeholder="分 时 日 月 周（例如 0 2 * * *）" />
          <div class="cron-presets">
            <span class="form-hint">快捷设置：</span>
            <el-button v-for="p in cronPresets" :key="p.label" link size="small" type="primary" @click="form.cron = p.value">{{ p.label }}</el-button>
          </div>
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleSubmit" :loading="submitting">
          {{ isEditing ? '保存修改' : '创建计划' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import request from '../utils/request'

const activeTab = ref('policy')

// ── 密钥管理 ──
const keyStatus = ref({ active_key_id: '-', total_key_versions: 0, encrypted_credentials_count: 0 })
const rotationProgress = ref(null)
const loadingKeyStatus = ref(false)
const rotatingKey = ref(false)

const rotationStatLabel = computed(() => {
  if (rotationProgress.value && rotationProgress.value.active_rotation) return '轮换中'
  return '就绪'
})

// ── 策略表单 ──
const policyForm = reactive({
  min_length: 16,
  require_upper: true,
  require_lower: true,
  require_digit: true,
  require_special: true,
  special_chars: '!@#$%^&*()_+-=[]{}|;:,.<>?'
})

const loading = ref(false)
const policyFormRef = ref(null)

const rules = {
  min_length: [{ required: true, message: '请输入最小长度', trigger: 'blur' }],
  special_chars: [{ required: true, message: '请输入特殊字符集', trigger: 'blur' }]
}

const loadPolicy = async () => {
  try {
    const res = await request.get('/system/policy')
    if (res.code === 200) {
      Object.assign(policyForm, res.data)
    }
  } catch (error) {
    console.error('加载策略失败:', error)
  }
}

const handleSave = async () => {
  if (!policyFormRef.value) return
  try {
    await policyFormRef.value.validate()
    loading.value = true
    const res = await request.post('/system/policy', policyForm)
    if (res.code === 200) {
      ElMessage.success('策略已更新')
    } else {
      ElMessage.error(res.message || '保存失败')
    }
  } catch (error) {
    if (error.message) {
      ElMessage.error(error.message)
    } else {
      ElMessage.error('保存失败')
    }
  } finally {
    loading.value = false
  }
}

// ── 调度管理 ──
const schedules = ref([])
const scheduleLoading = ref(false)
const dialogVisible = ref(false)
const isEditing = ref(false)
const editingId = ref(null)
const submitting = ref(false)
const assetOptions = ref([])

const cronPresets = [
  { label: '每天凌晨2:00', value: '0 2 * * *' },
  { label: '每天中午12:00', value: '0 12 * * *' },
  { label: '每30分钟', value: '*/30 * * * *' },
  { label: '每小时', value: '0 * * * *' },
  { label: '每周一凌晨3:00', value: '0 3 * * 1' }
]

const form = reactive({
  name: '',
  asset_types: [],
  asset_ids: [],
  cron: '0 2 * * *',
  enabled: true
})

const getAssetLabel = (id) => {
  const found = assetOptions.value.find(a => a.id === id)
  return found ? found.label : `#${id}`
}

const loadSchedules = async () => {
  scheduleLoading.value = true
  try {
    const res = await request.get('/rotation/schedules')
    if (res.code === 200) {
      schedules.value = res.data.map(s => ({ ...s, _toggling: false }))
    }
  } catch (error) {
    console.error('加载调度列表失败:', error)
  } finally {
    scheduleLoading.value = false
  }
}

const loadAssetOptions = async () => {
  try {
    const res = await request.get('/rotation/schedules/asset-options')
    if (res.code === 200) {
      assetOptions.value = res.data
    }
  } catch (error) {
    console.error('加载资产列表失败:', error)
  }
}

const resetForm = () => {
  form.name = ''
  form.asset_types = []
  form.asset_ids = []
  form.cron = '0 2 * * *'
  form.enabled = true
  isEditing.value = false
  editingId.value = null
}

const openCreateDialog = () => {
  resetForm()
  dialogVisible.value = true
}

const openEditDialog = (row) => {
  isEditing.value = true
  editingId.value = row.id
  form.name = row.name
  form.asset_types = [...(row.asset_types || [])]
  form.asset_ids = [...(row.asset_ids || [])]
  form.cron = row.cron
  form.enabled = row.enabled
  dialogVisible.value = true
}

const handleSubmit = async () => {
  if (!form.name.trim()) {
    ElMessage.warning('请输入计划名称')
    return
  }
  const parts = form.cron.trim().split(/\s+/)
  if (parts.length !== 5) {
    ElMessage.warning('Cron表达式格式错误（需5段：分 时 日 月 周）')
    return
  }

  submitting.value = true
  try {
    const payload = {
      name: form.name.trim(),
      asset_types: form.asset_types,
      asset_ids: form.asset_ids,
      cron: form.cron.trim(),
      enabled: form.enabled
    }
    let res
    if (isEditing.value) {
      res = await request.put(`/rotation/schedules/${editingId.value}`, payload)
    } else {
      res = await request.post('/rotation/schedules', payload)
    }
    if (res.code === 200) {
      ElMessage.success(isEditing.value ? '计划已更新' : '计划已创建')
      dialogVisible.value = false
      loadSchedules()
    } else {
      ElMessage.error(res.message || '操作失败')
    }
  } catch (error) {
    ElMessage.error('操作失败')
  } finally {
    submitting.value = false
  }
}

const toggleSchedule = async (row, enabled) => {
  row._toggling = true
  try {
    const res = await request.put(`/rotation/schedules/${row.id}`, { enabled })
    if (res.code === 200) {
      row.enabled = enabled
      ElMessage.success(enabled ? '已启用' : '已停用')
    } else {
      ElMessage.error(res.message || '操作失败')
    }
  } catch (error) {
    ElMessage.error('操作失败')
  } finally {
    row._toggling = false
  }
}

const confirmDelete = (row) => {
  ElMessageBox.confirm(`确定删除改密计划「${row.name}」吗？此操作不可恢复。`, '确认删除', {
    confirmButtonText: '删除',
    cancelButtonText: '取消',
    type: 'warning'
  }).then(async () => {
    try {
      const res = await request.delete(`/rotation/schedules/${row.id}`)
      if (res.code === 200) {
        ElMessage.success('已删除')
        loadSchedules()
      } else {
        ElMessage.error(res.message || '删除失败')
      }
    } catch (error) {
      ElMessage.error('删除失败')
    }
  }).catch(() => {})
}

// ── 密钥管理 ──
const refreshKeyStatus = async () => {
  loadingKeyStatus.value = true
  try {
    const res = await request.get('/keys/status')
    if (res.code === 200) {
      keyStatus.value = res.data
      rotationProgress.value = res.data.rotation_progress
    }
  } catch (error) {
    console.error('加载密钥状态失败:', error)
  } finally {
    loadingKeyStatus.value = false
  }
}

const rotateKey = async () => {
  rotatingKey.value = true
  try {
    const res = await request.post('/keys/rotate')
    if (res.code === 200) {
      ElMessage.success('密钥轮换已触发')
      refreshKeyStatus()
    } else {
      ElMessage.error(res.message || '轮换失败')
    }
  } catch (error) {
    ElMessage.error('轮换失败')
  } finally {
    rotatingKey.value = false
  }
}

onMounted(() => {
  loadPolicy()
  loadSchedules()
  loadAssetOptions()
  refreshKeyStatus()
})
</script>

<style scoped>
.system-settings-container {
  padding: 20px;
  min-height: calc(100vh - 60px);
  background: #f5f7fa;
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
  color: #303133;
}

.el-form-item {
  margin-bottom: 20px;
}

.form-hint {
  font-size: 12px;
  color: #909399;
  margin-left: 8px;
}

.cron-presets {
  margin-top: 6px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 2px;
}

.stat-label { font-size: 13px; color: #909399; margin-bottom: 8px; }
.stat-value { font-size: 24px; font-weight: 600; color: #303133; }
.rotation-progress { margin: 20px 0; }
.progress-detail { margin-top: 10px; color: #606266; font-size: 13px; }
</style>