<template>
  <div class="compliance-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>国密合规自检报告</h2>
          <el-button type="primary" @click="loadReport()" :loading="loading">
            刷新报告
          </el-button>
        </div>
      </template>

      <div v-if="report" class="report-body">
        <div class="report-summary">
          <div class="grade-section">
            <div class="grade-badge" :class="gradeClass">{{ report.grade }}</div>
            <div class="grade-text">
              <h3>{{ gradeText }}</h3>
              <p>通过 {{ report.pass_count }}/{{ report.total }} 项检查</p>
              <p class="timestamp">生成时间: {{ report.generated_at }}</p>
            </div>
          </div>
        </div>

        <el-divider />

        <div class="checks-list">
          <div v-for="check in report.checks" :key="check.id" class="check-item">
            <div class="check-header">
              <el-tag :type="tagType(check.status)" effect="dark" class="check-status-tag">
                {{ statusText(check.status) }}
              </el-tag>
              <span class="check-name">{{ check.name }}</span>
            </div>
            <div class="check-detail">{{ check.detail }}</div>
          </div>
        </div>

        <div v-if="totalChecks > pageSize" class="pagination-wrapper">
          <el-pagination
            v-model:current-page="currentPage"
            :page-size="pageSize"
            :total="totalChecks"
            layout="total, prev, pager, next"
            @current-change="handlePageChange"
          />
        </div>
      </div>

      <div v-else-if="!loading" class="empty-state">
        <el-empty description="点击「刷新报告」开始自检" />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import request from '../utils/request'

const loading = ref(false)
const report = ref(null)
const currentPage = ref(1)
const pageSize = ref(10)
const totalChecks = ref(0)

const gradeClass = computed(() => {
  if (!report.value) return ''
  const g = report.value.grade
  if (g === 'A') return 'grade-a'
  if (g === 'B') return 'grade-b'
  if (g === 'C') return 'grade-c'
  return 'grade-d'
})

const gradeText = computed(() => {
  if (!report.value) return ''
  const g = report.value.grade
  if (g === 'A') return '优秀 - 全面合规'
  if (g === 'B') return '良好 - 基本合规'
  if (g === 'C') return '一般 - 部分不合规'
  return '不合格 - 需立即整改'
})

const tagType = (status) => {
  if (status === 'pass') return 'success'
  if (status === 'warn') return 'warning'
  return 'danger'
}

const statusText = (status) => {
  if (status === 'pass') return '通过'
  if (status === 'warn') return '警告'
  return '未通过'
}

const loadReport = async (page = 1) => {
  loading.value = true
  currentPage.value = page
  try {
    const res = await request.get(`/compliance/report?page=${page}&page_size=${pageSize.value}`)
    if (res.code === 200) {
      report.value = res.data
      totalChecks.value = res.data.total_checks || 0
    }
  } catch (err) {
    console.error('获取合规报告失败:', err)
  } finally {
    loading.value = false
  }
}

const handlePageChange = (page) => {
  loadReport(page)
}
</script>

<style scoped>
.compliance-container {
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
}

.report-summary {
  display: flex;
  justify-content: center;
  padding: 20px 0;
}

.grade-section {
  display: flex;
  align-items: center;
  gap: 24px;
}

.grade-badge {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 36px;
  font-weight: 700;
  color: #fff;
}

.grade-a { background: linear-gradient(135deg, #67c23a, #85ce61); }
.grade-b { background: linear-gradient(135deg, #409eff, #79bbff); }
.grade-c { background: linear-gradient(135deg, #e6a23c, #f4d19b); }
.grade-d { background: linear-gradient(135deg, #f56c6c, #fab6b6); }

.grade-text h3 {
  margin: 0 0 4px;
  font-size: 18px;
  color: #303133;
}

.grade-text p {
  margin: 2px 0;
  color: #909399;
  font-size: 14px;
}

.timestamp { font-size: 12px !important; }

.checks-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.check-item {
  padding: 16px;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  transition: box-shadow 0.2s;
}

.check-item:hover {
  box-shadow: 0 2px 12px rgba(0,0,0,0.06);
}

.check-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.check-status-tag {
  flex-shrink: 0;
}

.check-name {
  font-weight: 600;
  font-size: 15px;
  color: #303133;
}

.check-detail {
  font-size: 13px;
  color: #606266;
  line-height: 1.6;
  padding-left: 4px;
}

.empty-state {
  padding: 60px 0;
}

.pagination-wrapper {
  display: flex;
  justify-content: center;
  padding: 20px 0 0;
}
</style>