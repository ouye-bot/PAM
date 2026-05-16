import { ref, computed } from 'vue'
import { ElMessage, ElMessageBox, ElLoading } from 'element-plus'
import request from '../utils/request'

export function useKeyManagement() {
  const keyStatus = ref({ active_key_id: '-', total_key_versions: 0, encrypted_credentials_count: 0 })
  const rotationProgress = ref(null)
  const loadingKeyStatus = ref(false)
  const rotatingKey = ref(false)

  const rotationStatLabel = computed(() => {
    if (rotationProgress.value && rotationProgress.value.active_rotation) return '轮换中'
    return '就绪'
  })

  const fetchKeyStatus = async () => {
    loadingKeyStatus.value = true
    try {
      const res = await request.get('/keys/status')
      if (res.code === 200) {
        keyStatus.value = res.data
        rotationProgress.value = res.data.rotation_progress
      }
    } catch (e) {
      console.error('获取密钥状态失败:', e)
    } finally {
      loadingKeyStatus.value = false
    }
  }

  const rotateKey = async () => {
    try {
      await ElMessageBox.confirm(
        '确定要轮换工作密钥吗？所有密码将使用新密钥重新加密。',
        '警告',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' }
      )
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
        await fetchKeyStatus()
        return res.data
      } else {
        ElMessage.error(res.message || '密钥轮换失败')
      }
    } catch (e) {
      loadingInstance.close()
      console.error('密钥轮换失败:', e)
    } finally {
      rotatingKey.value = false
    }
  }

  return {
    keyStatus,
    rotationProgress,
    loadingKeyStatus,
    rotatingKey,
    rotationStatLabel,
    fetchKeyStatus,
    rotateKey
  }
}
