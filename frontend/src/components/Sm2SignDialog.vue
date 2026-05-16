<template>
  <el-dialog v-model="visible" title="高危操作确认" width="420px"
    :close-on-click-modal="false" :close-on-press-escape="false" :show-close="false"
  >
    <div>
      <p style="color:#dc2626;font-weight:bold;margin-bottom:12px;">
        此操作为高危命令，需要进行数字签名确认
      </p>
      <p style="color:#666;font-size:13px;margin-bottom:16px;">
        命令: {{ command }}
      </p>
      <p style="color:#666;font-size:13px;margin-bottom:12px;">
        请输入账户密码以进行数字签名：
      </p>
      <el-input
        ref="passwordInput"
        v-model="password"
        type="password"
        show-password
        placeholder="请输入账户密码"
        @keydown.enter.prevent="submit"
      />
      <div v-if="errorMsg" style="color:#dc2626;font-size:12px;margin-top:8px;">
        {{ errorMsg }}
      </div>
    </div>
    <template #footer>
      <el-button @click="handleCancel">取消</el-button>
      <el-button type="danger" :disabled="!password.trim()" @click="submit">
        确认签名
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, watch, nextTick } from 'vue'
import { loadAndDecryptPrivateKey, signChallenge } from '../utils/sm2-utils'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  command: { type: String, default: '' },
  challenge: { type: Object, default: null }
})

const emit = defineEmits(['update:modelValue', 'signed', 'cancelled'])

const visible = ref(false)
const password = ref('')
const errorMsg = ref('')
const attempts = ref(0)
const passwordInput = ref(null)

watch(() => props.modelValue, (val) => {
  visible.value = val
  if (val) {
    password.value = ''
    errorMsg.value = ''
    attempts.value = 0
    nextTick(() => passwordInput.value?.focus())
  }
})

watch(visible, (val) => {
  if (!val) emit('update:modelValue', false)
})

const submit = async () => {
  const pwd = password.value.trim()
  if (!pwd) return

  try {
    const privateKey = await loadAndDecryptPrivateKey(pwd)
    if (!privateKey) {
      attempts.value++
      if (attempts.value >= 3) {
        errorMsg.value = '密码错误已达3次，操作已取消'
        setTimeout(() => handleCancel(), 2000)
        return
      }
      errorMsg.value = `密码错误，请重试（剩余${3 - attempts.value}次）`
      return
    }

    const signature = signChallenge(props.challenge, privateKey)
    emit('signed', { signature, nonce: props.challenge?.nonce })
    close()
  } catch (e) {
    attempts.value++
    if (attempts.value >= 3) {
      errorMsg.value = '密码错误已达3次，操作已取消'
      setTimeout(() => handleCancel(), 2000)
    } else {
      errorMsg.value = `解密失败，请重试（剩余${3 - attempts.value}次）`
    }
  }
}

const handleCancel = () => {
  emit('cancelled')
  close()
}

const close = () => {
  visible.value = false
  password.value = ''
  errorMsg.value = ''
  attempts.value = 0
}
</script>
