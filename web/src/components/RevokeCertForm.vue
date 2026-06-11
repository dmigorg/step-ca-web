<template>
  <div class="revoke-form">
    <el-form :model="form" :rules="rules" label-width="120px" @submit.prevent="handleRevoke">
      <el-form-item label="Serial Number" prop="serial">
        <el-input v-model="form.serial" placeholder="e.g., 123456789 or 0x1a2b3c" />
      </el-form-item>

      <el-form-item label="Reason Code" prop="reasonCode">
        <el-select v-model="form.reasonCode" placeholder="Select reason" style="width: 100%;">
          <el-option
            v-for="reason in reasonCodes"
            :key="reason.value"
            :label="reason.label"
            :value="reason.value"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="Reason Text">
        <el-input
          v-model="form.reason"
          type="textarea"
          :rows="2"
          placeholder="Optional: Additional details about the revocation"
        />
      </el-form-item>

      <el-form-item>
        <el-button type="danger" @click="handleRevoke" :loading="isLoading" :icon="Delete">
          Revoke Certificate
        </el-button>
      </el-form-item>
    </el-form>

    <el-alert
      v-if="result"
      :title="resultMessage"
      :type="resultType"
      show-icon
      style="margin-top: 20px;"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { Delete } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { caApi, getErrorMessage } from '@/api/client'

const form = reactive({
  serial: '',
  reasonCode: 0,
  reason: ''
})

const rules = {
  serial: [{ required: true, message: 'Serial number is required', trigger: 'blur' }]
}

const reasonCodes = [
  { value: 0, label: '0 - Unspecified' },
  { value: 1, label: '1 - Key Compromise' },
  { value: 2, label: '2 - CA Compromise' },
  { value: 3, label: '3 - Affiliation Changed' },
  { value: 4, label: '4 - Superseded' },
  { value: 5, label: '5 - Cessation of Operation' },
  { value: 6, label: '6 - Certificate Hold' },
  { value: 8, label: '8 - Remove from CRL' },
  { value: 9, label: '9 - Privilege Withdrawn' },
  { value: 10, label: '10 - AA Compromise' }
]

const isLoading = ref(false)
const result = ref<{ status: string } | null>(null)
const resultError = ref('')

const resultMessage = computed(() => {
  if (resultError.value) return resultError.value
  return result.value ? 'Certificate revoked successfully!' : ''
})

const resultType = computed((): 'success' | 'error' => {
  return resultError.value ? 'error' : 'success'
})

async function handleRevoke() {
  if (!form.serial) {
    ElMessage.warning('Serial number is required')
    return
  }

  try {
    await ElMessageBox.confirm(
      `Are you sure you want to revoke certificate with serial number "${form.serial}"?`,
      'Confirm Revocation',
      {
        confirmButtonText: 'Revoke',
        cancelButtonText: 'Cancel',
        type: 'warning'
      }
    )
  } catch {
    return
  }

  isLoading.value = true
  result.value = null
  resultError.value = ''

  try {
    result.value = await caApi.revoke({
      serial: form.serial,
      reasonCode: form.reasonCode,
      reason: form.reason || undefined
    })
    ElMessage.success('Certificate revoked successfully')
  } catch (err) {
    resultError.value = getErrorMessage(err)
    ElMessage.error(resultError.value)
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
.revoke-form {
  max-width: 600px;
}
</style>
