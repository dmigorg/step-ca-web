<template>
  <div class="cert-display">
    <div class="cert-actions">
      <el-button size="small" :icon="CopyDocument" @click="copyToClipboard">Copy PEM</el-button>
      <el-button size="small" :icon="Download" @click="downloadPEM">Download</el-button>
    </div>

    <el-input
      type="textarea"
      :model-value="pem"
      readonly
      :rows="pemRows"
      class="pem-textarea"
    />

    <div v-if="certInfo" class="cert-details">
      <el-divider>Certificate Details</el-divider>
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="Subject">{{ certInfo.subject }}</el-descriptions-item>
        <el-descriptions-item label="Issuer">{{ certInfo.issuer }}</el-descriptions-item>
        <el-descriptions-item label="Serial">{{ certInfo.serial }}</el-descriptions-item>
        <el-descriptions-item label="Is CA">
          <el-tag :type="certInfo.isCA ? 'success' : 'info'" size="small">
            {{ certInfo.isCA ? 'Yes' : 'No' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Valid From">{{ formatDate(certInfo.notBefore) }}</el-descriptions-item>
        <el-descriptions-item label="Valid Until">{{ formatDate(certInfo.notAfter) }}</el-descriptions-item>
        <el-descriptions-item label="Key Usage" :span="2">{{ certInfo.keyUsage || 'N/A' }}</el-descriptions-item>
        <el-descriptions-item v-if="certInfo.dnsNames?.length" label="DNS Names" :span="2">
          <el-tag v-for="dns in certInfo.dnsNames" :key="dns" size="small" style="margin-right: 4px;">
            {{ dns }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item v-if="certInfo.ipAddresses?.length" label="IP Addresses" :span="2">
          <el-tag v-for="ip in certInfo.ipAddresses" :key="ip" size="small" type="warning" style="margin-right: 4px;">
            {{ ip }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { CopyDocument, Download } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { caApi } from '@/api/client'
import type { CertInfo } from '@/types'

const props = defineProps<{
  pem: string
  label?: string
}>()

const certInfo = ref<CertInfo | null>(null)

const pemRows = computed(() => {
  const lines = props.pem?.split('\n').length || 1
  return Math.min(lines, 15)
})

async function parseCert() {
  if (!props.pem) return
  try {
    certInfo.value = await caApi.parseCert(props.pem)
  } catch {
    // Silently fail - cert details are optional
  }
}

function copyToClipboard() {
  navigator.clipboard.writeText(props.pem).then(() => {
    ElMessage.success('PEM copied to clipboard')
  }).catch(() => {
    ElMessage.error('Failed to copy to clipboard')
  })
}

function downloadPEM() {
  const blob = new Blob([props.pem], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${props.label || 'certificate'}.pem`
  a.click()
  URL.revokeObjectURL(url)
}

function formatDate(dateStr: string): string {
  if (!dateStr) return 'N/A'
  return new Date(dateStr).toLocaleString()
}

onMounted(() => {
  parseCert()
})
</script>

<style scoped>
.cert-display {
  padding: 8px 0;
}

.cert-actions {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.pem-textarea :deep(.el-textarea__inner) {
  font-family: monospace;
  font-size: 12px;
  background: #f5f7fa;
}

.cert-details {
  margin-top: 16px;
}
</style>
