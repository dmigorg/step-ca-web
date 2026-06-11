<template>
  <AppLayout>
    <template #title>Inspector</template>

    <div class="inspector-content">
      <el-tabs v-model="activeTab" type="border-card">
        <!-- Certificate Tab -->
        <el-tab-pane label="Certificate (CRT)" name="crt">
          <el-form label-width="0">
            <el-form-item>
              <el-input
                v-model="crtPem"
                type="textarea"
                :rows="8"
                placeholder="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"
                style="font-family: monospace; font-size: 13px;"
              />
              <div style="margin-top: 8px;">
                <el-button type="primary" @click="inspectCert" :loading="crtLoading" :icon="Search">
                  Inspect Certificate
                </el-button>
                <el-button @click="crtPem = ''; certInfo = null; crtError = ''" :icon="Delete">
                  Clear
                </el-button>
              </div>
            </el-form-item>
          </el-form>

          <el-alert
            v-if="crtError"
            :title="crtError"
            type="error"
            show-icon
            closable
            style="margin-bottom: 16px;"
          />

          <template v-if="certInfo">
            <el-card shadow="never">
              <template #header>
                <div class="card-header">
                  <span>Certificate Details</span>
                  <el-tag v-if="certInfo.isCA" type="warning">CA</el-tag>
                  <el-tag v-if="certInfo.selfSigned" type="info">Self-Signed</el-tag>
                </div>
              </template>

              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="Version">{{ certInfo.version }}</el-descriptions-item>
                <el-descriptions-item label="Serial Number">
                  <code>{{ certInfo.serial }}</code>
                </el-descriptions-item>
                <el-descriptions-item label="Signature Algorithm">{{ certInfo.signatureAlgo }}</el-descriptions-item>
                <el-descriptions-item label="Public Key">
                  {{ certInfo.publicKeyAlgo }} {{ certInfo.publicKeySize }} bit
                </el-descriptions-item>

                <el-descriptions-item label="Subject" :span="2">
                  <code>{{ certInfo.subjectFull }}</code>
                </el-descriptions-item>
                <el-descriptions-item label="Issuer" :span="2">
                  <code>{{ certInfo.issuerFull }}</code>
                </el-descriptions-item>

                <el-descriptions-item label="Not Before">{{ formatDate(certInfo.notBefore) }}</el-descriptions-item>
                <el-descriptions-item label="Not After">{{ formatDate(certInfo.notAfter) }}</el-descriptions-item>

                <el-descriptions-item label="Key Usage" :span="2">{{ certInfo.keyUsage }}</el-descriptions-item>
                <el-descriptions-item v-if="certInfo.extKeyUsage?.length" label="Extended Key Usage" :span="2">
                  <el-tag v-for="eku in certInfo.extKeyUsage" :key="eku" size="small" style="margin-right: 4px; margin-bottom: 4px;">
                    {{ eku }}
                  </el-tag>
                </el-descriptions-item>
              </el-descriptions>

              <!-- SANs -->
              <el-divider content-position="left">Subject Alternative Names</el-divider>
              <div class="sans-section">
                <template v-if="certInfo.dnsNames?.length">
                  <div class="san-group">
                    <span class="san-label">DNS Names:</span>
                    <el-tag v-for="dns in certInfo.dnsNames" :key="dns" size="small" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ dns }}
                    </el-tag>
                  </div>
                </template>
                <template v-if="certInfo.ipAddresses?.length">
                  <div class="san-group">
                    <span class="san-label">IP Addresses:</span>
                    <el-tag v-for="ip in certInfo.ipAddresses" :key="ip" size="small" type="warning" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ ip }}
                    </el-tag>
                  </div>
                </template>
                <template v-if="certInfo.emailAddresses?.length">
                  <div class="san-group">
                    <span class="san-label">Email:</span>
                    <el-tag v-for="email in certInfo.emailAddresses" :key="email" size="small" type="success" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ email }}
                    </el-tag>
                  </div>
                </template>
                <template v-if="certInfo.uris?.length">
                  <div class="san-group">
                    <span class="san-label">URIs:</span>
                    <el-tag v-for="uri in certInfo.uris" :key="uri" size="small" type="info" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ uri }}
                    </el-tag>
                  </div>
                </template>
                <span v-if="!certInfo.dnsNames?.length && !certInfo.ipAddresses?.length && !certInfo.emailAddresses?.length && !certInfo.uris?.length" class="empty-val">
                  No SANs found
                </span>
              </div>

              <!-- Distribution Points -->
              <template v-if="certInfo.ocspServers?.length || certInfo.crlDistPoints?.length || certInfo.issuerURLs?.length">
                <el-divider content-position="left">Distribution Points</el-divider>
                <el-descriptions :column="1" border size="small">
                  <el-descriptions-item v-if="certInfo.ocspServers?.length" label="OCSP Servers">
                    <div v-for="url in certInfo.ocspServers" :key="url">{{ url }}</div>
                  </el-descriptions-item>
                  <el-descriptions-item v-if="certInfo.crlDistPoints?.length" label="CRL Distribution Points">
                    <div v-for="url in certInfo.crlDistPoints" :key="url">{{ url }}</div>
                  </el-descriptions-item>
                  <el-descriptions-item v-if="certInfo.issuerURLs?.length" label="CA Issuers">
                    <div v-for="url in certInfo.issuerURLs" :key="url">{{ url }}</div>
                  </el-descriptions-item>
                </el-descriptions>
              </template>
            </el-card>
          </template>
        </el-tab-pane>

        <!-- CSR Tab -->
        <el-tab-pane label="CSR" name="csr">
          <el-form label-width="0">
            <el-form-item>
              <el-input
                v-model="csrPem"
                type="textarea"
                :rows="8"
                placeholder="-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----"
                style="font-family: monospace; font-size: 13px;"
              />
              <div style="margin-top: 8px;">
                <el-button type="primary" @click="inspectCSR" :loading="csrLoading" :icon="Search">
                  Inspect CSR
                </el-button>
                <el-button @click="csrPem = ''; csrInfo = null; csrError = ''" :icon="Delete">
                  Clear
                </el-button>
              </div>
            </el-form-item>
          </el-form>

          <el-alert
            v-if="csrError"
            :title="csrError"
            type="error"
            show-icon
            closable
            style="margin-bottom: 16px;"
          />

          <template v-if="csrInfo">
            <el-card shadow="never">
              <template #header>
                <div class="card-header">
                  <span>CSR Details</span>
                  <el-tag type="success" effect="dark">Signature OK</el-tag>
                </div>
              </template>

              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="Signature Algorithm">{{ csrInfo.signatureAlgo }}</el-descriptions-item>
                <el-descriptions-item label="Public Key">
                  {{ csrInfo.publicKeyAlgo }} {{ csrInfo.publicKeySize }} bit
                </el-descriptions-item>

                <el-descriptions-item label="Subject" :span="2">
                  <code>{{ csrInfo.subjectFull }}</code>
                </el-descriptions-item>
              </el-descriptions>

              <!-- SANs -->
              <el-divider content-position="left">Subject Alternative Names</el-divider>
              <div class="sans-section">
                <template v-if="csrInfo.dnsNames?.length">
                  <div class="san-group">
                    <span class="san-label">DNS Names:</span>
                    <el-tag v-for="dns in csrInfo.dnsNames" :key="dns" size="small" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ dns }}
                    </el-tag>
                  </div>
                </template>
                <template v-if="csrInfo.ipAddresses?.length">
                  <div class="san-group">
                    <span class="san-label">IP Addresses:</span>
                    <el-tag v-for="ip in csrInfo.ipAddresses" :key="ip" size="small" type="warning" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ ip }}
                    </el-tag>
                  </div>
                </template>
                <template v-if="csrInfo.emailAddresses?.length">
                  <div class="san-group">
                    <span class="san-label">Email:</span>
                    <el-tag v-for="email in csrInfo.emailAddresses" :key="email" size="small" type="success" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ email }}
                    </el-tag>
                  </div>
                </template>
                <template v-if="csrInfo.uris?.length">
                  <div class="san-group">
                    <span class="san-label">URIs:</span>
                    <el-tag v-for="uri in csrInfo.uris" :key="uri" size="small" type="info" style="margin-right: 4px; margin-bottom: 4px;">
                      {{ uri }}
                    </el-tag>
                  </div>
                </template>
                <span v-if="!csrInfo.dnsNames?.length && !csrInfo.ipAddresses?.length && !csrInfo.emailAddresses?.length && !csrInfo.uris?.length" class="empty-val">
                  No SANs found
                </span>
              </div>
            </el-card>
          </template>
        </el-tab-pane>
      </el-tabs>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Search, Delete } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import AppLayout from '@/components/AppLayout.vue'
import { caApi, getErrorMessage } from '@/api/client'
import type { CertInfo, CSRInfo } from '@/types'

const activeTab = ref('crt')

// Certificate tab state
const crtPem = ref('')
const certInfo = ref<CertInfo | null>(null)
const crtLoading = ref(false)
const crtError = ref('')

// CSR tab state
const csrPem = ref('')
const csrInfo = ref<CSRInfo | null>(null)
const csrLoading = ref(false)
const csrError = ref('')

function formatDate(dateStr: string): string {
  if (!dateStr) return '—'
  const d = new Date(dateStr)
  return d.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    timeZoneName: 'short'
  })
}

async function inspectCert() {
  if (!crtPem.value.trim()) {
    ElMessage.warning('Please paste a PEM-encoded certificate')
    return
  }
  crtLoading.value = true
  certInfo.value = null
  crtError.value = ''
  try {
    certInfo.value = await caApi.parseCert(crtPem.value)
  } catch (err) {
    crtError.value = getErrorMessage(err)
  } finally {
    crtLoading.value = false
  }
}

async function inspectCSR() {
  if (!csrPem.value.trim()) {
    ElMessage.warning('Please paste a PEM-encoded CSR')
    return
  }
  csrLoading.value = true
  csrInfo.value = null
  csrError.value = ''
  try {
    csrInfo.value = await caApi.parseCSR(csrPem.value)
  } catch (err) {
    csrError.value = getErrorMessage(err)
  } finally {
    csrLoading.value = false
  }
}
</script>

<style scoped>
.inspector-content {
  padding: 20px;
  max-width: 900px;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.sans-section {
  padding: 8px 0;
}

.san-group {
  margin-bottom: 8px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
}

.san-label {
  font-size: 13px;
  color: #606266;
  margin-right: 8px;
  min-width: 100px;
}

.empty-val {
  color: #c0c4cc;
  font-size: 13px;
}

code {
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 13px;
  word-break: break-all;
}
</style>
