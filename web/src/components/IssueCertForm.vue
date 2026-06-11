<template>
  <div class="issue-form">
    <el-form :model="form" :rules="rules" label-width="140px" @submit.prevent="handleSign">
      <el-form-item label="Mode">
        <el-radio-group v-model="mode" @change="onModeChange">
          <el-radio-button value="simple">Simple</el-radio-button>
          <el-radio-button value="advanced">Advanced (CNF)</el-radio-button>
          <el-radio-button value="csr">CSR Upload</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <template v-if="mode !== 'csr' && mode !== 'advanced'">
        <el-form-item label="Common Name" prop="cn">
          <el-input v-model="form.cn" placeholder="e.g., example.com or 10.0.0.1" />
        </el-form-item>

        <el-form-item label="SANs">
          <div class="sans-container">
            <el-tag
              v-for="san in form.sans"
              :key="san"
              closable
              @close="removeSAN(san)"
              :type="isIP(san) ? 'warning' : ''"
              style="margin-right: 8px; margin-bottom: 8px;"
            >
              <el-icon v-if="isIP(san)" style="margin-right: 4px;"><Position /></el-icon>
              {{ san }}
              <span v-if="isIP(san)" class="san-type">(IP)</span>
              <span v-else class="san-type">(DNS)</span>
            </el-tag>
            <el-input
              v-if="sanInputVisible"
              ref="sanInputRef"
              v-model="sanInputValue"
              size="small"
              style="width: 220px;"
              placeholder="DNS name or IP address"
              @keyup.enter="addSAN"
              @blur="addSAN"
            />
            <el-button v-else size="small" @click="showSANInput">+ Add SAN</el-button>
          </div>
          <div class="san-hint">
            Supports DNS names (e.g., <code>app.example.com</code>) and IP addresses (e.g., <code>192.168.1.10</code>)
          </div>
        </el-form-item>
      </template>

      <template v-if="mode === 'advanced'">
        <el-form-item label="OpenSSL CNF">
          <el-input
            v-model="cnfContent"
            type="textarea"
            :rows="16"
            placeholder="[ req ]
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = example.com
organizationName = My Org
countryName = US

[ req_ext ]
subjectAltName = @alternate_names

[ alternate_names ]
DNS.1 = example.com
DNS.2 = *.example.com
IP.1  = 192.168.1.10"
            style="font-family: monospace; font-size: 13px;"
          />
          <div class="cnf-actions" style="margin-top: 8px;">
            <el-button size="small" @click="parseCNF" :loading="isParsingCNF" :icon="View">
              Parse & Preview
            </el-button>
            <el-button size="small" @click="loadExampleCNF">Load Example</el-button>
          </div>
          <div class="cnf-hint">
            Paste your OpenSSL configuration file. CN, SANs, and subject fields are extracted automatically.
          </div>
        </el-form-item>

        <template v-if="cnfParsed">
          <el-form-item label="Parsed Preview">
            <el-card shadow="never" class="cnf-preview">
              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="Common Name">
                  <strong>{{ cnfParsed.commonName || '—' }}</strong>
                </el-descriptions-item>
                <el-descriptions-item label="Organization">{{ cnfParsed.organization || '—' }}</el-descriptions-item>
                <el-descriptions-item label="Country">{{ cnfParsed.country || '—' }}</el-descriptions-item>
                <el-descriptions-item label="State">{{ cnfParsed.state || '—' }}</el-descriptions-item>
                <el-descriptions-item label="Locality">{{ cnfParsed.locality || '—' }}</el-descriptions-item>
                <el-descriptions-item label="OU">{{ cnfParsed.organizationalUnit || '—' }}</el-descriptions-item>
                <el-descriptions-item label="DNS SANs" :span="2">
                  <el-tag v-for="dns in cnfParsed.dnsNames" :key="dns" size="small" style="margin-right: 4px; margin-bottom: 4px;">
                    {{ dns }}
                  </el-tag>
                  <span v-if="!cnfParsed.dnsNames?.length" class="empty-val">—</span>
                </el-descriptions-item>
                <el-descriptions-item label="IP SANs" :span="2">
                  <el-tag v-for="ip in cnfParsed.ipAddresses" :key="ip" size="small" type="warning" style="margin-right: 4px; margin-bottom: 4px;">
                    {{ ip }}
                  </el-tag>
                  <span v-if="!cnfParsed.ipAddresses?.length" class="empty-val">—</span>
                </el-descriptions-item>
                <el-descriptions-item v-if="cnfParsed.keyUsage?.length" label="Key Usage" :span="2">
                  <el-tag v-for="ku in cnfParsed.keyUsage" :key="ku" size="small" type="info" style="margin-right: 4px;">{{ ku }}</el-tag>
                </el-descriptions-item>
                <el-descriptions-item v-if="cnfParsed.extKeyUsage?.length" label="Ext Key Usage" :span="2">
                  <el-tag v-for="eku in cnfParsed.extKeyUsage" :key="eku" size="small" type="info" style="margin-right: 4px;">{{ eku }}</el-tag>
                </el-descriptions-item>
              </el-descriptions>
            </el-card>
          </el-form-item>
        </template>

        <el-alert
          v-if="cnfError"
          :title="cnfError"
          type="error"
          show-icon
          style="margin-bottom: 16px;"
        />
      </template>

      <template v-if="mode === 'csr'">
        <el-form-item label="Common Name" prop="cn">
          <el-input v-model="form.cn" placeholder="e.g., example.com (for token subject)" />
        </el-form-item>

        <el-form-item label="SANs">
          <div class="sans-container">
            <el-tag
              v-for="san in form.sans"
              :key="san"
              closable
              @close="removeSAN(san)"
              :type="isIP(san) ? 'warning' : ''"
              style="margin-right: 8px; margin-bottom: 8px;"
            >
              {{ san }}
              <span v-if="isIP(san)" class="san-type">(IP)</span>
              <span v-else class="san-type">(DNS)</span>
            </el-tag>
            <el-input
              v-if="sanInputVisible"
              ref="sanInputRef"
              v-model="sanInputValue"
              size="small"
              style="width: 220px;"
              placeholder="DNS name or IP address"
              @keyup.enter="addSAN"
              @blur="addSAN"
            />
            <el-button v-else size="small" @click="showSANInput">+ Add SAN</el-button>
          </div>
          <div class="san-hint">SANs are authorized via the token; the CSR provides the public key</div>
        </el-form-item>

        <el-form-item label="CSR (PEM)" prop="csr">
          <el-input
            v-model="form.csr"
            type="textarea"
            :rows="8"
            placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
          />
          <div class="csr-hint">
            Paste your PEM-encoded CSR here. The private key stays on your machine.
          </div>
        </el-form-item>
      </template>

      <el-form-item label="Not Before">
        <el-date-picker
          v-model="form.notBefore"
          type="datetime"
          placeholder="Optional (default: now)"
          format="YYYY-MM-DD HH:mm"
          value-format="YYYY-MM-DDTHH:mm:ssZ"
          clearable
        />
      </el-form-item>

      <el-form-item label="Not After">
        <el-date-picker
          v-model="form.notAfter"
          type="datetime"
          placeholder="Optional (default: CA policy)"
          format="YYYY-MM-DD HH:mm"
          value-format="YYYY-MM-DDTHH:mm:ssZ"
          clearable
        />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" @click="handleSign" :loading="isLoading" :icon="Check">
          Issue Certificate
        </el-button>
      </el-form-item>
    </el-form>

    <el-divider v-if="result" />

    <div v-if="result" class="result-section">
      <el-alert
        title="Certificate issued successfully!"
        type="success"
        show-icon
        :closable="false"
        style="margin-bottom: 20px;"
      />

      <el-alert
        v-if="result.privateKey"
        title="Save your private key now - it will not be shown again!"
        type="warning"
        show-icon
        :closable="false"
        style="margin-bottom: 20px;"
      />

      <el-tabs type="border-card">
        <el-tab-pane label="Certificate">
          <CertDisplay :pem="result.certificate" label="issued-certificate" />
        </el-tab-pane>

        <el-tab-pane label="Private Key" v-if="result.privateKey">
          <div class="private-key-warning">
            <el-alert
              title="IMPORTANT: Save this private key now. It cannot be recovered later."
              type="error"
              show-icon
              :closable="false"
              style="margin-bottom: 12px;"
            />
          </div>
          <CertDisplay :pem="result.privateKey" label="private-key" />
        </el-tab-pane>

        <el-tab-pane label="CA Chain">
          <CertDisplay :pem="result.caChain" label="ca-chain" />
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, nextTick } from 'vue'
import { Check, Position, View } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { caApi, getErrorMessage } from '@/api/client'
import CertDisplay from './CertDisplay.vue'
import type { SignResult, CNFParsedResult } from '@/types'

type Mode = 'simple' | 'advanced' | 'csr'

const mode = ref<Mode>('simple')

const form = reactive({
  cn: '',
  sans: [] as string[],
  notBefore: '',
  notAfter: '',
  csr: ''
})

const cnfContent = ref('')
const cnfParsed = ref<CNFParsedResult | null>(null)
const cnfError = ref('')
const isParsingCNF = ref(false)

const rules = {
  cn: [{ required: true, message: 'Common Name is required', trigger: 'blur' }]
}

const isLoading = ref(false)
const result = ref<SignResult | null>(null)

const sanInputVisible = ref(false)
const sanInputValue = ref('')
const sanInputRef = ref<InstanceType<typeof import('element-plus')['ElInput']> | null>(null)

const ipRegex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([0-9a-fA-F:]+:+)+[0-9a-fA-F]*$/

function isIP(value: string): boolean {
  return ipRegex.test(value)
}

function onModeChange() {
  result.value = null
  cnfError.value = ''
  cnfParsed.value = null
}

function showSANInput() {
  sanInputVisible.value = true
  nextTick(() => {
    sanInputRef.value?.input?.focus()
  })
}

function addSAN() {
  const value = sanInputValue.value.trim()
  if (value && !form.sans.includes(value)) {
    form.sans.push(value)
  }
  sanInputVisible.value = false
  sanInputValue.value = ''
}

function removeSAN(san: string) {
  form.sans = form.sans.filter(s => s !== san)
}

function loadExampleCNF() {
  cnfContent.value = `[ req ]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
countryName = RU
organizationName = My Organization
stateOrProvinceName = Moscow
localityName = Moscow
CN = app.example.com

[ req_ext ]
subjectAltName = @alternate_names

[ alternate_names ]
DNS.1 = app.example.com
DNS.2 = api.example.com
DNS.3 = *.example.com
IP.1  = 192.168.1.10
IP.2  = 10.0.0.5`
  cnfParsed.value = null
  cnfError.value = ''
}

async function parseCNF() {
  if (!cnfContent.value.trim()) {
    ElMessage.warning('Please enter CNF content')
    return
  }

  isParsingCNF.value = true
  cnfError.value = ''

  try {
    cnfParsed.value = await caApi.parseCNF(cnfContent.value)
    if (!cnfParsed.value.commonName) {
      cnfError.value = 'Warning: No CN (Common Name) found in [dn] section'
    }
    ElMessage.success('CNF parsed successfully')
  } catch (err) {
    cnfError.value = getErrorMessage(err)
    cnfParsed.value = null
  } finally {
    isParsingCNF.value = false
  }
}

async function handleSign() {
  isLoading.value = true
  result.value = null

  try {
    if (mode.value === 'advanced') {
      if (!cnfContent.value.trim()) {
        ElMessage.warning('Please enter CNF content')
        return
      }
      result.value = await caApi.signCNF({
        content: cnfContent.value,
        notBefore: form.notBefore || undefined,
        notAfter: form.notAfter || undefined
      })
    } else if (mode.value === 'csr') {
      if (!form.cn) {
        ElMessage.warning('Common Name is required')
        return
      }
      if (!form.csr.trim()) {
        ElMessage.warning('CSR (PEM) is required in CSR upload mode')
        return
      }
      const sans = form.sans.length > 0 ? form.sans : [form.cn]
      result.value = await caApi.sign({
        cn: form.cn,
        sans,
        notBefore: form.notBefore || undefined,
        notAfter: form.notAfter || undefined,
        csr: form.csr
      })
    } else {
      if (!form.cn) {
        ElMessage.warning('Common Name is required')
        return
      }
      const sans = form.sans.length > 0 ? form.sans : [form.cn]
      result.value = await caApi.sign({
        cn: form.cn,
        sans,
        notBefore: form.notBefore || undefined,
        notAfter: form.notAfter || undefined
      })
    }
    ElMessage.success('Certificate issued successfully')
  } catch (err) {
    ElMessage.error(getErrorMessage(err))
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
.issue-form {
  max-width: 800px;
}

.sans-container {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
}

.san-type {
  font-size: 11px;
  opacity: 0.7;
  margin-left: 4px;
}

.san-hint, .csr-hint, .cnf-hint {
  margin-top: 6px;
  font-size: 12px;
  color: #909399;
}

.san-hint code {
  background: #f5f7fa;
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 11px;
}

.cnf-preview {
  width: 100%;
}

.cnf-preview :deep(.el-descriptions__label) {
  width: 140px;
}

.empty-val {
  color: #c0c4cc;
}

.result-section {
  margin-top: 20px;
}

.private-key-warning {
  margin-bottom: 12px;
}
</style>
