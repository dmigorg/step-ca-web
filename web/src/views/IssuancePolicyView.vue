<template>
  <AppLayout>
    <template #title>Issuance Policy</template>

    <div class="settings-content">
      <el-card v-loading="loading" shadow="hover">
        <template #header>
          <div class="card-header">
            <span>Authority X.509 Policy</span>
            <el-button :icon="Refresh" circle aria-label="Reload issuance policy" :disabled="saving" @click="load" />
          </div>
        </template>

        <el-alert v-if="loadError" :title="loadError" type="error" :closable="false" show-icon />
        <el-form v-else-if="current" label-position="top" class="settings-form" @submit.prevent="review">
          <p class="hint">These rules apply to all X.509 issuance from this CA, including ACME.</p>
          <el-alert
            v-if="current.protectedDNS.length"
            :title="'Protected DNS names: ' + current.protectedDNS.join(', ')"
            type="info"
            :closable="false"
            show-icon
            class="protected-names"
          />
          <div class="rule-columns">
            <div>
              <h3>Allow</h3>
              <el-form-item label="DNS Names">
                <PolicyRuleInput v-model="draft.allow.dns" placeholder="e.g. *.example.local" />
              </el-form-item>
              <el-form-item label="IP Addresses or CIDRs">
                <PolicyRuleInput v-model="draft.allow.ips" placeholder="e.g. 10.20.8.0/22" />
              </el-form-item>
            </div>
            <div>
              <h3>Deny</h3>
              <el-form-item label="DNS Names">
                <PolicyRuleInput v-model="draft.deny.dns" placeholder="e.g. blocked.example.local" />
              </el-form-item>
              <el-form-item label="IP Addresses or CIDRs">
                <PolicyRuleInput v-model="draft.deny.ips" placeholder="e.g. 10.20.8.15" />
              </el-form-item>
            </div>
          </div>
          <el-form-item>
            <el-checkbox v-model="draft.allowWildcardNames">Allow wildcard DNS names in certificates</el-checkbox>
          </el-form-item>
          <p class="hint">A DNS rule such as *.example.local matches one level of subdomains.</p>
          <el-button type="primary" native-type="submit" :disabled="!changes.length">Review Changes</el-button>
          <el-button @click="setDraft(current)">Reset</el-button>
          <el-button v-if="current.previous" @click="setDraft(current.previous)">Load Previous Policy</el-button>
        </el-form>
      </el-card>

      <SettingsConfirm
        v-model="reviewing"
        :changes="changes"
        :saving="saving"
        :error="saveError"
        @confirm="save"
      />
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import AppLayout from '@/components/AppLayout.vue'
import PolicyRuleInput from '@/components/PolicyRuleInput.vue'
import SettingsConfirm from '@/components/SettingsConfirm.vue'
import { caApi, getErrorMessage } from '@/api/client'
import type { IssuancePolicy, IssuancePolicySettings, SettingsChange } from '@/types'

const current = ref<IssuancePolicySettings>()
const draft = ref<IssuancePolicy>({
  allow: { dns: [], ips: [] },
  deny: { dns: [], ips: [] },
  allowWildcardNames: false
})
const reviewing = ref(false)
const loading = ref(false)
const saving = ref(false)
const loadError = ref('')
const saveError = ref('')

const changes = computed(() => {
  const saved = current.value
  if (!saved) return []
  const edits = draft.value
  const result: SettingsChange[] = []
  const add = (label: string, oldRules: string[], newRules: string[]) => {
    const before = [...oldRules].sort().join(', ')
    const after = [...newRules].sort().join(', ')
    if (before !== after) result.push({ label, before: before || 'None', after: after || 'None' })
  }

  add('Allowed DNS Names', saved.allow.dns, edits.allow.dns)
  add('Allowed IP Addresses or CIDRs', saved.allow.ips, edits.allow.ips)
  add('Denied DNS Names', saved.deny.dns, edits.deny.dns)
  add('Denied IP Addresses or CIDRs', saved.deny.ips, edits.deny.ips)
  if (saved.allowWildcardNames !== edits.allowWildcardNames) {
    result.push({
      label: 'Wildcard DNS Names',
      before: saved.allowWildcardNames ? 'Allowed' : 'Disabled',
      after: edits.allowWildcardNames ? 'Allowed' : 'Disabled'
    })
  }
  return result
})

function setDraft(policy: IssuancePolicy) {
  draft.value = {
    allow: { dns: [...policy.allow.dns], ips: [...policy.allow.ips] },
    deny: { dns: [...policy.deny.dns], ips: [...policy.deny.ips] },
    allowWildcardNames: policy.allowWildcardNames
  }
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    current.value = await caApi.issuancePolicy()
    setDraft(current.value)
  } catch (error) {
    loadError.value = getErrorMessage(error)
  } finally {
    loading.value = false
  }
}

function review() {
  if (!changes.value.length) return
  saveError.value = ''
  reviewing.value = true
}

async function save() {
  if (!current.value) return
  saving.value = true
  saveError.value = ''
  try {
    current.value = await caApi.updateIssuancePolicy({
      ...draft.value,
      revision: current.value.revision
    })
    setDraft(current.value)
    reviewing.value = false
    ElMessage.success('Issuance policy saved')
  } catch (error) {
    saveError.value = getErrorMessage(error)
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped src="./ca-settings.css"></style>
<style scoped>
.protected-names {
  margin-bottom: 20px;
}

.rule-columns {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 0 20px;
}
</style>
