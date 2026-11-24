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
        <el-form v-else-if="current" label-position="top" class="settings-form" :disabled="saving"
          @submit.prevent="save">
          <p class="hint">These rules apply to all X.509 issuance from this CA, including ACME.
            Separate values with commas or press Enter.</p>
          <div class="rule-columns">
            <div>
              <h3>Allow</h3>
              <el-form-item label="DNS Names">
                <el-input-tag v-model="draft.allow.dns" delimiter="," tag-type="primary"
                  placeholder="e.g. *.example.local" />
              </el-form-item>
              <el-form-item label="IP Addresses or CIDRs">
                <el-input-tag v-model="draft.allow.ips" delimiter="," tag-type="primary"
                  placeholder="e.g. 10.20.8.0/22" />
              </el-form-item>
            </div>
            <div>
              <h3>Deny</h3>
              <el-form-item label="DNS Names">
                <el-input-tag v-model="draft.deny.dns" delimiter="," tag-type="primary"
                  placeholder="e.g. blocked.example.local" />
              </el-form-item>
              <el-form-item label="IP Addresses or CIDRs">
                <el-input-tag v-model="draft.deny.ips" delimiter="," tag-type="primary"
                  placeholder="e.g. 10.20.8.15" />
              </el-form-item>
            </div>
          </div>
          <el-form-item>
            <el-checkbox v-model="draft.allowWildcardNames">Allow wildcard DNS names in certificates</el-checkbox>
          </el-form-item>
          <p class="hint">A DNS rule such as *.example.local matches one level of subdomains.
            Add example.local separately to match the domain itself.</p>
          <el-alert v-if="saveError" :title="saveError" type="error" :closable="false" show-icon class="save-error" />
          <el-button type="primary" native-type="submit" :loading="saving">
            Save Changes
          </el-button>
          <el-button @click="setDraft(current)">Reset</el-button>
        </el-form>
      </el-card>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import AppLayout from '@/components/AppLayout.vue'
import { caApi, getErrorMessage } from '@/api/client'
import type { IssuancePolicy, IssuancePolicySettings } from '@/types'

const current = ref<IssuancePolicySettings>()
const draft = ref<IssuancePolicy>({
  allow: { dns: [], ips: [] },
  deny: { dns: [], ips: [] },
  allowWildcardNames: false
})
const loading = ref(false)
const saving = ref(false)
const loadError = ref('')
const saveError = ref('')

const policyToSave = computed<IssuancePolicy>(() => ({
  allow: {
    dns: [...new Set(draft.value.allow.dns)],
    ips: [...new Set(draft.value.allow.ips)]
  },
  deny: {
    dns: [...new Set(draft.value.deny.dns)],
    ips: [...new Set(draft.value.deny.ips)]
  },
  allowWildcardNames: draft.value.allowWildcardNames
}))

const hasChanges = computed(() => {
  const saved = current.value
  if (!saved) return false
  const edits = policyToSave.value
  const differs = (before: string[], after: string[]) => {
    const savedRules = new Set(before)
    return savedRules.size !== after.length || after.some(rule => !savedRules.has(rule))
  }

  return differs(saved.allow.dns, edits.allow.dns) ||
    differs(saved.allow.ips, edits.allow.ips) ||
    differs(saved.deny.dns, edits.deny.dns) ||
    differs(saved.deny.ips, edits.deny.ips) ||
    saved.allowWildcardNames !== edits.allowWildcardNames
})

function setDraft(policy: IssuancePolicy) {
  saveError.value = ''
  draft.value = {
    allow: { dns: [...policy.allow.dns], ips: [...policy.allow.ips] },
    deny: { dns: [...policy.deny.dns], ips: [...policy.deny.ips] },
    allowWildcardNames: policy.allowWildcardNames
  }
}

async function load() {
  loading.value = true
  loadError.value = ''
  saveError.value = ''
  try {
    current.value = await caApi.issuancePolicy()
    setDraft(current.value)
  } catch (error) {
    loadError.value = getErrorMessage(error)
  } finally {
    loading.value = false
  }
}

async function save(event: SubmitEvent) {
  if (!current.value || saving.value) return
  const input = document.activeElement
  if (input instanceof HTMLInputElement && input.type === 'text' &&
    event.currentTarget instanceof HTMLFormElement && event.currentTarget.contains(input)) {
    input.blur()
  }
  if (!hasChanges.value) return
  saving.value = true
  saveError.value = ''
  try {
    current.value = await caApi.updateIssuancePolicy({
      ...policyToSave.value,
      revision: current.value.revision
    })
    setDraft(current.value)
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
.rule-columns {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 0 20px;
}
</style>
