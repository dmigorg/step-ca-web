<template>
  <AppLayout>
    <template #title>ACME Settings</template>

    <div class="settings-content">
      <el-card v-loading="loading" shadow="hover">
        <template #header>
          <div class="card-header">
            <span>ACME Provisioner</span>
            <el-button :icon="Refresh" circle aria-label="Reload ACME settings" :disabled="saving" @click="load" />
          </div>
        </template>

        <el-alert v-if="loadError" :title="loadError" type="error" :closable="false" show-icon />
        <el-form
          v-else-if="current"
          label-position="top"
          class="settings-form"
          @submit.prevent="review"
        >
          <h3>Certificate Lifetime</h3>
          <div class="lifetimes">
            <el-form-item v-for="field in lifetimeFields" :key="field.key" :label="field.label">
              <el-input
                v-model="durations[field.key]"
                :placeholder="'Inherited: ' + current.defaults[field.key]"
                clearable
              />
            </el-form-item>
          </div>
          <p class="hint">Use durations such as 5m, 24h or 168h. Leave a field blank to inherit the CA value.</p>

          <h3>Challenge Methods</h3>
          <el-form-item>
            <el-checkbox v-model="useDefaultChallenges">Use CA Defaults</el-checkbox>
          </el-form-item>
          <el-form-item label="Allowed Methods">
            <el-checkbox-group :model-value="useDefaultChallenges ? defaultChallenges : challenges"
              :disabled="useDefaultChallenges" @update:model-value="setChallenges">
              <el-checkbox v-for="method in allowedChallenges" :key="method.value" :value="method.value">
                {{ method.label }}
              </el-checkbox>
            </el-checkbox-group>
          </el-form-item>
          <p v-if="current.additionalChallenges.length" class="hint">
            Additional configured methods: {{ current.additionalChallenges.join(', ') }}
          </p>

          <el-button type="primary" native-type="submit" :disabled="!changes.length">
            Review Changes
          </el-button>
          <el-button @click="reset">Reset</el-button>
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
import SettingsConfirm from '@/components/SettingsConfirm.vue'
import { caApi, getErrorMessage } from '@/api/client'
import type { ACMEProvisionerSettings, CertificateLifetimes, SettingsChange } from '@/types'

const lifetimeFields = [
  { key: 'min', label: 'Minimum' },
  { key: 'default', label: 'Default' },
  { key: 'max', label: 'Maximum' }
] as const
const allowedChallenges = [
  { value: 'HTTP_01', label: 'HTTP-01' },
  { value: 'DNS_01', label: 'DNS-01' },
  { value: 'TLS_ALPN_01', label: 'TLS-ALPN-01' }
] as const
const defaultChallenges = allowedChallenges.map((method) => method.value)

const current = ref<ACMEProvisionerSettings>()
const durations = ref<CertificateLifetimes>({ min: '', default: '', max: '' })
const useDefaultChallenges = ref(true)
const challenges = ref<string[]>([])
const reviewing = ref(false)
const loading = ref(false)
const saving = ref(false)
const loadError = ref('')
const saveError = ref('')

function setChallenges(values: (string | number | boolean)[]) {
  challenges.value = values.filter((value): value is string => typeof value === 'string')
}

function renderChallenges(useDefaults: boolean, methods: string[]) {
  if (useDefaults) return 'CA defaults (HTTP-01, DNS-01, TLS-ALPN-01)'
  return allowedChallenges.filter(({value}) => methods.includes(value)).map(({label}) => label).join(', ') || 'None selected'
}

const changes = computed(() => {
  const saved = current.value
  const result: SettingsChange[] = []
  if (!saved) return result

  for (const field of lifetimeFields) {
    const before = saved.durations[field.key]
    const after = durations.value[field.key].trim()
    const inherited = 'Inherited (' + saved.defaults[field.key] + ')'
    if (before !== after) result.push({ label: field.label + ' Lifetime', before: before || inherited, after: after || inherited })
  }
  const before = renderChallenges(saved.useDefaultChallenges, saved.challenges)
  const after = renderChallenges(useDefaultChallenges.value, challenges.value)
  if (before !== after) result.push({ label: 'Challenge Methods', before, after })
  return result
})

function reset() {
  if (!current.value) return
  durations.value = { ...current.value.durations }
  useDefaultChallenges.value = current.value.useDefaultChallenges
  challenges.value = [...current.value.challenges]
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    current.value = await caApi.acmeSettings()
    reset()
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

async function save(confirmation: string) {
  if (!current.value) return
  saving.value = true
  saveError.value = ''
  try {
    current.value = await caApi.updateACMESettings({
      revision: current.value.revision,
      durations: {
        min: durations.value.min.trim(),
        default: durations.value.default.trim(),
        max: durations.value.max.trim()
      },
      useDefaultChallenges: useDefaultChallenges.value,
      challenges: challenges.value,
      confirmation
    })
    reset()
    reviewing.value = false
    ElMessage.success('ACME settings saved')
  } catch (error) {
    saveError.value = getErrorMessage(error)
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped src="./ca-settings.css"></style>
