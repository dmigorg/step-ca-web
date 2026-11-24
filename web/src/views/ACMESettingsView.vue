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
          :disabled="saving"
          @submit.prevent="save"
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

          <el-alert v-if="saveError" :title="saveError" type="error" :closable="false" show-icon class="save-error" />
          <el-button type="primary" native-type="submit" :disabled="!hasChanges" :loading="saving">
            Save Changes
          </el-button>
          <el-button @click="reset">Reset</el-button>
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
import type { ACMEProvisionerSettings, CertificateLifetimes } from '@/types'

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
const loading = ref(false)
const saving = ref(false)
const loadError = ref('')
const saveError = ref('')

function setChallenges(values: (string | number | boolean)[]) {
  challenges.value = values.filter((value): value is string => typeof value === 'string')
}

const hasChanges = computed(() => {
  const saved = current.value
  if (!saved) return false
  return lifetimeFields.some(({ key }) => saved.durations[key] !== durations.value[key].trim()) ||
    saved.useDefaultChallenges !== useDefaultChallenges.value ||
    (!useDefaultChallenges.value &&
      (saved.challenges.length !== challenges.value.length ||
        saved.challenges.some(method => !challenges.value.includes(method))))
})

function reset() {
  if (!current.value) return
  saveError.value = ''
  durations.value = { ...current.value.durations }
  useDefaultChallenges.value = current.value.useDefaultChallenges
  challenges.value = [...current.value.challenges]
}

async function load() {
  loading.value = true
  loadError.value = ''
  saveError.value = ''
  try {
    current.value = await caApi.acmeSettings()
    reset()
  } catch (error) {
    loadError.value = getErrorMessage(error)
  } finally {
    loading.value = false
  }
}

async function save() {
  if (!current.value || saving.value || !hasChanges.value) return
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
      challenges: challenges.value
    })
    reset()
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
