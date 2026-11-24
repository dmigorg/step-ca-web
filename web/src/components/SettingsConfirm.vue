<template>
  <el-dialog
    :model-value="modelValue"
    title="Confirm Settings Changes"
    width="min(560px, 94vw)"
    :close-on-click-modal="!saving"
    :close-on-press-escape="!saving"
    :show-close="!saving"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <el-descriptions :column="1" border>
      <el-descriptions-item v-for="change in changes" :key="change.label" :label="change.label">
        <div class="change-value">Before: {{ change.before }}</div>
        <div class="change-value">After: {{ change.after }}</div>
      </el-descriptions-item>
    </el-descriptions>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      show-icon
      class="confirm-alert"
    />
    <el-form class="confirm-form" label-position="top" @submit.prevent="submit">
      <el-form-item label="Administrator Confirmation Code">
        <el-input
          v-model="confirmation"
          type="password"
          autocomplete="off"
          :disabled="saving"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button :disabled="saving" @click="emit('update:modelValue', false)">Cancel</el-button>
      <el-button type="primary" :loading="saving" :disabled="!confirmation" @click="submit">
        Apply Changes
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import type { SettingsChange } from '@/types'

const props = defineProps<{
  modelValue: boolean
  changes: SettingsChange[]
  saving: boolean
  error: string
}>()
const emit = defineEmits<{
  'update:modelValue': [open: boolean]
  confirm: [confirmation: string]
}>()
const confirmation = ref('')

watch(() => props.modelValue, (open) => {
  if (!open) confirmation.value = ''
})

function submit() {
  if (confirmation.value && !props.saving) emit('confirm', confirmation.value)
}
</script>

<style scoped>
.change-value {
  overflow-wrap: anywhere;
}

.confirm-form,
.confirm-alert {
  margin-top: 16px;
}

.confirm-form :deep(.el-form-item) {
  margin-bottom: 0;
}
</style>
