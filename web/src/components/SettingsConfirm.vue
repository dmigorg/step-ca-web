<template>
  <el-dialog
    :model-value="modelValue"
    title="Review Settings Changes"
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
    <template #footer>
      <el-button :disabled="saving" @click="emit('update:modelValue', false)">Cancel</el-button>
      <el-button type="primary" :loading="saving" @click="emit('confirm')">
        Apply Changes
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import type { SettingsChange } from '@/types'

defineProps<{
  modelValue: boolean
  changes: SettingsChange[]
  saving: boolean
  error: string
}>()
const emit = defineEmits<{
  'update:modelValue': [open: boolean]
  confirm: []
}>()
</script>

<style scoped>
.change-value {
  overflow-wrap: anywhere;
}

.confirm-alert {
  margin-top: 16px;
}

</style>
