<template>
  <div class="rule-input">
    <div v-if="modelValue.length" class="rule-tags">
      <el-tag
        v-for="(rule, index) in modelValue"
        :key="rule + index"
        closable
        @close="emit('update:modelValue', modelValue.filter((_, i) => i !== index))"
      >
        {{ rule }}
      </el-tag>
    </div>
    <el-input
      v-model="candidate"
      :placeholder="placeholder"
      @keydown.enter.prevent.stop="add"
    >
      <template #append>
        <el-button :disabled="!candidate.trim()" @click="add">Add</el-button>
      </template>
    </el-input>
  </div>
</template>

<script setup lang="ts">
import { mergePolicyRules } from './policyRules'

const props = defineProps<{ modelValue: string[]; placeholder: string }>()
const emit = defineEmits<{ 'update:modelValue': [rules: string[]] }>()
const candidate = defineModel<string>('candidate', { required: true })

function add() {
  emit('update:modelValue', mergePolicyRules(props.modelValue, candidate.value))
  candidate.value = ''
}
</script>

<style scoped>
.rule-input {
  width: 100%;
}

.rule-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
}
</style>
