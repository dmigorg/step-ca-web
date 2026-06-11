<template>
  <AppLayout>
    <template #title>Certificates</template>

    <div class="certificates-content">
      <el-tabs v-model="activeTab" type="border-card">
        <el-tab-pane label="Issue Certificate" name="issue">
          <IssueCertForm />
        </el-tab-pane>

        <el-tab-pane label="Revoke Certificate" name="revoke">
          <RevokeCertForm />
        </el-tab-pane>
      </el-tabs>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import AppLayout from '@/components/AppLayout.vue'
import IssueCertForm from '@/components/IssueCertForm.vue'
import RevokeCertForm from '@/components/RevokeCertForm.vue'

const activeTab = ref('issue')
</script>

<style scoped>
.certificates-content {
  padding: 20px;
}
</style>
