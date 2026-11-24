<template>
  <AppLayout>
    <template #title>Certificates</template>

    <div class="certificates-content">
      <el-tabs v-model="activeTab" type="border-card">
        <el-tab-pane label="Issued Certificates" name="issued">
          <IssuedCertificates v-if="activeTab === 'issued'" />
        </el-tab-pane>

        <el-tab-pane label="Issue Certificate" name="issue" lazy>
          <IssueCertForm />
        </el-tab-pane>

        <el-tab-pane label="Revoke Certificate" name="revoke" lazy>
          <RevokeCertForm />
        </el-tab-pane>
      </el-tabs>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AppLayout from '@/components/AppLayout.vue'
import IssueCertForm from '@/components/IssueCertForm.vue'
import IssuedCertificates from '@/components/IssuedCertificates.vue'
import RevokeCertForm from '@/components/RevokeCertForm.vue'

const route = useRoute()
const router = useRouter()

const activeTab = computed({
  get() {
    const tab = route.query.tab
    return tab === 'issue' || tab === 'revoke' ? tab : 'issued'
  },
  set(tab) {
    router.push({ query: { ...route.query, tab: tab === 'issued' ? undefined : tab } })
  }
})
</script>

<style scoped>
.certificates-content {
  padding: 20px;
}
</style>
