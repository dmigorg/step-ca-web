<template>
  <AppLayout>
    <template #title>Roots & Intermediates</template>

    <div class="roots-content">
      <el-row :gutter="20">
        <el-col :span="24">
          <el-card shadow="hover">
            <template #header>
              <div class="card-header">
                <el-icon><Key /></el-icon>
                <span>Root Certificates</span>
                <el-button :icon="Refresh" circle size="small" @click="caStore.fetchRoots()" :loading="caStore.isLoading" style="margin-left: auto;" />
              </div>
            </template>

            <div v-loading="caStore.isLoading">
              <el-empty v-if="!caStore.roots?.crts?.length" description="No root certificates found" />

              <el-collapse v-else>
                <el-collapse-item
                  v-for="(cert, index) in caStore.roots.crts"
                  :key="index"
                  :name="index"
                >
                  <template #title>
                    <div class="cert-title">
                      <el-tag type="success" size="small">Root {{ index + 1 }}</el-tag>
                      <span>Root Certificate</span>
                    </div>
                  </template>
                  <CertDisplay :pem="cert" :label="`Root Certificate ${index + 1}`" />
                </el-collapse-item>
              </el-collapse>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <el-row :gutter="20" style="margin-top: 20px;">
        <el-col :span="24">
          <el-card shadow="hover">
            <template #header>
              <div class="card-header">
                <el-icon><Link /></el-icon>
                <span>Intermediate Certificates</span>
                <el-button :icon="Refresh" circle size="small" @click="caStore.fetchIntermediates()" :loading="caStore.isLoading" style="margin-left: auto;" />
              </div>
            </template>

            <div v-loading="caStore.isLoading">
              <el-empty v-if="!caStore.intermediates?.crts?.length" description="No intermediate certificates found" />

              <el-collapse v-else>
                <el-collapse-item
                  v-for="(cert, index) in caStore.intermediates.crts"
                  :key="index"
                  :name="index"
                >
                  <template #title>
                    <div class="cert-title">
                      <el-tag type="warning" size="small">Intermediate {{ index + 1 }}</el-tag>
                      <span>Intermediate Certificate</span>
                    </div>
                  </template>
                  <CertDisplay :pem="cert" :label="`Intermediate Certificate ${index + 1}`" />
                </el-collapse-item>
              </el-collapse>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { useCaStore } from '@/stores/ca'
import AppLayout from '@/components/AppLayout.vue'
import CertDisplay from '@/components/CertDisplay.vue'

const caStore = useCaStore()

onMounted(() => {
  if (!caStore.roots) {
    caStore.fetchRoots()
  }
  if (!caStore.intermediates) {
    caStore.fetchIntermediates()
  }
})
</script>

<style scoped>
.roots-content {
  padding: 20px;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 500;
}

.cert-title {
  display: flex;
  align-items: center;
  gap: 12px;
}
</style>
