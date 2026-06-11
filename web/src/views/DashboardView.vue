<template>
  <AppLayout>
    <template #title>Dashboard</template>

    <div class="dashboard-content">
      <el-row :gutter="20">
        <el-col :xs="24" :sm="12" :md="6">
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="card-header">
                <el-icon><CircleCheck /></el-icon>
                <span>CA Status</span>
              </div>
            </template>
            <div class="stat-value">
              <el-tag :type="caStore.health?.status === 'ok' ? 'success' : 'danger'" size="large">
                {{ caStore.health?.status || 'Unknown' }}
              </el-tag>
            </div>
          </el-card>
        </el-col>

        <el-col :xs="24" :sm="12" :md="6">
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="card-header">
                <el-icon><InfoFilled /></el-icon>
                <span>CA Version</span>
              </div>
            </template>
            <div class="stat-value">
              {{ caStore.version?.version || 'N/A' }}
            </div>
          </el-card>
        </el-col>

        <el-col :xs="24" :sm="12" :md="6">
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="card-header">
                <el-icon><Document /></el-icon>
                <span>Root Certs</span>
              </div>
            </template>
            <div class="stat-value">
              {{ caStore.roots?.crts?.length || 0 }}
            </div>
          </el-card>
        </el-col>

        <el-col :xs="24" :sm="12" :md="6">
          <el-card shadow="hover" class="stat-card">
            <template #header>
              <div class="card-header">
                <el-icon><User /></el-icon>
                <span>Provisioners</span>
              </div>
            </template>
            <div class="stat-value">
              {{ caStore.provisioners?.provisioners?.length || 0 }}
            </div>
          </el-card>
        </el-col>
      </el-row>

      <el-row :gutter="20" style="margin-top: 20px;">
        <el-col :span="24">
          <el-card shadow="hover">
            <template #header>
              <div class="card-header">
                <el-icon><Connection /></el-icon>
                <span>Session Info</span>
              </div>
            </template>
            <el-descriptions :column="2" border>
              <el-descriptions-item label="Provisioner">
                {{ authStore.provisionerName || 'N/A' }}
              </el-descriptions-item>
              <el-descriptions-item label="Authenticated">
                <el-tag type="success">Yes</el-tag>
              </el-descriptions-item>
            </el-descriptions>
          </el-card>
        </el-col>
      </el-row>

      <el-row :gutter="20" style="margin-top: 20px;" v-if="caStore.roots?.crts?.length">
        <el-col :span="24">
          <el-card shadow="hover">
            <template #header>
              <div class="card-header">
                <el-icon><Key /></el-icon>
                <span>Root Certificate</span>
              </div>
            </template>
            <CertDisplay :pem="caStore.roots.crts[0]" label="Root CA Certificate" />
          </el-card>
        </el-col>
      </el-row>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useCaStore } from '@/stores/ca'
import AppLayout from '@/components/AppLayout.vue'
import CertDisplay from '@/components/CertDisplay.vue'

const authStore = useAuthStore()
const caStore = useCaStore()

onMounted(() => {
  caStore.fetchAll()
})
</script>

<style scoped>
.dashboard-content {
  padding: 20px;
}

.stat-card {
  text-align: center;
}

.stat-card .card-header {
  display: flex;
  align-items: center;
  gap: 8px;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  color: #303133;
  padding: 10px 0;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 500;
}
</style>
