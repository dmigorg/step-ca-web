<template>
  <AppLayout>
    <template #title>Provisioners</template>

    <div class="provisioners-content">
      <el-card shadow="hover">
        <template #header>
          <div class="card-header">
            <span>Provisioners List</span>
            <el-button :icon="Refresh" circle @click="caStore.fetchProvisioners()" :loading="caStore.isLoading" />
          </div>
        </template>

        <el-table
          :data="caStore.provisioners?.provisioners || []"
          stripe
          style="width: 100%;"
          v-loading="caStore.isLoading"
        >
          <el-table-column prop="name" label="Name" min-width="150" />
          <el-table-column prop="type" label="Type" width="120">
            <template #default="{ row }">
              <el-tag :type="getProvisionerTagType(row.type)" size="small">
                {{ row.type }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Key ID" min-width="200">
            <template #default="{ row }">
              <el-tooltip :content="row.key?.kid || 'N/A'" placement="top">
                <span class="kid-text">{{ truncateKID(row.key?.kid) }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="Algorithm" width="120">
            <template #default="{ row }">
              {{ row.key?.alg || 'N/A' }}
            </template>
          </el-table-column>
          <el-table-column label="Encrypted Key" width="120">
            <template #default="{ row }">
              <el-tag :type="row.encryptedKey ? 'success' : 'info'" size="small">
                {{ row.encryptedKey ? 'Yes' : 'No' }}
              </el-tag>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { useCaStore } from '@/stores/ca'
import AppLayout from '@/components/AppLayout.vue'

const caStore = useCaStore()

onMounted(() => {
  if (!caStore.provisioners) {
    caStore.fetchProvisioners()
  }
})

function getProvisionerTagType(type: string): '' | 'success' | 'warning' | 'info' | 'danger' {
  switch (type) {
    case 'JWK': return 'primary' as ''
    case 'OIDC': return 'success'
    case 'X5C': return 'warning'
    case 'ACME': return 'info'
    default: return 'info'
  }
}

function truncateKID(kid?: string): string {
  if (!kid) return 'N/A'
  if (kid.length <= 20) return kid
  return kid.substring(0, 20) + '...'
}
</script>

<style scoped>
.provisioners-content {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.kid-text {
  font-family: monospace;
  font-size: 12px;
  color: #606266;
}
</style>
