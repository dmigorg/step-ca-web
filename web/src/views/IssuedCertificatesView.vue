<template>
  <AppLayout>
    <template #title>Выданные сертификаты</template>
    <section class="inventory" aria-label="Реестр сертификатов">
      <div class="toolbar">
        <el-input v-model="query" aria-label="Поиск по домену или серийному номеру"
          placeholder="Домен или серийный номер" clearable />
        <el-checkbox v-model="includeExpired">Показывать истёкшие</el-checkbox>
        <el-button :loading="loading" @click="load">Обновить</el-button>
      </div>
      <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
      <el-table v-else v-loading="loading" :data="visibleRows" row-key="serial"
        :empty-text="loading ? 'Загрузка…' : 'Сертификаты не найдены'" stripe>
        <el-table-column label="Домен / SAN" min-width="225">
          <template #default="{ row }">
            <strong>{{ row.subject || row.sans || '—' }}</strong>
            <div v-if="row.subject && row.sans && row.sans !== row.subject" class="names">
              {{ row.sans }}
            </div>
          </template>
        </el-table-column>
        <el-table-column label="Серийный номер" min-width="210">
          <template #default="{ row }">
            <code class="serial">{{ row.serial }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="Источник" width="105" />
        <el-table-column label="Начало действия" min-width="165">
          <template #default="{ row }">{{ formatDate(row.notBefore) }}</template>
        </el-table-column>
        <el-table-column label="Окончание действия" min-width="180">
          <template #default="{ row }">
            <div>{{ formatDate(row.notAfter) }}</div>
            <el-tag v-if="Date.parse(row.notAfter) <= now" type="info" size="small">Срок истёк</el-tag>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination v-if="filtered.length > pageSize" v-model:current-page="page"
        :page-size="pageSize" :total="filtered.length" layout="prev, pager, next" />
    </section>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import AppLayout from '@/components/AppLayout.vue'
import { caApi } from '@/api/client'
import type { IssuedCertificate } from '@/types'

const rows = ref<IssuedCertificate[]>([])
const loading = ref(false)
const error = ref('')
const query = ref('')
const includeExpired = ref(false)
const page = ref(1)
const now = ref(Date.now())
const pageSize = 20

const dateFormat = new Intl.DateTimeFormat('ru-RU', {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  timeZoneName: 'short'
})

function formatDate(value: string) {
  return dateFormat.format(new Date(value))
}

const filtered = computed(() => {
  const term = query.value.trim().toLowerCase()
  return rows.value.filter((row) => {
    const withinTerm = Date.parse(row.notAfter) > now.value
    const matches = [row.subject, row.sans, row.serial].some((value) => value.toLowerCase().includes(term))
    return (includeExpired.value || withinTerm) && matches
  }).sort((left, right) => {
    const leftExpiry = Date.parse(left.notAfter)
    const rightExpiry = Date.parse(right.notAfter)
    const leftExpired = leftExpiry <= now.value
    const rightExpired = rightExpiry <= now.value
    if (leftExpired !== rightExpired) return leftExpired ? 1 : -1
    return leftExpired ? rightExpiry - leftExpiry : leftExpiry - rightExpiry
  })
})

const visibleRows = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize))

watch([query, includeExpired], () => {
  page.value = 1
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    rows.value = (await caApi.issuedCertificates()).certificates
    now.value = Date.now()
    page.value = 1
  } catch {
    error.value = 'Не удалось загрузить реестр сертификатов. Попробуйте обновить список.'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.inventory {
  display: grid;
  min-width: 0;
  gap: 16px;
}

.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
}

.toolbar .el-input {
  width: min(100%, 300px);
}

.serial {
  overflow-wrap: anywhere;
}

.names {
  color: var(--el-text-color-secondary);
}
</style>
