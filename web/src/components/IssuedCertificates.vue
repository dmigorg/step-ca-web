<template>
  <div class="inventory-content">
    <div class="toolbar">
      <el-input
        v-model="query"
        aria-label="Search by domain or serial number"
        placeholder="Domain or serial number"
        clearable
      />
      <el-checkbox v-model="showHistory">Show history</el-checkbox>
      <el-checkbox v-model="includeExpired">Show expired</el-checkbox>
      <el-button
        :icon="Refresh"
        circle
        class="refresh-button"
        aria-label="Refresh certificate list"
        :loading="loading"
        @click="load"
      />
    </div>

    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
    <el-table
      v-else
      v-loading="loading"
      :data="visibleRows"
      row-key="serial"
      :empty-text="loading ? 'Loading…' : 'No certificates found'"
      stripe
      style="width: 100%;"
    >
      <el-table-column label="Domain / SAN" min-width="205">
        <template #default="{ row }">
          <span>{{ row.subject || row.displaySANs || '—' }}</span>
          <div v-if="row.subject && row.displaySANs && row.displaySANs !== row.subject" class="names">
            {{ row.displaySANs }}
          </div>
        </template>
      </el-table-column>
      <el-table-column label="Serial Number" min-width="170" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="serial">{{ row.serial }}</span>
        </template>
      </el-table-column>
      <el-table-column label="Source" width="100">
        <template #default="{ row }">
          <el-tag type="info" size="small">{{ row.source }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Not Before" min-width="165">
        <template #default="{ row }">{{ formatDate(row.notBefore) }}</template>
      </el-table-column>
      <el-table-column label="Not After" min-width="175">
        <template #default="{ row }">
          <div>{{ formatDate(row.notAfter) }}</div>
          <el-tag v-if="row.revoked" type="danger" size="small">Revoked</el-tag>
          <el-tag v-else-if="row.endsAt <= now" type="info" size="small">Expired</el-tag>
        </template>
      </el-table-column>
    </el-table>

    <el-pagination
      v-if="filtered.length > pageSize"
      v-model:current-page="page"
      :page-size="pageSize"
      :total="filtered.length"
      layout="prev, pager, next"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { caApi } from '@/api/client'
import type { IssuedCertificate } from '@/types'

type CertificateRow = IssuedCertificate & {
  displaySANs: string
  identity: string
  startsAt: number
  endsAt: number
}

const rows = ref<CertificateRow[]>([])
const loading = ref(false)
const error = ref('')
const query = ref('')
const showHistory = ref(false)
const includeExpired = ref(false)
const page = ref(1)
const now = ref(Date.now())
const pageSize = 20

const dateFormat = new Intl.DateTimeFormat('en-US', {
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

function toCertificateRow(cert: IssuedCertificate): CertificateRow {
  const names: string[] = []
  const keys: string[] = []
  const loggedGroups = cert.sans.match(/^map\[(.*)\]$/)?.[1]
  if (loggedGroups !== undefined) {
    // step-ca logs SANs as a Go map containing DNS, IP, e-mail and URI lists.
    for (const [, kind, values] of loggedGroups.matchAll(/(dns|ip|email|uri):\[(.*?)\](?=\s+(?:dns|ip|email|uri):\[|$)/g)) {
      for (const value of values.trim().split(/\s+/).filter(Boolean)) {
        names.push(value)
        keys.push(kind === 'dns' ? 'dns:' + value.toLowerCase().replace(/\.$/, '') : kind + ':' + value)
      }
    }
  }

  const displaySANs = names.join(', ') || (loggedGroups === '' ? '' : cert.sans)
  const identity = keys.length > 0
    ? JSON.stringify([...new Set(keys)].sort())
    : (displaySANs || cert.subject).trim().toLowerCase() || cert.serial
  return {
    ...cert,
    displaySANs,
    identity,
    startsAt: Date.parse(cert.notBefore),
    endsAt: Date.parse(cert.notAfter)
  }
}

const matchingValidity = computed(() =>
  rows.value.filter((row) => includeExpired.value || row.endsAt > now.value)
)

const displayed = computed(() => {
  if (showHistory.value) return matchingValidity.value

  const latest = new Map<string, CertificateRow>()
  for (const row of matchingValidity.value) {
    if (row.revoked) continue
    const previous = latest.get(row.identity)
    const newer = !previous || row.startsAt > previous.startsAt
    const laterExpiry = previous && row.startsAt === previous.startsAt && row.endsAt > previous.endsAt
    if (newer || laterExpiry) latest.set(row.identity, row)
  }
  return [...latest.values()]
})

const filtered = computed(() => {
  const term = query.value.trim().toLowerCase()
  return displayed.value.filter((row) =>
    [row.subject, row.displaySANs, row.serial].some((value) => value.toLowerCase().includes(term))
  ).sort((left, right) => {
    const leftExpired = left.endsAt <= now.value
    const rightExpired = right.endsAt <= now.value
    if (leftExpired !== rightExpired) return leftExpired ? 1 : -1
    return leftExpired ? right.endsAt - left.endsAt : left.endsAt - right.endsAt
  })
})

const visibleRows = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize))

watch([query, showHistory, includeExpired], () => {
  page.value = 1
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    rows.value = (await caApi.issuedCertificates()).certificates.map(toCertificateRow)
    now.value = Date.now()
    page.value = 1
  } catch {
    error.value = 'Could not load the certificate inventory. Try refreshing.'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.inventory-content {
  min-width: 0;
}

.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.toolbar .el-input {
  width: min(100%, 300px);
}

.toolbar .el-checkbox {
  margin-right: 0;
}

.refresh-button {
  margin-left: auto;
}

.serial {
  font-family: monospace;
  font-size: 12px;
  color: var(--el-text-color-regular);
}

.names {
  color: var(--el-text-color-secondary);
}

.el-pagination {
  margin-top: 16px;
}
</style>
