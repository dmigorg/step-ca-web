import { defineStore } from 'pinia'
import { ref } from 'vue'
import { caApi, getErrorMessage } from '@/api/client'
import type {
  HealthResponse,
  VersionResponse,
  RootsResponse,
  IntermediatesResponse,
  ProvisionersResponse
} from '@/types'

export const useCaStore = defineStore('ca', () => {
  const health = ref<HealthResponse | null>(null)
  const version = ref<VersionResponse | null>(null)
  const roots = ref<RootsResponse | null>(null)
  const intermediates = ref<IntermediatesResponse | null>(null)
  const provisioners = ref<ProvisionersResponse | null>(null)
  const isLoading = ref(false)
  const error = ref('')

  async function fetchHealth() {
    try {
      health.value = await caApi.health()
    } catch (err) {
      error.value = getErrorMessage(err)
      health.value = null
    }
  }

  async function fetchVersion() {
    try {
      version.value = await caApi.version()
    } catch (err) {
      error.value = getErrorMessage(err)
      version.value = null
    }
  }

  async function fetchRoots() {
    try {
      roots.value = await caApi.roots()
    } catch (err) {
      error.value = getErrorMessage(err)
      roots.value = null
    }
  }

  async function fetchIntermediates() {
    try {
      intermediates.value = await caApi.intermediates()
    } catch (err) {
      error.value = getErrorMessage(err)
      intermediates.value = null
    }
  }

  async function fetchProvisioners() {
    try {
      provisioners.value = await caApi.provisioners()
    } catch (err) {
      error.value = getErrorMessage(err)
      provisioners.value = null
    }
  }

  async function fetchAll() {
    isLoading.value = true
    error.value = ''
    try {
      await Promise.all([
        fetchHealth(),
        fetchVersion(),
        fetchRoots(),
        fetchIntermediates(),
        fetchProvisioners()
      ])
    } finally {
      isLoading.value = false
    }
  }

  function clearData() {
    health.value = null
    version.value = null
    roots.value = null
    intermediates.value = null
    provisioners.value = null
  }

  return {
    health,
    version,
    roots,
    intermediates,
    provisioners,
    isLoading,
    error,
    fetchHealth,
    fetchVersion,
    fetchRoots,
    fetchIntermediates,
    fetchProvisioners,
    fetchAll,
    clearData
  }
})
