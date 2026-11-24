import { defineStore } from 'pinia'
import { ref } from 'vue'
import { authApi, getErrorMessage } from '@/api/client'

export const useAuthStore = defineStore('auth', () => {
  const isAuthenticated = ref(false)
  const provisionerName = ref('')
  const isLoading = ref(false)
  const error = ref('')

  function clearSession() {
    isAuthenticated.value = false
    provisionerName.value = ''
  }

  async function login(password: string) {
    isLoading.value = true
    error.value = ''
    try {
      const response = await authApi.login(password)
      isAuthenticated.value = true
      provisionerName.value = response.provisioner
    } catch (err) {
      error.value = getErrorMessage(err)
      throw err
    } finally {
      isLoading.value = false
    }
  }

  async function logout() {
    try {
      await authApi.logout()
    } finally {
      clearSession()
    }
  }

  async function checkAuth() {
    try {
      const response = await authApi.check()
      isAuthenticated.value = response.authenticated
      provisionerName.value = response.provisioner || ''
    } catch {
      clearSession()
    }
  }

  return {
    isAuthenticated,
    provisionerName,
    isLoading,
    error,
    clearSession,
    login,
    logout,
    checkAuth
  }
})
