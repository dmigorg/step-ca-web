import { defineStore } from 'pinia'
import { ref } from 'vue'
import { authApi, getErrorMessage } from '@/api/client'

export const useAuthStore = defineStore('auth', () => {
  const isAuthenticated = ref(false)
  const provisionerName = ref('')
  const isLoading = ref(false)
  const error = ref('')

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
      isAuthenticated.value = false
      provisionerName.value = ''
    }
  }

  async function checkAuth() {
    try {
      const response = await authApi.check()
      isAuthenticated.value = response.authenticated
      provisionerName.value = response.provisioner || ''
    } catch {
      isAuthenticated.value = false
      provisionerName.value = ''
    }
  }

  return {
    isAuthenticated,
    provisionerName,
    isLoading,
    error,
    login,
    logout,
    checkAuth
  }
})
