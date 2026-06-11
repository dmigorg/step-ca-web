<template>
  <div class="login-container">
    <el-card class="login-card" shadow="hover">
      <template #header>
        <div class="login-header">
          <el-icon :size="32"><Key /></el-icon>
          <h2>Step CA Web Interface</h2>
          <p class="subtitle">Enter your provisioner password to continue</p>
        </div>
      </template>

      <el-form @submit.prevent="handleLogin" class="login-form">
        <el-form-item>
          <el-input
            v-model="password"
            type="password"
            placeholder="Provisioner Password"
            show-password
            size="large"
            :disabled="authStore.isLoading"
            @keyup.enter="handleLogin"
          >
            <template #prefix>
              <el-icon><Lock /></el-icon>
            </template>
          </el-input>
        </el-form-item>

        <el-alert
          v-if="authStore.error"
          :title="authStore.error"
          type="error"
          show-icon
          closable
          @close="authStore.error = ''"
          style="margin-bottom: 16px;"
        />

        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="authStore.isLoading"
            @click="handleLogin"
            style="width: 100%;"
          >
            Sign In
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { ElMessage } from 'element-plus'

const router = useRouter()
const authStore = useAuthStore()
const password = ref('')

async function handleLogin() {
  if (!password.value) {
    ElMessage.warning('Please enter your password')
    return
  }

  try {
    await authStore.login(password.value)
    password.value = ''
    router.push('/dashboard')
  } catch {
    // Error is already handled in the store
  }
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.login-card {
  width: 400px;
  max-width: 90vw;
}

.login-header {
  text-align: center;
}

.login-header h2 {
  margin: 16px 0 8px;
  color: #303133;
}

.login-header .subtitle {
  margin: 0;
  color: #909399;
  font-size: 14px;
}

.login-form {
  margin-top: 20px;
}
</style>
