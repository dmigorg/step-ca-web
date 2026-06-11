<template>
  <el-container class="app-layout">
    <el-aside :width="isCollapsed ? '64px' : '220px'" class="sidebar">
      <div class="logo-container">
        <el-icon :size="24"><Key /></el-icon>
        <span v-show="!isCollapsed" class="logo-text">Step CA</span>
      </div>

      <el-menu
        :default-active="route.path"
        :collapse="isCollapsed"
        router
        class="sidebar-menu"
      >
        <el-menu-item index="/dashboard">
          <el-icon><DataBoard /></el-icon>
          <template #title>Dashboard</template>
        </el-menu-item>

        <el-menu-item index="/provisioners">
          <el-icon><User /></el-icon>
          <template #title>Provisioners</template>
        </el-menu-item>

        <el-menu-item index="/certificates">
          <el-icon><Document /></el-icon>
          <template #title>Certificates</template>
        </el-menu-item>

        <el-menu-item index="/roots">
          <el-icon><Key /></el-icon>
          <template #title>Roots</template>
        </el-menu-item>

        <el-menu-item index="/inspector">
          <el-icon><View /></el-icon>
          <template #title>Inspector</template>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="header">
        <div class="header-left">
          <el-button :icon="isCollapsed ? Expand : Fold" text @click="isCollapsed = !isCollapsed" />
          <h2><slot name="title">Dashboard</slot></h2>
        </div>
        <div class="header-right">
          <el-dropdown @command="handleCommand">
            <el-button text>
              <el-icon><UserFilled /></el-icon>
              <span style="margin-left: 8px;">{{ authStore.provisionerName || 'User' }}</span>
              <el-icon style="margin-left: 4px;"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">
                  <el-icon><SwitchButton /></el-icon>
                  Logout
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <el-main class="main-content">
        <slot></slot>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Expand, Fold } from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const isCollapsed = ref(false)

async function handleCommand(command: string) {
  if (command === 'logout') {
    await authStore.logout()
    router.push('/login')
  }
}
</script>

<style scoped>
.app-layout {
  height: 100vh;
}

.sidebar {
  background: #304156;
  transition: width 0.3s;
}

.logo-container {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  color: white;
  font-size: 18px;
  font-weight: bold;
  border-bottom: 1px solid #3a4a5c;
}

.logo-text {
  white-space: nowrap;
}

.sidebar-menu {
  border-right: none;
  background: #304156;
}

:deep(.el-menu-item) {
  color: #bfcbd9;
}

:deep(.el-menu-item:hover),
:deep(.el-menu-item.is-active) {
  background: #263445 !important;
  color: #409eff;
}

.header {
  background: white;
  box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.header-left h2 {
  margin: 0;
  font-size: 20px;
  color: #303133;
}

.header-right {
  display: flex;
  align-items: center;
}

.main-content {
  background: #f5f7fa;
  padding: 0;
}
</style>
