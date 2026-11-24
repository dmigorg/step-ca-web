import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { public: true }
    },
    {
      path: '/',
      redirect: '/dashboard'
    },
    {
      path: '/dashboard',
      name: 'dashboard',
      component: () => import('@/views/DashboardView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/provisioners',
      name: 'provisioners',
      component: () => import('@/views/ProvisionersView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/provisioners/acme',
      name: 'acme-settings',
      component: () => import('@/views/ACMESettingsView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/certificates',
      name: 'certificates',
      component: () => import('@/views/CertificatesView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/roots',
      name: 'roots',
      component: () => import('@/views/RootsView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/issuance-policy',
      name: 'issuance-policy',
      component: () => import('@/views/IssuancePolicyView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/inspector',
      name: 'inspector',
      component: () => import('@/views/InspectorView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/:pathMatch(.*)*',
      redirect: '/dashboard'
    }
  ]
})

router.beforeEach(async (to) => {
  const authStore = useAuthStore()

  if (!to.meta.public && to.meta.requiresAuth) {
    if (!authStore.isAuthenticated) {
      await authStore.checkAuth()
      if (!authStore.isAuthenticated) {
        return { name: 'login' }
      }
    }
  }

  if (to.name === 'login' && authStore.isAuthenticated) {
    return { name: 'dashboard' }
  }
})

export default router
