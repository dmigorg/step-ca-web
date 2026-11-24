import axios, { type AxiosError } from 'axios'
import router from '@/router'
import { useAuthStore } from '@/stores/auth'
import type {
  HealthResponse,
  VersionResponse,
  RootsResponse,
  IntermediatesResponse,
  ProvisionersResponse,
  SignRequest,
  SignResult,
  RevokeRequest,
  RevokeResponse,
  LoginRequest,
  LoginResponse,
  AuthCheckResponse,
  CertInfo,
  CSRInfo,
  ApiError,
  CNFParsedResult,
  SignCNFRequest,
  CertificateInventory,
  ACMEProvisionerSettings,
  ACMEProvisionerUpdate,
  IssuancePolicySettings,
  IssuancePolicyUpdate
} from '@/types'

const api = axios.create({
  baseURL: '',
  timeout: 30000
})

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiError>) => {
    if (error.response?.status === 401 && error.config?.url !== '/auth/login') {
      const auth = useAuthStore()
      const wasAuthenticated = auth.isAuthenticated
      auth.clearSession()
      if (wasAuthenticated && router.currentRoute.value.meta.requiresAuth) {
        void router.replace({ name: 'login' })
      }
    }
    return Promise.reject(error)
  }
)

export const authApi = {
  async login(password: string): Promise<LoginResponse> {
    const req: LoginRequest = { password }
    const response = await api.post<LoginResponse>('/auth/login', req)
    return response.data
  },

  async logout(): Promise<void> {
    await api.post('/auth/logout')
  },

  async check(): Promise<AuthCheckResponse> {
    const response = await api.get<AuthCheckResponse>('/auth/check')
    return response.data
  }
}

export const caApi = {
  async acmeSettings(): Promise<ACMEProvisionerSettings> {
    return (await api.get<ACMEProvisionerSettings>('/api/settings/acme')).data
  },

  async updateACMESettings(update: ACMEProvisionerUpdate): Promise<ACMEProvisionerSettings> {
    return (await api.put<ACMEProvisionerSettings>('/api/settings/acme', update)).data
  },

  async issuancePolicy(): Promise<IssuancePolicySettings> {
    return (await api.get<IssuancePolicySettings>('/api/settings/issuance-policy')).data
  },

  async updateIssuancePolicy(update: IssuancePolicyUpdate): Promise<IssuancePolicySettings> {
    return (await api.put<IssuancePolicySettings>('/api/settings/issuance-policy', update)).data
  },

  async issuedCertificates(): Promise<CertificateInventory> {
    const response = await api.get<CertificateInventory>('/api/certificates/issued')
    return response.data
  },

  async health(): Promise<HealthResponse> {
    const response = await api.get<HealthResponse>('/api/health')
    return response.data
  },

  async version(): Promise<VersionResponse> {
    const response = await api.get<VersionResponse>('/api/version')
    return response.data
  },

  async roots(): Promise<RootsResponse> {
    const response = await api.get<RootsResponse>('/api/roots')
    return response.data
  },

  async intermediates(): Promise<IntermediatesResponse> {
    const response = await api.get<IntermediatesResponse>('/api/intermediates')
    return response.data
  },

  async provisioners(): Promise<ProvisionersResponse> {
    const response = await api.get<ProvisionersResponse>('/api/provisioners')
    return response.data
  },

  async sign(req: SignRequest): Promise<SignResult> {
    const response = await api.post<SignResult>('/api/sign', req)
    return response.data
  },

  async revoke(req: RevokeRequest): Promise<RevokeResponse> {
    const response = await api.post<RevokeResponse>('/api/revoke', req)
    return response.data
  },

  async parseCert(pem: string): Promise<CertInfo> {
    const response = await api.post<CertInfo>('/api/parse-cert', { pem })
    return response.data
  },

  async parseCSR(pem: string): Promise<CSRInfo> {
    const response = await api.post<CSRInfo>('/api/parse-csr', { pem })
    return response.data
  },

  async parseCNF(content: string): Promise<CNFParsedResult> {
    const response = await api.post<CNFParsedResult>('/api/parse-cnf', { content })
    return response.data
  },

  async signCNF(req: SignCNFRequest): Promise<SignResult> {
    const response = await api.post<SignResult>('/api/sign-cnf', req)
    return response.data
  }
}

export function getErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const apiError = error.response?.data as ApiError | undefined
    if (apiError?.error) {
      return apiError.error
    }
    return error.message || 'An error occurred'
  }
  if (error instanceof Error) {
    return error.message
  }
  return 'An unknown error occurred'
}

export default api
