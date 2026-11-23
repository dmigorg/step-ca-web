export interface HealthResponse {
  status: string
}

export interface VersionResponse {
  version: string
  requireClientAuthentication?: boolean
}

export interface RootsResponse {
  crts: string[]
}

export interface IntermediatesResponse {
  crts: string[]
}

export interface ProvisionerKey {
  type: string
  name: string
  key?: {
    kty?: string
    kid?: string
    crv?: string
    alg?: string
    x?: string
    y?: string
  }
  encryptedKey?: string
  claims?: Record<string, unknown>
}

export interface ProvisionersResponse {
  provisioners: ProvisionerKey[]
  nextCursor?: string
}

export interface SignRequest {
  cn: string
  sans: string[]
  notBefore?: string
  notAfter?: string
  csr?: string
  templateData?: Record<string, unknown>
}

export interface SignResult {
  certificate: string
  privateKey?: string
  caChain: string
  certChain?: string[]
}

export interface RevokeRequest {
  serial: string
  reasonCode: number
  reason?: string
}

export interface RevokeResponse {
  status: string
}

export interface LoginRequest {
  password: string
}

export interface LoginResponse {
  provisioner: string
  kid: string
}

export interface AuthCheckResponse {
  authenticated: boolean
  provisioner?: string
  kid?: string
}

export interface CertInfo {
  version: number
  serial: string
  signatureAlgo: string
  publicKeyAlgo: string
  publicKeySize: number
  subject: string
  subjectFull: string
  issuer: string
  issuerFull: string
  notBefore: string
  notAfter: string
  dnsNames?: string[]
  ipAddresses?: string[]
  emailAddresses?: string[]
  uris?: string[]
  keyUsage: string
  extKeyUsage?: string[]
  isCA: boolean
  selfSigned: boolean
  ocspServers?: string[]
  crlDistPoints?: string[]
  issuerURLs?: string[]
}

export interface CSRInfo {
  subject: string
  subjectFull: string
  publicKeyAlgo: string
  publicKeySize: number
  signatureAlgo: string
  dnsNames?: string[]
  ipAddresses?: string[]
  emailAddresses?: string[]
  uris?: string[]
  attributes?: Record<string, string>
}

export interface ApiError {
  error: string
}

export interface CNFParsedResult {
  commonName: string
  organization?: string
  organizationalUnit?: string
  country?: string
  state?: string
  locality?: string
  dnsNames?: string[]
  ipAddresses?: string[]
  emailAddresses?: string[]
  uris?: string[]
  keyUsage?: string[]
  extKeyUsage?: string[]
}

export interface SignCNFRequest {
  content: string
  notBefore?: string
  notAfter?: string
}

export interface IssuedCertificate {
  serial: string
  subject: string
  sans: string
  source: string
  notBefore: string
  notAfter: string
  revoked: boolean
}

export interface CertificateInventory {
  certificates: IssuedCertificate[]
}
