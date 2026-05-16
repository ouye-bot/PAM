/**
 * SM2 密钥管理共享工具模块
 * 统一所有 SM2 相关操作的密钥派生、加解密、签名逻辑
 */
import { sm2, sm4 } from 'sm-crypto'

const bytesToHex = (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)))

/**
 * PBKDF2(SHA-256, 100000轮) 从密码派生 128-bit SM4 密钥
 */
export async function deriveSM4Key(password, salt) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  )
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 128
  )
  return bytesToHex(new Uint8Array(derivedBits))
}

/**
 * SM4-CBC 加密 SM2 私钥
 * @returns {string} "saltHex:ivHex:ciphertextHex"
 */
export async function encryptPrivateKey(privateKeyHex, password, providedSalt = null) {
  const salt = providedSalt || crypto.getRandomValues(new Uint8Array(16))
  const sm4KeyHex = await deriveSM4Key(password, salt)
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const ivHex = bytesToHex(iv)
  const ciphertextHex = sm4.encrypt(privateKeyHex, sm4KeyHex, { iv: ivHex })
  const saltHex = bytesToHex(salt)
  return `${saltHex}:${ivHex}:${ciphertextHex}`
}

/**
 * SM4-CBC 解密 SM2 私钥
 * @param {string} encryptedData "saltHex:ivHex:ciphertextHex"
 * @returns {string} 明文私钥 hex
 */
export async function decryptPrivateKey(encryptedData, password) {
  const [saltHex, ivHex, ciphertextHex] = encryptedData.split(':')
  const salt = hexToBytes(saltHex)
  const sm4KeyHex = await deriveSM4Key(password, salt)
  return sm4.decrypt(ciphertextHex, sm4KeyHex, { iv: ivHex })
}

/**
 * 生成 SM2 密钥对并返回 Base64 编码的公钥
 * @returns {{ privateKeyHex: string, publicKeyB64: string }}
 */
export function generateSm2KeyPair() {
  const keypair = sm2.generateKeyPairHex()
  let publicKeyHex = keypair.publicKey
  if (publicKeyHex.length === 130 && publicKeyHex.startsWith('04')) {
    publicKeyHex = publicKeyHex.substring(2)
  }
  const publicKeyBytes = hexToBytes(publicKeyHex)
  const publicKeyB64 = btoa(String.fromCharCode(...publicKeyBytes))
  return { privateKeyHex: keypair.privateKey, publicKeyB64 }
}

/**
 * SM2 签名挑战数据
 * @returns {string} Base64 编码的签名
 */
export function signChallenge(challenge, privateKeyHex) {
  const challengeStr = typeof challenge === 'object' ? JSON.stringify(challenge) : challenge
  const signatureHex = sm2.doSignature(challengeStr, privateKeyHex, { hash: true })
  const signatureBytes = hexToBytes(signatureHex)
  return btoa(String.fromCharCode(...signatureBytes))
}

/**
 * 从 localStorage 读取加密私钥并用密码解密
 * @returns {string|null} 明文私钥 hex，失败返回 null
 */
export async function loadAndDecryptPrivateKey(password) {
  const encryptedData = localStorage.getItem('sm2_encrypted_private_key')
  if (!encryptedData) return null
  try {
    return await decryptPrivateKey(encryptedData, password)
  } catch {
    return null
  }
}
