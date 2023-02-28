// Some key params for the ecryption and decryption to work.
// Preferred IV length is 12 bytes for AES-256-GCM.
// I don't know why.
const ivLength = 12
// Salt length in bytes:
const saltLength = 16
const pbkdf2Iterations = 10000

/**
 * Creates both the actual derived key and a salt.
 * @param {string} passphrase 
 * @param {Uint8Array} salt - Optional, will be generated randomly if not present
 * @returns Object with "key" (CryptoKey) and "salt" (Uint8Array)
 */
export async function deriveKey(passphrase, salt) {
  // Need to convert the string to byte array.
  // When you're a normal person you use TextEncoder.
  const enc = new TextEncoder()

  const key = await crypto.subtle.importKey(
    "raw", //only "raw" is allowed
    enc.encode(passphrase), //your password
    { name: "PBKDF2" },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
  )

  if (!salt) {
    salt = crypto.getRandomValues(new Uint8Array(saltLength))
  }

  const cryptoKey = await crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt: salt,
      iterations: pbkdf2Iterations,
      hash: { name: "SHA-512" },
    },
    key,
    { "name": "AES-GCM", "length": 256 },
    true,
    ["encrypt", "decrypt"]
  )

  return {
    key: cryptoKey,
    salt
  }
}

/**
 * Perform the encryption
 * @param {string} text 
 * @param {string} passphrase
 * @returns {string} the full ciphertext, including iv and salt (in that order) appended to it, encoded in base64
 */
export async function encrypt(text, passphrase) {
  const { key, salt } = await deriveKey(passphrase)
  // Generate an IV. We'll put it right before the encrypted 
  // message.
  const iv = crypto.getRandomValues(new Uint8Array(ivLength))

  const enc = new TextEncoder()
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    enc.encode(text)
  )
  const cipherBytes = new Uint8Array(ciphertext)

  // Append salt and IV.
  const fullBytes = new Uint8Array(cipherBytes.length + salt.length + iv.length)
  fullBytes.set(salt);
  fullBytes.set(iv, salt.length);
  fullBytes.set(cipherBytes, salt.length + iv.length);

  return Uint8ArrayToBase64(fullBytes)
}

export async function decrypt(ciphertextB64, passphrase) {
  // Convert ciphertext from base64:
  const ciphertext = base64DecToArr(ciphertextB64)

  // Extract the salt from the ciphertext, then
  // derive the key.
  if (ciphertext.length <= saltLength + ivLength) {
    throw new Error('Invalid cipher text')
  }
  const salt = ciphertext.slice(0, saltLength)
  const { key } = await deriveKey(passphrase, salt)

  // Extract the IV:
  const iv = ciphertext.slice(saltLength, saltLength + ivLength)

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    ciphertext.slice(saltLength + ivLength)
  )

  const dec = new TextDecoder();
  return dec.decode(decrypted)
}

/**
 * @param {Uint8Array} aBytes 
 * @returns {string}
 */
function Uint8ArrayToBase64(aBytes) {

  var nMod3 = 2, sB64Enc = ""

  for (var nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
    nMod3 = nIdx % 3
    if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0) { sB64Enc += "\r\n" }
    nUint24 |= aBytes[nIdx] << (16 >>> nMod3 & 24)
    if (nMod3 === 2 || aBytes.length - nIdx === 1) {
      sB64Enc += String.fromCharCode(uint6ToB64(nUint24 >>> 18 & 63), uint6ToB64(nUint24 >>> 12 & 63), uint6ToB64(nUint24 >>> 6 & 63), uint6ToB64(nUint24 & 63));
      nUint24 = 0
    }
  }

  return sB64Enc.substr(0, sB64Enc.length - 2 + nMod3) + (nMod3 === 2 ? '' : nMod3 === 1 ? '=' : '==')

}

/**
 * Stole this from here: https://developer.mozilla.org/en-US/docs/Glossary/Base64
 * @param {string} sBase64 source base64 string
 * @param {number} nBlocksSize OPTIONAL don't provide it
 * @returns {Uint8Array} The byte array decoded from the base64 string
 */
function base64DecToArr(sBase64, nBlocksSize) {
  var
    sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""), nInLen = sB64Enc.length,
    nOutLen = nBlocksSize ? Math.ceil((nInLen * 3 + 1 >> 2) / nBlocksSize) * nBlocksSize : nInLen * 3 + 1 >> 2, taBytes = new Uint8Array(nOutLen);

  for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
    nMod4 = nInIdx & 3;
    nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 6 * (3 - nMod4);
    if (nMod4 === 3 || nInLen - nInIdx === 1) {
      for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
        taBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
      }
      nUint24 = 0;
    }
  }

  return taBytes;
}

function b64ToUint6(nChr) {

  return nChr > 64 && nChr < 91 ?
    nChr - 65
    : nChr > 96 && nChr < 123 ?
      nChr - 71
      : nChr > 47 && nChr < 58 ?
        nChr + 4
        : nChr === 43 ?
          62
          : nChr === 47 ?
            63
            :
            0
}

function uint6ToB64(nUint6) {

  return nUint6 < 26 ?
    nUint6 + 65
    : nUint6 < 52 ?
      nUint6 + 71
      : nUint6 < 62 ?
        nUint6 - 4
        : nUint6 === 62 ?
          43
          : nUint6 === 63 ?
            47
            :
            65
}

/**
 * I found this function here: https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
 * It's just using atob then converting...
 * There might be a more terse way to do this.
 * @param {string} base64
 * @returns {Uint8Array} the result
 */
/*
function base64ToUint8Array(base64) {
 const binary_string = atob(base64);
 const len = binary_string.length;
 let bytes = new Uint8Array(len);
 for (let i = 0; i < len; i++) {
   bytes[i] = binary_string.charCodeAt(i);
 }
 return bytes;
}
*/

export async function decodeCertificate(encoded) {
  // Remove first line if it contains "BEGIN" ans last line 
  // if it contains "END":
  encoded = encoded.replace(/-+BEGIN\s\w+-*/, '')
    .replace(/-+END\s\w+-*/, '')
    .replace(/\s/g, '')
  // Convert base64 to ArrayBuffer:
  const bytes = base64DecToArr(encoded)
  // Try to import the key:
  const signAlgorithm = {
    name: "RSA-PSS",
    hash: "SHA-256",
  }
  try {
    const certInfo = await crypto.subtle.
      importKey("spki", bytes, signAlgorithm, true, ["sign"])
    return certInfo
  } catch (ex) {
    throw new Error("Key import failed: " + ex.message)
  }
}