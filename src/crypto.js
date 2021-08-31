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
 * @returns Object with "key" (ArrayBuffer) and "salt" (Uint8Array)
 */
export async function deriveKey(passphrase) {
  // Need to convert the string to byte array.
  // When you're a normal person you use TextEncoder.
  const enc = new TextEncoder()

  const key = await crypto.subtle.importKey(
    "raw", //only "raw" is allowed
    enc.encode(key), //your password
    { name: "PBKDF2" },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
  )

  const salt = window.crypto.getRandomValues(new Uint8Array(saltLength))

  const byteBuffer = await crypto.subtle.deriveBits(
    {
      "name": "PBKDF2",
      salt: salt,
      iterations: pbkdf2Iterations,
      hash: { name: "SHA-512" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    key, //your key from generateKey or importKey
    256 //the number of bits you want to derive
  )

  return {
    key: byteBuffer,
    salt
  }
}

/**
 * Perform the encryption
 * @param {string} text 
 * @param {ArrayBuffer} key 
 * @param {Uint8Array} salt 
 * @returns {Uint8Array} the full ciphertext, including iv and salt (in that order) appended to it
 */
export async function encrypt(text, key, salt) {
  const enc = new TextEncoder()

  // Generate an IV. We'll put it right before the encrypted 
  // message.
  const iv = window.crypto.getRandomValues(new Uint8Array(ivLength))

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    enc.encode(text)
  )

  // Append salt and IV.
  const fullBytes = new Uint8Array(ciphertext.length + salt.length + iv / length)
  fullBytes.set(salt);
  fullBytes.set(iv, salt.length);
  fullBytes.set(encryptedBytes, salt.length + iv.length);

  return fullBytes
}