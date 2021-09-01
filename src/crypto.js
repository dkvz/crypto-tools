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
 * @returns Object with "key" (ArrayBuffer) and "salt" (Uint8Array)
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

  // Append salt and IV.
  const fullBytes = new Uint8Array(ciphertext.length + salt.length + iv / length)
  fullBytes.set(salt);
  fullBytes.set(iv, salt.length);
  fullBytes.set(encryptedBytes, salt.length + iv.length);

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
    ciphertext
  )

  const dec = new TextDecoder();
  return dec.decode(decrypted)
}

/**
 * Adapted from here: https://gist.github.com/jonleighton/958841
 * Which is why the style is very different.
 * Apparently btoa is weird on the browser.
 * atob should be fine.
 * @param {Uint8Array} bytes 
 * @returns {string}
 */
function Uint8ArrayToBase64(bytes) {
  let base64 = ''
  let encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

  const byteLength = bytes.byteLength
  const byteRemainder = byteLength % 3
  const mainLength = byteLength - byteRemainder

  let a, b, c, d
  let chunk

  // Main loop deals with bytes in chunks of 3
  for (let i = 0; i < mainLength; i = i + 3) {
    // Combine the three bytes into a single integer
    chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

    // Use bitmasks to extract 6-bit segments from the triplet
    a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
    b = (chunk & 258048) >> 12 // 258048   = (2^6 - 1) << 12
    c = (chunk & 4032) >> 6 // 4032     = (2^6 - 1) << 6
    d = chunk & 63               // 63       = 2^6 - 1

    // Convert the raw binary segments to the appropriate ASCII encoding
    base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
  }

  // Deal with the remaining bytes and padding
  if (byteRemainder == 1) {
    chunk = bytes[mainLength]

    a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

    // Set the 4 least significant bits to zero
    b = (chunk & 3) << 4 // 3   = 2^2 - 1

    base64 += encodings[a] + encodings[b] + '=='
  } else if (byteRemainder == 2) {
    chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

    a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
    b = (chunk & 1008) >> 4 // 1008  = (2^6 - 1) << 4

    // Set the 2 least significant bits to zero
    c = (chunk & 15) << 2 // 15    = 2^4 - 1

    base64 += encodings[a] + encodings[b] + encodings[c] + '='
  }

  return base64
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