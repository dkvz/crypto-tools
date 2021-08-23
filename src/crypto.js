export async function deriveKey(passphrase) {
  // Need to convert the string to byte array.
  // When you're a normal person you use TextEncoder.
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw", //only "raw" is allowed
    enc.encode(key), //your password
    { name: "PBKDF2" },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
  )

  //returns a key object
  console.log('Imported key: ', key);

  // I used to create a Uint8Array from the ArrayBuffer:
  // console.log(new Uint8Array(byteBuffer));

  const byteBuffer = await crypto.subtle.deriveBits(
    {
      "name": "PBKDF2",
      salt: window.crypto.getRandomValues(new Uint8Array(16)),
      iterations: 10000,
      hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    key, //your key from generateKey or importKey
    256 //the number of bits you want to derive
  )

  return byteBuffer
}