# Crypto-Tools
Currently deployed here (but anybody could deploy it, I'm not going to sue (I think)): https://tools.dkvz.eu/crypto

Client-side JavaScript crypto tools, mostly something to encode text in AES.

To run the project dev server:
```
npm install
npm start
```

Making a production build in "dist":
```
npm run build
```

## Resources
- Got a pen with a complete key derivation: https://codepen.io/dkvz/pen/MMdbey

### Importing a certificate
- I'll have to try the example here: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#examples

# TODO
- [x] Try encrypting 16 bytes unicode characters and see if decryption works. I'm doubting my base64 decode.
