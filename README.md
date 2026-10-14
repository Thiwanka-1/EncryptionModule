# AES Workbench

A single-page AES encrypt / decrypt tool that runs entirely in the browser. No server, no ads, no network calls: keys and text never leave the machine.

## Use it

Open `index.html` in any modern browser (double-click it, or drag it onto a browser window). That is all.

- Modes: ECB, CBC, CFB, OFB, CTR, GCM
- Padding: PKCS5Padding (PKCS#7), NoPadding, ZeroPadding, ISO10126Padding, X923Padding
- Key sizes: 128, 192, 256 bits
- Key and IV can be typed as plain text, Base64 or Hex; ciphertext as Base64 or Hex
- Generate buttons produce random keys and IVs in the selected format
- "Send to Decrypt" copies a result and its settings across for a round-trip check
- Ctrl+Enter in any text box runs that bench

The badge on each bench shows the equivalent Java `Cipher` transformation (for example `AES/CBC/PKCS5Padding`). Output is byte-for-byte compatible with Java, OpenSSL and the devglan online tool when the same raw key, IV and settings are used. An empty IV means all zero bytes, which is what most libraries assume. GCM appends its 16-byte authentication tag to the ciphertext, the same layout Java and OpenSSL use.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | The page: layout, styling and the form logic |
| `aes-core.js` | Encodings, padding and the cipher modes. No DOM code, so it can be tested in Node |
| `vendor/crypto-js.min.js` | CryptoJS 4.2.0, used for ECB, CBC, CFB, OFB and CTR. GCM uses the browser's Web Crypto API |
| `test/aes-core.test.js` | Checks every mode, key size and padding against Node's OpenSSL and against FIPS-197 / GCM test vectors |

## Run the tests

```
node test/aes-core.test.js
```

Needs Node 18 or newer. Prints the number of checks passed and exits non-zero on any failure.

## Notes

- Chrome and Edge do not support 192-bit keys in GCM mode (a Web Crypto limitation). The page explains this when it happens; every other mode works with 192-bit keys.
- If `vendor/crypto-js.min.js` is missing, the page loads the same version from cdnjs, so the single `index.html` still works online.
- Mode, padding, key size and format choices are remembered in the browser's local storage. Keys, IVs and text are never stored.
