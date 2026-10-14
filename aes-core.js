/*
 * AES Workbench core: encodings, padding and the AES modes. No DOM code here.
 *
 * Loads in the browser as window.AESCore (CryptoJS must be loaded first) and in
 * Node as a CommonJS module, which is how test/aes-core.test.js checks it
 * against Node's own OpenSSL-backed crypto.
 *
 * ECB, CBC, CFB, OFB and CTR run on CryptoJS, always with NoPadding: padding is
 * added and checked here so a wrong key reports "padding check failed" instead
 * of silently returning garbage. GCM runs on the Web Crypto API, which CryptoJS
 * does not provide. Layouts match Java's Cipher ("AES/CBC/PKCS5Padding") and
 * OpenSSL: raw key bytes, raw IV bytes, and for GCM the 16-byte tag appended
 * to the ciphertext.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./vendor/crypto-js.min.js'));
  } else {
    root.AESCore = factory(root.CryptoJS);
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (CryptoJS) {
  'use strict';

  const BLOCK = 16;
  const GCM_IV_BYTES = 12;
  const MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM'];
  const STREAM_MODES = ['CFB', 'OFB', 'CTR', 'GCM'];
  const PADDINGS = ['PKCS5Padding', 'NoPadding', 'ZeroPadding', 'ISO10126Padding', 'X923Padding'];
  const KEY_SIZES = [128, 192, 256];
  const FORMATS = ['text', 'base64', 'hex'];

  const isStream = (mode) => STREAM_MODES.includes(mode);
  const usesIV = (mode) => mode !== 'ECB';
  const ivBytes = (mode) => (mode === 'GCM' ? GCM_IV_BYTES : BLOCK);

  // ---- encodings -----------------------------------------------------------
  const encoder = new TextEncoder();
  const strictDecoder = new TextDecoder('utf-8', { fatal: true });

  function utf8Encode(str) { return encoder.encode(String(str)); }
  function utf8Decode(bytes) {
    try { return strictDecoder.decode(bytes); }
    catch (e) { throw new Error('The bytes are not valid UTF-8 text.'); }
  }
  function isValidUtf8(bytes) {
    try { strictDecoder.decode(bytes); return true; } catch (e) { return false; }
  }

  const HEX = '0123456789abcdef';
  function hexEncode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
    return s;
  }
  function hexDecode(str) {
    const s = String(str).replace(/\s+/g, '').replace(/^0x/i, '').replace(/[:-]/g, '');
    if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error('That is not valid Hex. Only the characters 0-9 and A-F are allowed.');
    if (s.length % 2) throw new Error('Hex input has an odd number of characters (' + s.length + '); every byte needs two.');
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  function b64Encode(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }
  function b64Decode(str) {
    let s = String(str).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('That is not valid Base64. Allowed characters are A-Z, a-z, 0-9, + and /.');
    s = s.replace(/=+$/, '');
    if (s.length % 4 === 1) throw new Error('Base64 input is cut short: a length of ' + s.length + ' characters cannot be right.');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function decode(str, format) {
    if (format === 'text') return utf8Encode(str);
    if (format === 'base64') return b64Decode(str);
    if (format === 'hex') return hexDecode(str);
    throw new Error('Unknown format: ' + format);
  }
  function encode(bytes, format) {
    if (format === 'text') return utf8Decode(bytes);
    if (format === 'base64') return b64Encode(bytes);
    if (format === 'hex') return hexEncode(bytes);
    throw new Error('Unknown format: ' + format);
  }

  // ---- random --------------------------------------------------------------
  function randomBytes(n) {
    const out = new Uint8Array(n);
    globalThis.crypto.getRandomValues(out);
    return out;
  }
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  function randomText(n) {
    // One ASCII character per byte, drawn without modulo bias (62 * 4 = 248).
    let s = '';
    while (s.length < n) {
      const buf = randomBytes(n - s.length + 8);
      for (let i = 0; i < buf.length && s.length < n; i++) if (buf[i] < 248) s += ALPHABET[buf[i] % 62];
    }
    return s;
  }
  function generate(nBytes, format) {
    return format === 'text' ? randomText(nBytes) : encode(randomBytes(nBytes), format);
  }

  // ---- padding -------------------------------------------------------------
  function badPadding() {
    return new Error('Padding check failed. The key, IV, mode or padding is not what was used to encrypt.');
  }
  function pad(bytes, scheme) {
    if (scheme === 'NoPadding') return bytes;
    const n = BLOCK - (bytes.length % BLOCK); // 1..16
    if (scheme === 'ZeroPadding' && n === BLOCK) return bytes;
    const out = new Uint8Array(bytes.length + n);
    out.set(bytes);
    switch (scheme) {
      case 'ZeroPadding': break;
      case 'PKCS5Padding': out.fill(n, bytes.length); break;
      case 'ISO10126Padding': out.set(randomBytes(n - 1), bytes.length); out[out.length - 1] = n; break;
      case 'X923Padding': out[out.length - 1] = n; break;
      default: throw new Error('Unknown padding: ' + scheme);
    }
    return out;
  }
  function unpad(bytes, scheme) {
    if (scheme === 'NoPadding') return bytes;
    if (scheme === 'ZeroPadding') {
      let end = bytes.length;
      while (end > 0 && bytes[end - 1] === 0) end--;
      return bytes.subarray(0, end);
    }
    if (!PADDINGS.includes(scheme)) throw new Error('Unknown padding: ' + scheme);
    if (bytes.length === 0 || bytes.length % BLOCK !== 0) throw badPadding();
    const n = bytes[bytes.length - 1];
    if (n < 1 || n > BLOCK) throw badPadding();
    if (scheme === 'PKCS5Padding') {
      for (let i = bytes.length - n; i < bytes.length; i++) if (bytes[i] !== n) throw badPadding();
    } else if (scheme === 'X923Padding') {
      for (let i = bytes.length - n; i < bytes.length - 1; i++) if (bytes[i] !== 0) throw badPadding();
    }
    // ISO10126: the filler bytes are random, only the count byte is checked.
    return bytes.subarray(0, bytes.length - n);
  }

  // ---- CryptoJS bridge -----------------------------------------------------
  function toWords(bytes) {
    const words = new Array((bytes.length + 3) >>> 2).fill(0);
    for (let i = 0; i < bytes.length; i++) words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
    return CryptoJS.lib.WordArray.create(words, bytes.length);
  }
  function fromWords(wa) {
    const out = new Uint8Array(wa.sigBytes);
    for (let i = 0; i < wa.sigBytes; i++) out[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    return out;
  }
  function runCryptoJS(op, mode, key, iv, data) {
    const cfg = { mode: CryptoJS.mode[mode], padding: CryptoJS.pad.NoPadding };
    if (mode !== 'ECB') cfg.iv = toWords(iv);
    const k = toWords(key);
    if (op === 'encrypt') return fromWords(CryptoJS.AES.encrypt(toWords(data), k, cfg).ciphertext);
    const params = CryptoJS.lib.CipherParams.create({ ciphertext: toWords(data) });
    return fromWords(CryptoJS.AES.decrypt(params, k, cfg));
  }

  // ---- GCM via Web Crypto --------------------------------------------------
  async function runGCM(op, key, iv, data) {
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) {
      throw new Error('GCM needs the Web Crypto API, which this browser only exposes on https:// pages and local files. The other modes still work.');
    }
    let cryptoKey;
    try {
      cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [op]);
    } catch (e) {
      if (key.length === 24) throw new Error('This browser cannot use 192-bit keys in GCM mode (Chrome and Edge do not support them). Use a 128-bit or 256-bit key, or another mode.');
      throw e;
    }
    try {
      return new Uint8Array(await subtle[op]({ name: 'AES-GCM', iv: iv, tagLength: 128 }, cryptoKey, data));
    } catch (e) {
      if (op === 'decrypt') throw new Error('GCM authentication failed: the key, IV or ciphertext is not what was used to encrypt, or the 16-byte tag at the end is missing.');
      throw e;
    }
  }

  // ---- validation ----------------------------------------------------------
  function checkMode(mode) {
    if (!MODES.includes(mode)) throw new Error('Unknown cipher mode: ' + mode);
  }
  function checkKey(key) {
    if (!(key instanceof Uint8Array) || !KEY_SIZES.includes(key.length * 8)) {
      throw new Error('Key is ' + (key ? key.length : 0) + ' bytes. AES needs exactly 16, 24 or 32 bytes (128, 192 or 256 bits).');
    }
  }
  function checkIV(iv, mode) {
    if (mode === 'ECB') return;
    if (mode === 'GCM') {
      if (iv.length < 1) throw new Error('GCM needs an IV (nonce); 12 bytes is the standard length.');
      return;
    }
    if (iv.length !== BLOCK) throw new Error('IV is ' + iv.length + ' bytes. ' + mode + ' mode needs exactly 16.');
  }

  // ---- public API ----------------------------------------------------------
  async function encrypt(opts) {
    const mode = opts.mode, padding = opts.padding || 'NoPadding';
    const plaintext = opts.plaintext, key = opts.key, iv = opts.iv || new Uint8Array(0);
    checkMode(mode); checkKey(key); checkIV(iv, mode);
    if (mode === 'GCM') return runGCM('encrypt', key, iv, plaintext);
    const padded = pad(plaintext, padding);
    if (!isStream(mode) && padded.length % BLOCK) {
      throw new Error('With NoPadding the text must be a whole number of 16-byte blocks. It is ' + plaintext.length + ' bytes; ' + (BLOCK - plaintext.length % BLOCK) + ' more would complete the last block. Pick PKCS5Padding to let the tool pad it.');
    }
    return runCryptoJS('encrypt', mode, key, iv, padded);
  }

  async function decrypt(opts) {
    const mode = opts.mode, padding = opts.padding || 'NoPadding';
    const ciphertext = opts.ciphertext, key = opts.key, iv = opts.iv || new Uint8Array(0);
    checkMode(mode); checkKey(key); checkIV(iv, mode);
    if (mode === 'GCM') return runGCM('decrypt', key, iv, ciphertext);
    if (!isStream(mode) && ciphertext.length % BLOCK) {
      throw new Error('Ciphertext is ' + ciphertext.length + ' bytes, not a whole number of 16-byte blocks. Check the input format (Base64 or Hex) and that nothing was cut off.');
    }
    return unpad(runCryptoJS('decrypt', mode, key, iv, ciphertext), padding);
  }

  function transformation(mode, padding) {
    return 'AES/' + mode + '/' + (mode === 'GCM' ? 'NoPadding' : padding);
  }

  return {
    BLOCK, GCM_IV_BYTES, MODES, STREAM_MODES, PADDINGS, KEY_SIZES, FORMATS,
    isStream, usesIV, ivBytes,
    utf8Encode, utf8Decode, isValidUtf8, hexEncode, hexDecode, b64Encode, b64Decode, decode, encode,
    randomBytes, generate, pad, unpad, encrypt, decrypt, transformation
  };
}));
