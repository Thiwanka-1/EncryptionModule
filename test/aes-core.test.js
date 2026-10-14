'use strict';
// Checks aes-core.js against Node's OpenSSL-backed crypto and against published
// test vectors. Run with: node test/aes-core.test.js
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const A = require('../aes-core.js');

let passed = 0;
async function check(name, fn) {
  try { await fn(); passed++; }
  catch (e) { console.error('FAIL ' + name + ': ' + (e && e.message)); process.exitCode = 1; }
}
const hex = A.hexEncode;
const rnd = (n) => new Uint8Array(crypto.randomBytes(n));

function nodeRun(op, mode, key, iv, data, autoPad) {
  const name = 'aes-' + key.length * 8 + '-' + mode.toLowerCase();
  const ivArg = mode === 'ECB' ? null : iv;
  const c = op === 'encrypt' ? crypto.createCipheriv(name, key, ivArg) : crypto.createDecipheriv(name, key, ivArg);
  if (mode === 'GCM') {
    if (op === 'decrypt') { c.setAuthTag(data.subarray(data.length - 16)); data = data.subarray(0, data.length - 16); }
  } else {
    c.setAutoPadding(autoPad);
  }
  let out = Buffer.concat([c.update(data), c.final()]);
  if (mode === 'GCM' && op === 'encrypt') out = Buffer.concat([out, c.getAuthTag()]);
  return new Uint8Array(out);
}

(async () => {
  await check('FIPS-197 C.1 AES-128 ECB vector', async () => {
    const ct = await A.encrypt({ plaintext: A.hexDecode('00112233445566778899aabbccddeeff'), key: A.hexDecode('000102030405060708090a0b0c0d0e0f'), mode: 'ECB', padding: 'NoPadding' });
    assert.equal(hex(ct), '69c4e0d86a7b0430d8cdb78070b4c55a');
  });
  await check('FIPS-197 C.3 AES-256 ECB vector', async () => {
    const ct = await A.encrypt({ plaintext: A.hexDecode('00112233445566778899aabbccddeeff'), key: A.hexDecode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), mode: 'ECB', padding: 'NoPadding' });
    assert.equal(hex(ct), '8ea2b7ca516745bfeafc49904b496089');
  });
  await check('GCM spec test case 2', async () => {
    const ct = await A.encrypt({ plaintext: new Uint8Array(16), key: new Uint8Array(16), iv: new Uint8Array(12), mode: 'GCM' });
    assert.equal(hex(ct), '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf');
  });

  const lengths = [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000];
  for (const mode of A.MODES) for (const bits of A.KEY_SIZES) for (const len of lengths) {
    const key = rnd(bits / 8);
    const iv = mode === 'ECB' ? null : rnd(A.ivBytes(mode));
    const pt = rnd(len);
    const stream = A.isStream(mode);
    const paddings = mode === 'GCM' ? ['NoPadding']
      : stream ? ['NoPadding', 'PKCS5Padding']
      : (len % 16 === 0 ? ['PKCS5Padding', 'NoPadding'] : ['PKCS5Padding']);
    for (const padding of paddings) {
      await check(mode + '/' + padding + '/' + bits + '/' + len + ' bytes', async () => {
        const ours = await A.encrypt({ plaintext: pt, key, iv, mode, padding });
        if (!(stream && padding === 'PKCS5Padding')) { // OpenSSL never pads stream modes
          const theirs = nodeRun('encrypt', mode, key, iv, pt, padding === 'PKCS5Padding');
          assert.equal(hex(ours), hex(theirs), 'ciphertext differs from OpenSSL');
          assert.equal(hex(await A.decrypt({ ciphertext: theirs, key, iv, mode, padding })), hex(pt), 'cannot decrypt OpenSSL output');
          assert.equal(hex(nodeRun('decrypt', mode, key, iv, ours, padding === 'PKCS5Padding')), hex(pt), 'OpenSSL cannot decrypt our output');
        }
        assert.equal(hex(await A.decrypt({ ciphertext: ours, key, iv, mode, padding })), hex(pt), 'round trip failed');
      });
    }
  }

  for (const padding of ['ZeroPadding', 'ISO10126Padding', 'X923Padding']) for (const len of [1, 15, 16, 17, 100]) {
    await check('CBC/' + padding + '/' + len + ' round trip', async () => {
      const key = rnd(16), iv = rnd(16), pt = rnd(len);
      if (padding === 'ZeroPadding') pt[len - 1] |= 1; // zero padding cannot preserve trailing zero bytes
      const ct = await A.encrypt({ plaintext: pt, key, iv, mode: 'CBC', padding });
      assert.equal(ct.length % 16, 0);
      assert.equal(hex(await A.decrypt({ ciphertext: ct, key, iv, mode: 'CBC', padding })), hex(pt));
    });
  }
  await check('padding layouts', () => {
    assert.equal(hex(A.pad(A.hexDecode('aabb'), 'PKCS5Padding')), 'aabb0e0e0e0e0e0e0e0e0e0e0e0e0e0e');
    assert.equal(hex(A.pad(A.hexDecode('aabb'), 'X923Padding')), 'aabb000000000000000000000000000e');
    assert.equal(hex(A.pad(A.hexDecode('aabb'), 'ZeroPadding')), 'aabb0000000000000000000000000000');
    const iso = A.pad(A.hexDecode('aabb'), 'ISO10126Padding');
    assert.equal(iso.length, 16); assert.equal(iso[15], 14);
    assert.equal(hex(A.pad(new Uint8Array(16), 'PKCS5Padding')), '00'.repeat(16) + '10'.repeat(16));
    assert.throws(() => A.unpad(A.hexDecode('aabb0e0e0e0e0e0e0e0e0e0e0e0e0e0d'), 'PKCS5Padding'), /Padding check failed/);
    assert.throws(() => A.unpad(A.hexDecode('aabb0e0e0e0e0e0e0e0e0e0e0e0e0e00'), 'PKCS5Padding'), /Padding check failed/);
  });

  await check('wrong key is reported (CBC/PKCS5)', async () => {
    const key = A.utf8Encode('0123456789abcdef'), wrong = A.utf8Encode('0123456789abcdeg'), iv = new Uint8Array(16);
    const ct = await A.encrypt({ plaintext: A.utf8Encode('hello world'), key, iv, mode: 'CBC', padding: 'PKCS5Padding' });
    await assert.rejects(A.decrypt({ ciphertext: ct, key: wrong, iv, mode: 'CBC', padding: 'PKCS5Padding' }), /Padding check failed/);
  });
  await check('wrong key is reported (GCM)', async () => {
    const key = rnd(32), iv = rnd(12);
    const ct = await A.encrypt({ plaintext: A.utf8Encode('hello world'), key, iv, mode: 'GCM' });
    await assert.rejects(A.decrypt({ ciphertext: ct, key: rnd(32), iv, mode: 'GCM' }), /authentication failed/);
    ct[3] ^= 1;
    await assert.rejects(A.decrypt({ ciphertext: ct, key, iv, mode: 'GCM' }), /authentication failed/);
  });
  await check('key length validation', () => assert.rejects(A.encrypt({ plaintext: rnd(5), key: rnd(10), iv: rnd(16), mode: 'CBC', padding: 'PKCS5Padding' }), /16, 24 or 32/));
  await check('IV length validation', () => assert.rejects(A.encrypt({ plaintext: rnd(5), key: rnd(16), iv: rnd(12), mode: 'CBC', padding: 'PKCS5Padding' }), /needs exactly 16/));
  await check('NoPadding alignment', () => assert.rejects(A.encrypt({ plaintext: rnd(5), key: rnd(16), iv: rnd(16), mode: 'CBC', padding: 'NoPadding' }), /whole number of 16-byte blocks/));
  await check('ciphertext alignment', () => assert.rejects(A.decrypt({ ciphertext: rnd(20), key: rnd(16), iv: rnd(16), mode: 'CBC', padding: 'PKCS5Padding' }), /not a whole number/));

  await check('base64', () => {
    const b = rnd(50);
    assert.equal(A.b64Encode(b), Buffer.from(b).toString('base64'));
    assert.equal(hex(A.b64Decode(A.b64Encode(b))), hex(b));
    const urlSafe = A.b64Encode(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    assert.equal(hex(A.b64Decode(' ' + urlSafe + '\n')), hex(b));
    assert.throws(() => A.b64Decode('abc$'), /not valid Base64/);
    assert.throws(() => A.b64Decode('abcde'), /cut short/);
  });
  await check('hex', () => {
    const b = rnd(33);
    assert.equal(hex(A.hexDecode(hex(b).toUpperCase())), hex(b));
    assert.equal(hex(A.hexDecode('0x' + hex(b))), hex(b));
    assert.equal(hex(A.hexDecode('aa:bb cc')), 'aabbcc');
    assert.throws(() => A.hexDecode('abc'), /odd number/);
    assert.throws(() => A.hexDecode('zz'), /not valid Hex/);
  });
  await check('utf8', () => {
    assert.equal(A.utf8Decode(A.utf8Encode('héllo wörld, සිංහල')), 'héllo wörld, සිංහල');
    assert.equal(A.isValidUtf8(new Uint8Array([0xff, 0xfe])), false);
    assert.throws(() => A.utf8Decode(new Uint8Array([0xff])), /not valid UTF-8/);
  });
  await check('generate', () => {
    assert.match(A.generate(16, 'text'), /^[A-Za-z0-9]{16}$/);
    assert.equal(A.utf8Encode(A.generate(24, 'text')).length, 24);
    assert.equal(A.hexDecode(A.generate(32, 'hex')).length, 32);
    assert.equal(A.b64Decode(A.generate(24, 'base64')).length, 24);
    assert.notEqual(A.generate(16, 'hex'), A.generate(16, 'hex'));
  });
  await check('transformation names', () => {
    assert.equal(A.transformation('CBC', 'PKCS5Padding'), 'AES/CBC/PKCS5Padding');
    assert.equal(A.transformation('GCM', 'PKCS5Padding'), 'AES/GCM/NoPadding');
  });

  console.log(passed + ' checks passed' + (process.exitCode ? ', some FAILED' : ''));
})();
