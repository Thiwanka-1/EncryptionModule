// Template for a default key and IV. To use it on your own computer:
//   1. Copy this file to defaults.local.js (same folder as index.html).
//   2. Replace the placeholder values below with your key and IV.
// index.html reads defaults.local.js on every load and fills both benches.
// defaults.local.js is ignored by git, so the key is never committed or published.
window.AES_WORKBENCH_DEFAULTS = {
  key: 'REPLACE-WITH-KEY',   // 16, 24 or 32 bytes once decoded
  keyFormat: 'text',         // 'text', 'base64' or 'hex'
  iv: 'REPLACE-WITH-IV',     // 16 bytes once decoded (12 is usual for GCM)
  ivFormat: 'text'           // 'text', 'base64' or 'hex'
};
