#!/usr/bin/env node
// generate-hash.js
// Run locally to create the SHA-256 password hash for your env vars
// Usage: node generate-hash.js <password>

const password = process.argv[2];

if (!password) {
  console.error('Usage: node generate-hash.js <password>');
  process.exit(1);
}

const { createHash, randomBytes } = require('crypto');

const salt = randomBytes(16).toString('hex');
const hash = createHash('sha256').update(salt + password).digest('hex');
const result = `sha256:${salt}:${hash}`;

console.log('\n✅ Password hash generated:\n');
console.log(`AUTH_PASSWORD_HASH=${result}`);
console.log('\nAdd this to your Cloudflare Pages environment variables.');
console.log('Keep this secret — never commit it to git!\n');
