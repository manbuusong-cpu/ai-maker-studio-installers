'use strict';
// Generic repair of one immutable private artifact. Never print archived source.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const exec = promisify(execFile);
const REPOSITORY = 'manbuusong-cpu/ai-maker-studio-installers';
const API = `https://api.github.com/repos/${REPOSITORY}`;
const VERSION = '0.3.1-dev.2';
const ARTIFACT = `AI-Maker-Studio-Setup-${VERSION}-Windows-x64-UNSIGNED.exe`;
const ORIGINAL = Object.freeze({ assetId: 782615221, bytes: 137767835, sha256: '4c93d4032860f6ee0b55a76715761c48605527e95b55ecd5730edd5fe8cf9fa6', asarSha256: 'ef37a88dce5beb45f57aea7ea1c35c76c361ee218efc096103f32dc1ab848c36' });
const POLICY = 'apps/desktop/electron/updates/trust-policy.cjs';
const POLICY_HASH = '57f3d8e9696eb7c2e5ea96f6385935477a3ee8673148b6779e8ec0266f6ced22';
const NSIS_GUARD_SHA256 = '675c7ee772d6bf690f476b2001dd09c8e0aecdf6554711cc603ac65ccdfd9940';
const PATCHES = Object.freeze({
  'apps/desktop/electron/security/renderer-policy.cjs': ['46d1e131a713cd72837dab276ca8ffdc968c0a8796c8f33c185d1235c4ac1394', '1d90ea6a0163e87bfb473107e7c21f7e24585218f95505df65cfc1f3f7e80b29'],
  'package.json': ['b1791b16b1f68acd25cc35f90f9a6b8132afc9658afffb2a5ea3b47ccbec45c4', 'f74fcf2f499e7f367854a4898e382fca78c49e16f3991387b7d6dc6a98c0063f'],
  'apps/desktop/dist/assets/index-BYKYZYmK.js': ['8aa22fac18b080cdcfad0fb4a9d9b8880b6e6ad6a32750bd16025f2c65137c68', 'b2dc1dc7ebda60315611b20b8748af9185577efdf23079950a45735d18a1e90a'],
});
function fail(code) { throw new Error(code); }
function sha(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
let lastStage = 'NOT_STARTED';
function stage(name) { lastStage = name; console.log(JSON.stringify({ stage: name })); }
function failureDiagnostic(error, phase = lastStage) {
  return {
    lastStage: phase,
    reason: typeof error?.message === 'string' && /^[A-Z0-9_]{3,100}$/.test(error.message) ? error.message : 'DETAILS_WITHHELD',
    code: typeof error?.code === 'string' && /^[A-Z0-9_]{1,50}$/.test(error.code) ? error.code : null,
    syscall: typeof error?.syscall === 'string' ? (error.syscall.match(/^[a-zA-Z][a-zA-Z0-9_-]{0,39}/)?.[0] || null) : null,
    exitCode: Number.isInteger(error?.code) ? error.code : Number.isInteger(error?.exitCode) ? error.exitCode : null,
    errno: Number.isInteger(error?.errno) ? error.errno : null,
    signal: typeof error?.signal === 'string' && /^[A-Z0-9_]{1,30}$/.test(error.signal) ? error.signal : null,
  };
}
function selectPayloadMember(listing) {
  if (typeof listing !== 'string' || listing.length > 1024 * 1024) fail('NSIS_MEMBER_LIST_INVALID');
  const members = [...listing.matchAll(/^Path = ([^\r\n]+)\r?$/gm)].map(match => match[1])
    .filter(name => name.replace(/\\/g, '/') === '$PLUGINSDIR/app-64.7z');
  if (members.length !== 1) fail('UNIQUE_NSIS_PAYLOAD_MEMBER_REQUIRED');
  // Feed 7-Zip its own platform-specific spelling; member selectors are separator-sensitive.
  return members[0];
}
function replaceOnce(text, before, after) {
  const offset = text.indexOf(before);
  if (offset < 0 || text.indexOf(before, offset + before.length) !== -1) fail('PATCH_OCCURRENCE_MISMATCH');
  return text.slice(0, offset) + after + text.slice(offset + before.length);
}
function patchArchivedFile(name, bytes) {
  if (!Object.hasOwn(PATCHES, name) || sha(bytes) !== PATCHES[name][0]) fail('PATCH_INPUT_HASH_MISMATCH');
  let text = bytes.toString('utf8');
  if (name.endsWith('renderer-policy.cjs')) {
    // Only this generic compatibility insertion is public; original source stays private.
    const insertion = '// Electron presents an ASAR as a virtual directory through patched node:fs.\n' +
      '// Inspect the physical outer archive with the unpatched main-process API;\n' +
      '// retain the same regular-file, canonical-path and link checks.\n' +
      "const archiveIO = process.versions.electron ? require('original-fs').promises : require('node:fs/promises');\n";
    text = replaceOnce(text, 'async function isAllowedRendererRequest', insertion + 'async function isAllowedRendererRequest');
    text = replaceOnce(text, "assertSafePath(archiveRoot, { kind: 'file' })", "assertSafePath(archiveRoot, { kind: 'file', io: archiveIO })");
  } else if (name === 'package.json') {
    const metadata = JSON.parse(text);
    if (metadata.name !== 'ai-maker-studio' || metadata.version !== '0.3.1-dev.1') fail('PACKAGE_IDENTITY_MISMATCH');
    metadata.version = VERSION;
    text = JSON.stringify(metadata, null, 2);
  } else text = replaceOnce(text, '`0.3.1-dev.1`', '`0.3.1-dev.2`');
  const result = Buffer.from(text);
  if (sha(result) !== PATCHES[name][1]) fail('PATCH_OUTPUT_HASH_MISMATCH');
  return result;
}
function childEnvironment(env) {
  return Object.fromEntries(Object.entries(env).filter(([name]) => !/^(?:GH|GITHUB|.*CSC|NODE_OPTIONS$|NODE_PATH$|NODE_DEBUG$|NODE_TLS_REJECT_UNAUTHORIZED$|DEBUG$|ELECTRON_BUILDER_DEBUG$|ELECTRON_RUN_AS_NODE$|__COMPAT_LAYER$|ACTIONS_.*TOKEN)/i.test(name)));
}
function requireEnvironment(mode, env = process.env, platform = process.platform) {
  if (platform !== 'win32' || env.GITHUB_ACTIONS !== 'true' || env.GITHUB_REPOSITORY !== REPOSITORY || env.AI_MAKER_PRIVATE_REBUILD_APPROVED !== '1' || !env.RUNNER_TEMP || !env.GH_TOKEN) fail('AUTHORIZED_DISPOSABLE_WINDOWS_CI_REQUIRED');
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0') fail('TLS_VALIDATION_REQUIRED');
  if (mode === 'publish' && env.AI_MAKER_PRIVATE_DRAFT_PUBLISH_APPROVED !== '1') fail('EXPLICIT_PRIVATE_DRAFT_APPROVAL_REQUIRED');
}
async function safePath(filename, root, directory = false) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) fail('LOCAL_PATH_REQUIRED');
  const resolved = path.resolve(filename), relative = path.relative(root, resolved);
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) fail('RUNNER_TEMP_CONFINEMENT_REQUIRED');
  let current = path.parse(resolved).root;
  const parts = path.relative(current, resolved).split(path.sep);
  for (let index = 0; index < parts.length; index++) {
    current = path.join(current, parts[index]);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1) || (index < parts.length - 1 ? !stat.isDirectory() : directory ? !stat.isDirectory() : !stat.isFile())) fail('NONREGULAR_PATH_REJECTED');
    if ((await fs.realpath(current)).toLowerCase() !== current.toLowerCase()) fail('REDIRECTED_PATH_REJECTED');
  }
  return resolved;
}
async function hashFile(filename) { return sha(await fs.readFile(filename)); }
async function writeJSON(filename, value) { await fs.writeFile(filename, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' }); }
async function smallJSON(filename, root) {
  await safePath(filename, root);
  if ((await fs.stat(filename)).size > 1024 * 1024) fail('REPORT_TOO_LARGE');
  return JSON.parse((await fs.readFile(filename, 'utf8')).replace(/^\uFEFF/, ''));
}
function github(token) {
  async function request(url, options = {}, download = false) {
    const cancel = new AbortController(), timer = setTimeout(() => cancel.abort(), 180000);
    try {
      const result = await fetch(url, { ...options, redirect: 'manual', signal: cancel.signal,
        headers: { Authorization: `Bearer ${token}`, Accept: download ? 'application/octet-stream' : 'application/vnd.github+json', ...options.headers } });
      if (download && result.status === 302) {
        const next = new URL(result.headers.get('location'));
        if (next.protocol !== 'https:' || next.username || next.password || !next.hostname.endsWith('.githubusercontent.com')) fail('ASSET_DOWNLOAD_REDIRECT_REJECTED');
        return await fetch(next, { redirect: 'error', signal: cancel.signal });
      }
      if (!result.ok) fail('GITHUB_REQUEST_FAILED_' + result.status);
      return result;
    } finally { clearTimeout(timer); }
  }
  return { request, async json(url, options) {
    const result = await request(url, options);
    const reader = result.body.getReader(), chunks = [];
    let length = 0;
    const timer = setTimeout(() => { void reader.cancel().catch(() => {}); }, 30000);
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        length += next.value.length;
        if (length > 1024 * 1024) fail('GITHUB_RESPONSE_TOO_LARGE');
        chunks.push(Buffer.from(next.value));
      }
    } finally { clearTimeout(timer); await reader.cancel().catch(() => {}); }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } };
}
async function downloadOriginal(client, filename) {
  const result = await client.request(`${API}/releases/assets/${ORIGINAL.assetId}`, {}, true);
  if (!result.ok || !result.body) fail('ORIGINAL_ASSET_UNAVAILABLE');
  const file = await fs.open(filename, 'wx'), hash = crypto.createHash('sha256');
  let bytes = 0;
  const cancel = new AbortController(), timer = setTimeout(() => cancel.abort(), 180000);
  const reader = result.body.getReader();
  const abort = () => { void reader.cancel().catch(() => {}); };
  cancel.signal.addEventListener('abort', abort, { once: true });
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      bytes += next.value.length;
      if (bytes > ORIGINAL.bytes) fail('ORIGINAL_ASSET_TOO_LARGE');
      hash.update(next.value);
      await file.write(next.value);
    }
  } finally { clearTimeout(timer); await reader.cancel().catch(() => {}); await file.close(); }
  if (bytes !== ORIGINAL.bytes || hash.digest('hex') !== ORIGINAL.sha256) fail('ORIGINAL_ASSET_INTEGRITY_MISMATCH');
}
function nativeArchivePath(name, flavor = path) { return flavor.normalize(name); }
function archiveLookup(asar, method, archive, name, ...args) {
  try { return asar[method](archive, nativeArchivePath(name), ...args); }
  catch { fail('ARCHIVE_LOOKUP_FAILED'); }
}
function archiveInventory(archive, asar) {
  const entries = [];
  for (const item of asar.listPackage(archive)) {
    const name = item.replace(/^[/\\]/, '').replace(/\\/g, '/');
    if (!name || name.split('/').some(part => !part || part === '.' || part === '..') || path.posix.isAbsolute(name) || name.includes(':')) fail('ARCHIVE_PATH_REJECTED');
    const stat = archiveLookup(asar, 'statFile', archive, name, false);
    if (stat.link) fail('ARCHIVE_LINK_REJECTED');
    if (!stat.files) {
      const bytes = archiveLookup(asar, 'extractFile', archive, name, false);
      const integrity = stat.integrity;
      if (!integrity || integrity.algorithm !== 'SHA256' || integrity.hash !== sha(bytes) || !Number.isSafeInteger(integrity.blockSize) || integrity.blockSize < 1) fail('ARCHIVE_FILE_INTEGRITY_MISMATCH');
      const blocks = [];
      for (let offset = 0; offset <= bytes.length; offset += integrity.blockSize) blocks.push(sha(bytes.subarray(offset, offset + integrity.blockSize)));
      if (JSON.stringify(blocks) !== JSON.stringify(integrity.blocks)) fail('ARCHIVE_BLOCK_INTEGRITY_MISMATCH');
      entries.push({ name, sha256: sha(bytes), unpacked: stat.unpacked === true });
    }
  }
  return entries.sort((a, b) => a.name.localeCompare(b.name));
}
function assertInventory(before, after) {
  if (before.length !== 3986 || after.length !== before.length || before.filter(item => item.unpacked).length !== 8) fail('ARCHIVE_FILE_COUNT_MISMATCH');
  for (let index = 0; index < before.length; index++) {
    const original = before[index], actual = after[index];
    if (original.name !== actual.name || original.unpacked !== actual.unpacked || actual.sha256 !== (PATCHES[original.name]?.[1] || original.sha256)) fail('UNEXPECTED_ARCHIVE_CHANGE');
  }
  if (after.find(item => item.name === POLICY)?.sha256 !== POLICY_HASH) fail('RUNTIME_UPDATE_POLICY_CHANGED');
}
async function treeHashes(root) {
  const result = {};
  async function visit(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name), stat = await fs.lstat(filename);
      if (stat.isSymbolicLink() || !(stat.isFile() || stat.isDirectory()) || (stat.isFile() && stat.nlink !== 1)) fail('PAYLOAD_LINK_OR_SPECIAL_FILE_REJECTED');
      if (stat.isDirectory()) await visit(filename);
      else result[path.relative(root, filename).replace(/\\/g, '/')] = await hashFile(filename);
    }
  }
  await visit(root); return result;
}
function assertCompanions(before, after) {
  const allowed = new Set(['AI Maker Studio.exe', 'resources/app.asar']);
  if (Object.keys(before).length !== Object.keys(after).length || Object.keys(before).some(name => !Object.hasOwn(after, name) || (!allowed.has(name) && before[name] !== after[name]))) fail('UNEXPECTED_COMPANION_CHANGE');
}
function assertUnsignedPE(bytes) {
  if (bytes.length < 64 || bytes.readUInt16LE(0) !== 0x5a4d) fail('PE_HEADER_INVALID');
  const pe = bytes.readUInt32LE(0x3c), optional = pe + 24;
  if (pe + 24 > bytes.length || bytes.readUInt32LE(pe) !== 0x4550) fail('PE_HEADER_INVALID');
  const magic = bytes.readUInt16LE(optional), directories = magic === 0x20b ? optional + 112 : magic === 0x10b ? optional + 96 : -1;
  if (directories < 0 || directories + 40 > bytes.length || bytes.readUInt32LE(directories + 32) !== 0 || bytes.readUInt32LE(directories + 36) !== 0) fail('UNSIGNED_DEVELOPMENT_PE_REQUIRED');
}
function peSnapshot(bytes, resedit) {
  assertUnsignedPE(bytes);
  const exe = resedit.NtExecutable.from(bytes), resources = resedit.NtExecutableResource.from(exe);
  const manifest = resources.entries.filter(item => item.type === 24).map(item => ({ id: item.id, lang: item.lang, hash: sha(Buffer.from(item.bin)) }));
  if (!manifest.length || !resources.entries.filter(item => item.type === 24).every(item => /requestedExecutionLevel[^>]*level="asInvoker"/.test(Buffer.from(item.bin).toString('utf8')))) fail('ASINVOKER_MANIFEST_REQUIRED');
  const sentinel = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'), offset = bytes.indexOf(sentinel);
  if (offset < 0 || offset !== bytes.lastIndexOf(sentinel)) fail('UNIQUE_FUSE_WIRE_REQUIRED');
  const start = offset + sentinel.length, length = bytes[start + 1];
  if (bytes[start] !== 1 || length < 9 || length > 64) fail('FUSE_WIRE_INVALID');
  const fuses = bytes.subarray(start, start + length + 2).toString('hex');
  for (const [index, value] of [[0, 48], [1, 49], [2, 48], [3, 48], [4, 49], [5, 49]]) if (bytes[start + 2 + index] !== value) fail('REQUIRED_FUSE_DISABLED');
  return { manifest, fuses, resources, exe };
}
async function editExecutable(filename, resourcesPath, version, tools) {
  const beforeBytes = await fs.readFile(filename), before = peSnapshot(beforeBytes, tools.resedit);
  const entries = before.resources.entries.filter(item => item.type === 'INTEGRITY' && item.id === 'ELECTRONASAR');
  if (entries.length !== 1) fail('UNIQUE_ASAR_RESOURCE_REQUIRED');
  const integrity = await tools.computeData({ resourcesPath, resourcesRelativePath: 'resources', resourcesDestinationPath: resourcesPath, extraResourceMatchers: null });
  entries[0].bin = Buffer.from(JSON.stringify(Object.entries(integrity).map(([file, value]) => ({ file: path.win32.normalize(file), alg: value.algorithm, value: value.hash }))));
  before.resources.outputResource(before.exe);
  await fs.writeFile(filename, Buffer.from(before.exe.generate()));
  await tools.editWindowsResources({ file: filename, versionStrings: { CompanyName: 'AI Maker Studio', ProductName: 'AI Maker Studio', FileDescription: 'AI Maker Studio', InternalName: 'AI Maker Studio', OriginalFilename: '' }, fileVersion: version, productVersion: '0.3.1.0', requestedExecutionLevel: 'asInvoker' });
  const after = peSnapshot(await fs.readFile(filename), tools.resedit);
  if (before.fuses !== after.fuses || JSON.stringify(before.manifest) !== JSON.stringify(after.manifest)) fail('EXECUTABLE_HARDENING_CHANGED');
  const actual = after.resources.entries.filter(item => item.type === 'INTEGRITY' && item.id === 'ELECTRONASAR');
  if (actual.length !== 1 || !Buffer.from(actual[0].bin).equals(Buffer.from(entries[0].bin))) fail('ASAR_RESOURCE_UPDATE_FAILED');
  return { fuses: after.fuses, manifest: after.manifest, asarIntegrity: integrity };
}
function validateFunctionalReport(report, artifact) {
  if (!report || report.functionalResult !== 'PASS' || report.lifecycleResult === 'FAIL' || artifact.version !== VERSION || report.artifact?.version !== artifact.version || report.artifact?.sha256 !== artifact.sha256 || report.artifact?.bytes !== artifact.bytes || report.childTimedOut || report.childExitCode !== 0 || report.standardUserProgress?.phase !== 'FINISHED' || report.checks?.some(item => /^DISPOSABLE_/.test(item.id) && item.status === 'FAIL')) fail('MATCHING_FUNCTIONAL_REPORT_REQUIRED');
}
async function buildPrivate(client, root) {
  for (const [name, expected] of [['electron-builder', '26.18.0'], ['app-builder-lib', '26.18.0'], ['@electron/asar', '3.4.1']]) if (require(name + '/package.json').version !== expected) fail('PINNED_TOOL_VERSION_REQUIRED');
  const asar = require('@electron/asar'), resedit = require('resedit');
  const reseditMetadata = JSON.parse(await fs.readFile(path.join(path.dirname(require.resolve('resedit')), '..', 'package.json'), 'utf8'));
  if (reseditMetadata.version !== '1.7.2') fail('PINNED_RESEDIT_VERSION_REQUIRED');
  const work = await fs.mkdtemp(path.join(root, 'ai-maker-private-rebuild-'));
  const original = path.join(work, 'original.exe'), wrapper = path.join(work, 'wrapper'), payload = path.join(work, 'payload'), source = path.join(work, 'archive-source'), output = path.join(work, 'output');
  for (const item of [wrapper, payload, source, output]) await fs.mkdir(item);
  stage('DOWNLOAD_ORIGINAL');
  await downloadOriginal(client, original);
  stage('LOCATE_7ZIP');
  const sevenZip = path.join(process.env.ProgramFiles, '7-Zip', '7z.exe');
  const nativeOptions = { env: childEnvironment(process.env), timeout: 180000, maxBuffer: 1024 * 1024, windowsHide: true };
  stage('LIST_PINNED_NSIS_MEMBER');
  const listing = await exec(sevenZip, ['l', '-slt', '-ba', original], nativeOptions);
  const payloadMember = selectPayloadMember(listing.stdout);
  stage('EXTRACT_NSIS_PAYLOAD_MEMBER');
  await exec(sevenZip, ['x', '-y', '-bso0', '-bsp0', '-bse0', '-o' + wrapper, original, payloadMember], nativeOptions);
  const appPackage = path.join(wrapper, '$PLUGINSDIR', 'app-64.7z');
  stage('VERIFY_EXTRACTED_NSIS_MEMBER');
  await safePath(appPackage, root);
  stage('EXTRACT_PINNED_APP_FILES');
  await exec(sevenZip, ['x', '-y', '-bso0', '-bsp0', '-bse0', '-o' + payload, appPackage], nativeOptions);
  const archive = path.join(payload, 'resources', 'app.asar');
  stage('VERIFY_PINNED_APP_ARCHIVE');
  await safePath(archive, root);
  if (await hashFile(archive) !== ORIGINAL.asarSha256) fail('ORIGINAL_ASAR_HASH_MISMATCH');
  stage('VERIFY_APP_COMPANIONS');
  const outerBefore = await treeHashes(payload);
  stage('VERIFY_ASAR_FILE_BLOCKS');
  const inventory = archiveInventory(archive, asar);
  if (inventory.find(item => item.name === POLICY)?.sha256 !== POLICY_HASH || !archiveLookup(asar, 'extractFile', archive, POLICY).toString('utf8').includes('schemaVersion: 1, enabled: false')) fail('DISABLED_PINNED_UPDATE_POLICY_REQUIRED');
  stage('VALIDATE_AND_PATCH_ARCHIVE');
  asar.extractAll(archive, source);
  for (const name of Object.keys(PATCHES)) await fs.writeFile(path.join(source, name), patchArchivedFile(name, archiveLookup(asar, 'extractFile', archive, name)));
  const nextArchive = path.join(work, 'app.asar'), unpacked = inventory.filter(item => item.unpacked).map(item => item.name);
  // The exact original unpacked paths contain no glob metacharacters.
  if (unpacked.some(name => /[{}*?!]|\[|\]/.test(name))) fail('UNSUPPORTED_UNPACK_PATH');
  // ASAR matches absolute source filenames, so retain the exact relative suffixes.
  await asar.createPackageWithOptions(source, nextArchive, { dot: true, unpack: '{' + unpacked.map(name => '**/' + name).join(',') + '}' });
  assertInventory(inventory, archiveInventory(nextArchive, asar));
  await fs.copyFile(nextArchive, archive);
  asar.uncache(archive);
  const executable = path.join(payload, 'AI Maker Studio.exe');
  stage('UPDATE_AND_VERIFY_PE_INTEGRITY');
  const hardening = await editExecutable(executable, path.join(payload, 'resources'), VERSION, {
    resedit, computeData: require('app-builder-lib/out/asar/integrity').computeData,
    editWindowsResources: require('app-builder-lib/out/util/resEdit').editWindowsResources,
  });
  assertCompanions(outerBefore, await treeHashes(payload));
  const metadata = JSON.parse(archiveLookup(asar, 'extractFile', archive, 'package.json'));
  await writeJSON(path.join(work, 'package.json'), metadata);
  const guard = await fs.readFile(path.join(__dirname, 'nsis-app-running-guard.nsh'));
  if (sha(guard) !== NSIS_GUARD_SHA256) fail('NSIS_APP_RUNNING_GUARD_HASH_MISMATCH');
  const guardInclude = path.join(work, 'nsis-app-running-guard.nsh');
  await fs.writeFile(guardInclude, guard, { flag: 'wx' });
  const config = { appId: 'lt.aimaker.studio', productName: 'AI Maker Studio', electronVersion: '45.4.1', asar: true, forceCodeSigning: false, compression: 'normal', directories: { output }, publish: null,
    win: { target: [{ target: 'nsis', arch: ['x64'] }], artifactName: ARTIFACT, requestedExecutionLevel: 'asInvoker', forceCodeSigning: false, signAndEditExecutable: false, signExecutable: false },
    nsis: { include: guardInclude, oneClick: false, perMachine: false, selectPerMachineByDefault: false, allowElevation: false, packElevateHelper: false, allowToChangeInstallationDirectory: true, deleteAppDataOnUninstall: false, createDesktopShortcut: true, createStartMenuShortcut: true, runAfterFinish: false, warningsAsErrors: true },
  };
  const { WineVmManager } = require('app-builder-lib/out/vm/WineVm'), { UninstallerReader } = require('app-builder-lib/out/targets/nsis/nsisUtil');
  const intermediate = path.join(output, ARTIFACT), originalExec = WineVmManager.prototype.exec;
  WineVmManager.prototype.exec = async function (file, args = []) {
    if (path.resolve(file) !== intermediate || args.length) fail('UNEXPECTED_NATIVE_EXECUTION_REJECTED');
    await safePath(file, root);
    return UninstallerReader.exec(file, file.replace(/\.exe$/, '.__uninstaller.exe'));
  };
  try {
    const { build, Platform, Arch } = require('electron-builder');
    stage('PACKAGE_UNSIGNED_PRIVATE_NSIS');
    await build({ projectDir: work, prepackaged: payload, config, targets: Platform.WINDOWS.createTarget('nsis', Arch.x64), publish: 'never' });
  } finally { WineVmManager.prototype.exec = originalExec; }
  assertCompanions(outerBefore, await treeHashes(payload));
  assertUnsignedPE(await fs.readFile(intermediate));
  const artifact = { path: intermediate, version: VERSION, bytes: (await fs.stat(intermediate)).size, sha256: await hashFile(intermediate) };
  if (artifact.bytes < 1024 * 1024 || artifact.sha256 === ORIGINAL.sha256) fail('NEW_INSTALLER_REQUIRED');
  const evidenceFile = path.join(work, 'rebuild-evidence.json');
  await writeJSON(evidenceFile, { schemaVersion: 1, original: ORIGINAL, artifact: { version: VERSION, bytes: artifact.bytes, sha256: artifact.sha256 }, changedArchiveFiles: Object.keys(PATCHES).map(name => ({ name, beforeSha256: PATCHES[name][0], afterSha256: PATCHES[name][1] })), nsisAppRunningGuardSha256: NSIS_GUARD_SHA256, archiveFilesVerified: inventory.length, unpackedFilesPreserved: unpacked.length, unchangedCompanionsVerified: Object.keys(outerBefore).length - 2, productionUpdates: 'DISABLED', authenticode: 'UNSIGNED', hardening, publicSourceUploaded: false, limitations: ['Unsigned private development artifact; SmartScreen reputation and target user-PC acceptance are not validated by rebuilding.'] });
  await fs.writeFile(intermediate + '.sha256', `${artifact.sha256}  ${ARTIFACT}\n`, { flag: 'wx' });
  const manifestFile = path.join(work, 'rebuild-manifest.json');
  await writeJSON(manifestFile, { schemaVersion: 1, workRoot: work, artifact, evidenceFile });
  stage('REBUILD_COMPLETE_NOT_PUBLISHED');
  return { manifest: manifestFile, artifact: artifact.path, sha256: artifact.sha256, bytes: artifact.bytes };
}
async function publishPrivate(client, root, manifestPath, reportPath) {
  const manifest = await smallJSON(manifestPath, root), work = await safePath(manifest.workRoot, root, true);
  const artifact = manifest.artifact;
  if (manifest.schemaVersion !== 1 || artifact?.version !== VERSION || artifact.path !== path.join(work, 'output', ARTIFACT) || manifest.evidenceFile !== path.join(work, 'rebuild-evidence.json')) fail('REBUILD_MANIFEST_INVALID');
  await safePath(artifact.path, root);
  if ((await fs.stat(artifact.path)).size !== artifact.bytes || await hashFile(artifact.path) !== artifact.sha256 || !/^[0-9a-f]{64}$/.test(artifact.sha256)) fail('REBUILD_ARTIFACT_CHANGED');
  const report = await smallJSON(reportPath, root);
  validateFunctionalReport(report, artifact);
  stage('MATCHING_FUNCTIONAL_REPORT_VERIFIED');
  const evidence = await smallJSON(manifest.evidenceFile, root);
  if (evidence.artifact?.sha256 !== artifact.sha256 || evidence.artifact?.bytes !== artifact.bytes || evidence.productionUpdates !== 'DISABLED' || evidence.authenticode !== 'UNSIGNED') fail('REBUILD_EVIDENCE_MISMATCH');
  const checksum = artifact.path + '.sha256';
  await safePath(checksum, root);
  if (await fs.readFile(checksum, 'utf8') !== `${artifact.sha256}  ${ARTIFACT}\n`) fail('CHECKSUM_CHANGED');
  const releases = await client.json(API + '/releases?per_page=100');
  if (!Array.isArray(releases) || releases.some(item => item.tag_name === 'v' + VERSION)) fail('RELEASE_TAG_ALREADY_EXISTS');
  const release = await client.json(API + '/releases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tag_name: 'v' + VERSION, name: `AI Maker Studio ${VERSION} — private unsigned test`, draft: true, prerelease: true, body: 'Owner-only draft. Unsigned personal-use development installer. Windows functional evidence is attached; publisher trust and interactive SmartScreen are not certified. Production updates remain disabled.' }) });
  if (release.draft !== true || release.prerelease !== true || !Number.isSafeInteger(release.id)) fail('PRIVATE_DRAFT_REQUIRED');
  const files = [[artifact.path, ARTIFACT, 'application/vnd.microsoft.portable-executable'], [checksum, ARTIFACT + '.sha256', 'text/plain'], [manifest.evidenceFile, 'rebuild-evidence.json', 'application/json'], [reportPath, 'windows-functional-report.json', 'application/json']];
  const uploaded = [];
  for (const [filename, name, type] of files) {
    if ((await client.json(`${API}/releases/${release.id}`)).draft !== true) fail('DRAFT_STATE_CHANGED');
    const bytes = await fs.readFile(filename);
    const asset = await client.json(`https://uploads.github.com/repos/${REPOSITORY}/releases/${release.id}/assets?name=${encodeURIComponent(name)}`, { method: 'POST', headers: { 'Content-Type': type, 'Content-Length': String(bytes.length) }, body: bytes });
    if (asset.size !== bytes.length || asset.digest !== 'sha256:' + sha(bytes)) fail('UPLOADED_ASSET_INTEGRITY_MISMATCH');
    uploaded.push({ id: asset.id, name, bytes: bytes.length, sha256: sha(bytes) });
  }
  if ((await client.json(`${API}/releases/${release.id}`)).draft !== true) fail('DRAFT_STATE_CHANGED');
  return { draft: true, prerelease: true, releaseId: release.id, assets: uploaded };
}
async function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (!['build', 'publish'].includes(mode)) fail('BUILD_OR_PUBLISH_MODE_REQUIRED');
  requireEnvironment(mode);
  const token = process.env.GH_TOKEN, root = await fs.realpath(process.env.RUNNER_TEMP), client = github(token);
  const clean = childEnvironment(process.env);
  for (const name of Object.keys(process.env)) if (!Object.hasOwn(clean, name)) delete process.env[name];
  let result;
  if (mode === 'build') { if (args.length) fail('BUILD_ARGUMENTS_REJECTED'); result = await buildPrivate(client, root); }
  else {
    if (args.length !== 4 || args[0] !== '--manifest' || args[2] !== '--report') fail('PUBLISH_ARGUMENTS_INVALID');
    result = await publishPrivate(client, root, args[1], args[3]);
  }
  console.log(JSON.stringify(result));
}
module.exports = { ORIGINAL, PATCHES, POLICY_HASH, NSIS_GUARD_SHA256, replaceOnce, patchArchivedFile, childEnvironment, requireEnvironment, assertInventory, assertCompanions, assertUnsignedPE, validateFunctionalReport, selectPayloadMember, failureDiagnostic, nativeArchivePath, archiveLookup };
if (require.main === module) main().catch(error => { console.error(JSON.stringify({ error: 'PRIVATE_INSTALLER_OPERATION_FAILED', ...failureDiagnostic(error) })); process.exitCode = 1; });
