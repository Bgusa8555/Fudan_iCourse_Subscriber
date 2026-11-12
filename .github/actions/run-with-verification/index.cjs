// Upload the QR artifact while Python is waiting, using the official toolkit.
// JavaScript actions receive the artifact runtime credentials from the runner;
// no personal GitHub token, external hosting service, or repository file is used.
const fs = require('node:fs/promises');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {setTimeout: delay} = require('node:timers/promises');

function isInside(root, target) {
  const relative = path.relative(root, target);
  return relative !== '' && !relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative);
}

async function validateRequest(request, workspace) {
  if (!/^wechat-[a-f0-9]{32}$/.test(request.id) || !Array.isArray(request.files) || request.files.length !== 2) {
    throw new Error('Invalid verification request');
  }
  const root = await fs.realpath(workspace);
  const directory = await fs.realpath(request.directory);
  if (!isInside(root, directory)) throw new Error('QR directory must be inside the workspace');
  const files = [];
  for (const filename of request.files) {
    const real = await fs.realpath(filename);
    const extension = path.extname(real);
    if (path.dirname(real) !== directory || path.basename(real, extension) !== request.id ||
        !['.png', '.jpeg', '.gif', '.html'].includes(extension) || (await fs.stat(real)).size > 4 * 1024 * 1024) {
      throw new Error('Invalid QR file');
    }
    files.push(real);
  }
  if (new Set(files).size !== 2 || files.filter(file => file.endsWith('.html')).length !== 1) {
    throw new Error('Expected one QR image and one HTML page');
  }
  return {files, directory};
}

async function processRequests(bridge, workspace, client, artifacts, environment = process.env) {
  const entries = await fs.readdir(bridge);
  const removed = new Set();
  for (const filename of entries.filter(name => /^wechat-[a-f0-9]{32}\.remove$/.test(name))) {
    const id = filename.slice(0, -'.remove'.length);
    const artifact = artifacts.get(id);
    if (artifact) {
      try {
        await client.deleteArtifact(artifact);
        artifacts.delete(id);
      } catch {
        // Retry on the next pass; retention is also limited to one day.
        continue;
      }
    }
    await fs.unlink(path.join(bridge, filename));
    removed.add(id);
    for (const suffix of ['.request.json', '.result.json']) {
      await fs.unlink(path.join(bridge, id + suffix)).catch(() => {});
    }
  }
  for (const filename of entries.filter(name => /^wechat-[a-f0-9]{32}\.request\.json$/.test(name))) {
    const id = filename.slice(0, -'.request.json'.length);
    if (removed.has(id)) continue;
    const requestPath = path.join(bridge, filename);
    const resultPath = path.join(bridge, id + '.result.json');
    if (await fs.stat(resultPath).then(() => true, () => false)) continue;
    if (await fs.stat(path.join(bridge, id + '.remove')).then(() => true, () => false)) continue;
    let result = {};
    try {
      if (!client) throw new Error('Artifact toolkit unavailable');
      const request = JSON.parse(await fs.readFile(requestPath, 'utf8'));
      if (request.id !== id) throw new Error('Mismatched QR request');
      const {files, directory} = await validateRequest(request, workspace);
      const name = `wechat-verification-${environment.GITHUB_RUN_ID}-${environment.GITHUB_RUN_ATTEMPT || '1'}-${id}`;
      const artifact = await client.uploadArtifact(name, files, directory, {retentionDays: 1});
      if (!Number.isSafeInteger(artifact.id) || artifact.id <= 0) throw new Error('Missing artifact ID');
      artifacts.set(id, name);
      result.url = `https://github.com/${environment.GITHUB_REPOSITORY}/actions/runs/${environment.GITHUB_RUN_ID}/artifacts/${artifact.id}`;
      console.log(`::notice title=微信扫码入口::${result.url} 下载并解压，打开 HTML 后用微信扫码；本次任务会继续等待。`);
    } catch {
      // Toolkit exceptions can contain signed storage URLs. Report no raw errors.
      console.log('::warning::二维码备用入口上传失败，程序将尝试邮件发送。');
    }
    const temporary = resultPath + '.tmp';
    await fs.writeFile(temporary, JSON.stringify(result), {mode: 0o600});
    await fs.rename(temporary, resultPath);
  }
}

async function main() {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const bridge = await fs.mkdtemp(path.join(process.env.RUNNER_TEMP || workspace, 'icourse-verification-'));
  let client;
  try {
    const {DefaultArtifactClient} = require('@actions/artifact');
    client = new DefaultArtifactClient();
  } catch {
    console.log('::warning::二维码备用入口依赖不可用，将使用邮件发送。');
  }
  const artifacts = new Map();
  const child = spawn('bash', ['-e', '-c',
    'eval "$(python scripts/provider_env.py)"\nunset SECRETS_CONTEXT\nexec python -u main.py'], {
    cwd: workspace, stdio: 'inherit',
    env: {...process.env, ICOURSE_VERIFICATION_BRIDGE: bridge},
  });
  let finished = false;
  let exitCode = 1;
  child.on('error', () => { finished = true; });
  child.on('exit', code => { exitCode = code === null ? 1 : code; finished = true; });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => child.kill(signal));
  try {
    while (!finished) {
      await processRequests(bridge, workspace, client, artifacts);
      await delay(500);
    }
  } finally {
    if (!finished) child.kill('SIGTERM');
    for (const [id, name] of artifacts) {
      try {
        await client.deleteArtifact(name);
        artifacts.delete(id);
      } catch {
        console.log('::warning::临时二维码附件清理暂未完成，将在 1 天保留期后删除。');
      }
    }
    await fs.rm(bridge, {recursive: true, force: true});
  }
  process.exitCode = exitCode;
}

module.exports = {validateRequest, processRequests};
if (require.main === module) main().catch(() => {
  console.log('::error::运行或二维码入口处理失败。');
  process.exitCode = 1;
});
