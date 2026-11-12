const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {validateRequest, processRequests} = require('../.github/actions/run-with-verification/index.cjs');

async function fixture(t) {
  const parent = path.resolve(process.env.ICOURSE_TEST_TEMP_DIR || os.tmpdir());
  await fs.mkdir(parent, {recursive: true});
  const root = await fs.mkdtemp(path.join(parent, 'qr-runner-test-'));
  assert.equal(path.dirname(root), parent);
  t.after(() => fs.rm(root, {recursive: true, force: true}));
  const workspace = path.join(root, 'workspace');
  const directory = path.join(workspace, 'data', 'auth-verification');
  const bridge = path.join(root, 'bridge');
  await fs.mkdir(directory, {recursive: true});
  await fs.mkdir(bridge);
  const id = 'wechat-' + 'a'.repeat(32);
  const files = [path.join(directory, id + '.png'), path.join(directory, id + '.html')];
  await fs.writeFile(files[0], 'image');
  await fs.writeFile(files[1], '<html>qr</html>');
  const request = {id, directory, files};
  await fs.writeFile(path.join(bridge, id + '.request.json'), JSON.stringify(request));
  return {root, workspace, directory, bridge, id, files, request};
}

const env = {GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '2', GITHUB_REPOSITORY: 'owner/repo'};

test('QR is downloadable during the running job and removed on completion', async t => {
  const f = await fixture(t);
  const artifacts = new Map();
  let uploads = 0;
  let deleted;
  const client = {
    async uploadArtifact(name, files, directory, options) {
      uploads++;
      assert.match(name, /^wechat-verification-123-2-wechat-/);
      assert.deepEqual(files, await Promise.all(f.files.map(file => fs.realpath(file))));
      assert.equal(directory, await fs.realpath(f.directory));
      assert.equal(options.retentionDays, 1);
      return {id: 456};
    },
    async deleteArtifact(name) { deleted = name; },
  };
  await processRequests(f.bridge, f.workspace, client, artifacts, env);
  const result = JSON.parse(await fs.readFile(path.join(f.bridge, f.id + '.result.json'), 'utf8'));
  assert.equal(result.url, 'https://github.com/owner/repo/actions/runs/123/artifacts/456');
  await processRequests(f.bridge, f.workspace, client, artifacts, env);
  assert.equal(uploads, 1, 'same live QR must not be uploaded again');
  await fs.writeFile(path.join(f.bridge, f.id + '.remove'), '');
  await processRequests(f.bridge, f.workspace, client, artifacts, env);
  assert.match(deleted, /^wechat-verification-/);
  assert.equal(artifacts.size, 0);
  assert.deepEqual(await fs.readdir(f.bridge), []);
});

test('toolkit failures return a fallback result without logging signed URLs', async t => {
  const f = await fixture(t);
  const client = {async uploadArtifact() { throw new Error('https://secret.example/?signed=token'); }};
  await processRequests(f.bridge, f.workspace, client, new Map(), env);
  const result = JSON.parse(await fs.readFile(path.join(f.bridge, f.id + '.result.json'), 'utf8'));
  assert.deepEqual(result, {});
});

test('unavailable toolkit reports fallback without blocking Python', async t => {
  const f = await fixture(t);
  await processRequests(f.bridge, f.workspace, undefined, new Map(), env);
  const result = JSON.parse(await fs.readFile(path.join(f.bridge, f.id + '.result.json'), 'utf8'));
  assert.deepEqual(result, {});
});

test('files outside the workspace cannot be uploaded', async t => {
  const f = await fixture(t);
  const outside = path.join(f.root, f.id + '.html');
  await fs.writeFile(outside, 'private');
  await assert.rejects(validateRequest({...f.request, files: [f.files[0], outside]}, f.workspace));
});

test('unrelated or duplicate files cannot be uploaded', async t => {
  const f = await fixture(t);
  await assert.rejects(validateRequest({...f.request, files: [f.files[0], f.files[0]]}, f.workspace));
  await assert.rejects(validateRequest({...f.request, id: '../../secret'}, f.workspace));
});
