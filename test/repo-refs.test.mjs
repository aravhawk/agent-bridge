import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createProtector } from '../src/webhook.mjs';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore } from '../src/store.mjs';
import { VERIFIED_AUTHORIZATION, SCOPES } from '../src/policy.mjs';
import { MESSAGE_PROTOCOL, validateMessage } from '../src/messages.mjs';
import { formatRepoReferences, parseRepoReferences, REPO_REFS_HEADER, MAX_REPO_REFS, MAX_REPO_PATHS } from '../src/repo-refs.mjs';

const SHA1 = 'a'.repeat(40), SHA256 = 'b'.repeat(64);
const ref = { repository: 'aravhawk/agent-bridge', commit: SHA1,
  paths: [{ path: 'src/bridge.mjs', lines: { start: 10, end: 42 } }, 'docs/attachments.md'] };

test('repo refs: format and parse round-trip; full commit SHA, selected paths and line ranges', () => {
  const text = formatRepoReferences({ text: 'Please review the ACK change.', refs: [ref, { host: 'git.example.test', repository: 'team/tool', commit: SHA256 }] });
  assert.equal(text, ['Please review the ACK change.', '', REPO_REFS_HEADER,
    `- github.com/aravhawk/agent-bridge@${SHA1}`, '  - src/bridge.mjs#L10-L42', '  - docs/attachments.md',
    `- git.example.test/team/tool@${SHA256}`].join('\n'));
  assert.deepEqual(parseRepoReferences(text), [
    { host: 'github.com', repository: 'aravhawk/agent-bridge', commit: SHA1,
      paths: [{ path: 'src/bridge.mjs', lines: { start: 10, end: 42 } }, { path: 'docs/attachments.md' }] },
    { host: 'git.example.test', repository: 'team/tool', commit: SHA256, paths: [] }]);
  assert.deepEqual(parseRepoReferences(text + '\n\n'), parseRepoReferences(text));
  assert.deepEqual(parseRepoReferences('No references here.'), []);
});

test('repo refs: only immutable, bounded, relative references; never URLs, traversal or abbreviated commits', () => {
  for (const bad of [
    { ...ref, commit: 'abc1234' }, { ...ref, commit: SHA1.toUpperCase() }, { ...ref, commit: 'main' },
    { ...ref, repository: 'https://evil.example/x' }, { ...ref, repository: 'a/b/c' }, { ...ref, repository: '../x' },
    { ...ref, repository: 'a/..' }, { ...ref, host: 'https://github.com' }, { ...ref, host: 'localhost' },
    { ...ref, paths: ['../etc/passwd'] }, { ...ref, paths: ['/etc/passwd'] }, { ...ref, paths: ['a//b'] },
    { ...ref, paths: ['a\\b'] }, { ...ref, paths: ['a b'] }, { ...ref, paths: ['a#L1'] }, { ...ref, paths: ['a/./b'] },
    { ...ref, paths: [{ path: 'a', lines: { start: 0, end: 1 } }] }, { ...ref, paths: [{ path: 'a', lines: { start: 5, end: 4 } }] },
    { ...ref, paths: [{ path: 'a', lines: { start: 1, end: 1e9 } }] }, { ...ref, paths: Array(MAX_REPO_PATHS + 1).fill('a') },
    { ...ref, url: 'https://x' }, { ...ref, paths: ['x'.repeat(257)] },
  ]) assert.throws(() => formatRepoReferences({ refs: [bad] }), /invalid_repo_reference/, JSON.stringify(bad).slice(0, 80));
  assert.throws(() => formatRepoReferences({ refs: Array(MAX_REPO_REFS + 1).fill(ref) }), /invalid_repo_reference/);
  assert.throws(() => formatRepoReferences({ refs: [] }), /invalid_repo_reference/);
  // The whole message text stays within 4096 bytes.
  assert.throws(() => formatRepoReferences({ text: 'x'.repeat(4000), refs: [ref] }), /invalid_repo_reference/);
  // Malformed blocks in peer text are refused, never guessed at.
  for (const text of [`${REPO_REFS_HEADER}\n- github.com/a/b@abc`, `${REPO_REFS_HEADER}\n  - src/a.mjs`,
    `${REPO_REFS_HEADER}\n- github.com/a/b@${SHA1}\nextra line`, REPO_REFS_HEADER,
    `${REPO_REFS_HEADER}\n- github.com/a/b@${SHA1}\n  - ../x`]) {
    assert.throws(() => parseRepoReferences(text), /invalid_repo_reference/, text);
  }
});

test('repo refs: carried by the ordinary message text with storage unconfigured; no new envelope field', async () => {
  const principal = role => Object.defineProperty({ role, scopes: Object.values(SCOPES[role]), principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) },
    VERIFIED_AUTHORIZATION, { value: { policyId: 'c'.repeat(64), expiresAt: Date.now() + 86400000 } });
  // No attachment capability at all (the default): references still work.
  const store = new MemoryStore();
  const bridge = new Bridge({ store, dailyEnabled: true, messagePolicyIds: { jarvis: 'c'.repeat(64), friday: 'c'.repeat(64) } });
  const events = new NativeEvents({ store, protector: createProtector(randomBytes(32)), policyId: 'c'.repeat(64), enabled: true,
    transport: async (_url, req) => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  await events.subscribe(principal('jarvis'), { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const now = Date.now(), text = formatRepoReferences({ text: 'See commit.', refs: [ref] });
  const m = { protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'friday', to: 'jarvis', kind: 'message', sentAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 3600000).toISOString(), threadId: randomUUID(), route: 'inbox', text };
  assert.deepEqual(Object.keys(validateMessage(m, principal('friday'), now).envelope),
    ['protocol', 'id', 'from', 'to', 'kind', 'sentAt', 'expiresAt', 'threadId', 'route', 'text']);
  await bridge.sendMessage(principal('friday'), m);
  const read = await bridge.read(principal('jarvis'), { messageId: m.id });
  assert.deepEqual(parseRepoReferences(read.envelope.text)[0].paths[0], { path: 'src/bridge.mjs', lines: { start: 10, end: 42 } });
  assert.throws(() => validateMessage({ ...m, repoRefs: [ref] }, principal('friday'), now), /invalid_message/, 'no new wire field');
});
