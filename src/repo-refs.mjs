import { BridgeError } from './policy.mjs';

// Immutable repository references carried in ordinary message text (no new
// envelope field, no storage, no credential, no repository access). Prefer
// these over uploading archives when both peers can already reach the
// repository: a full commit SHA plus selected paths and line ranges. The
// bridge never fetches, clones, unpacks or executes anything; the receiver
// resolves the reference with its own already-authorized Git tools and,
// where that is denied or unavailable, asks for an explicitly chosen file
// transfer instead. The format is text, so it reads the same whether or not
// attachments are enabled, and the whole message stays within the 4096-byte
// text limit.
//
//   <your text>
//
//   Repository references (immutable; resolve with your own authorized Git access):
//   - github.com/owner/repo@<40 or 64 hex commit>
//     - src/file.mjs#L10-L42
//     - docs/README.md
export const REPO_REFS_HEADER = 'Repository references (immutable; resolve with your own authorized Git access):';
export const MAX_REPO_REFS = 4, MAX_REPO_PATHS = 16, MAX_PATH_BYTES = 256, MAX_LINE = 10000000;
const TEXT_LIMIT = 4096;
const HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const NAME = /^[A-Za-z0-9_.-]{1,100}$/;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SEGMENT = /^[A-Za-z0-9._@+-]{1,255}$/;
const fail = () => { throw new BridgeError('invalid_repo_reference', 400); };

function checkRepository(repository) {
  const parts = typeof repository === 'string' ? repository.split('/') : [];
  if (parts.length !== 2 || parts.some(p => !NAME.test(p) || p === '.' || p === '..')) fail();
  return repository;
}
function checkPath(entry) {
  const { path, lines } = typeof entry === 'string' ? { path: entry } : entry || {};
  if (typeof path !== 'string' || Buffer.byteLength(path) > MAX_PATH_BYTES ||
      path.split('/').some(s => !SEGMENT.test(s) || s === '.' || s === '..')) fail();
  if (lines === undefined) return { path };
  const { start, end } = lines || {};
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 1 || end < start || end > MAX_LINE) fail();
  return { path, lines: { start, end } };
}
// Normalized, validated copy of one reference: { host, repository, commit, paths }.
export function repoReference(ref) {
  if (!ref || typeof ref !== 'object' || Array.isArray(ref) ||
      Object.keys(ref).some(k => !['host', 'repository', 'commit', 'paths'].includes(k))) fail();
  const host = ref.host ?? 'github.com';
  if (typeof host !== 'string' || !HOST.test(host) || host.length > 253) fail();
  if (typeof ref.commit !== 'string' || !COMMIT.test(ref.commit)) fail();
  const paths = ref.paths ?? [];
  if (!Array.isArray(paths) || paths.length > MAX_REPO_PATHS) fail();
  return { host, repository: checkRepository(ref.repository), commit: ref.commit, paths: paths.map(checkPath) };
}
const line = p => `  - ${p.path}${p.lines ? `#L${p.lines.start}-L${p.lines.end}` : ''}`;
// Message text with the references appended. Refuses (invalid_repo_reference)
// anything malformed or a result over the 4096-byte message text limit.
export function formatRepoReferences({ text = '', refs }) {
  if (typeof text !== 'string' || !Array.isArray(refs) || refs.length < 1 || refs.length > MAX_REPO_REFS) fail();
  const block = [REPO_REFS_HEADER, ...refs.map(repoReference).flatMap(r =>
    [`- ${r.host}/${r.repository}@${r.commit}`, ...r.paths.map(line)])].join('\n');
  const out = text.trim() ? `${text.trimEnd()}\n\n${block}` : block;
  if (Buffer.byteLength(out, 'utf8') > TEXT_LIMIT) fail();
  return out;
}
// The references in a message's text, validated exactly as formatted, or []
// when there is no reference block. Peer text is data: a malformed block is
// refused, never guessed at.
export function parseRepoReferences(text) {
  if (typeof text !== 'string') fail();
  const lines = text.split('\n'), at = lines.indexOf(REPO_REFS_HEADER);
  if (at === -1) return [];
  const refs = [];
  const body = lines.slice(at + 1);
  while (body.length && body.at(-1) === '') body.pop();
  for (const l of body) {
    let m;
    if ((m = /^- ([^/\s]+)\/([^/\s]+\/[^@\s]+)@([0-9a-f]+)$/.exec(l))) {
      refs.push({ host: m[1], repository: m[2], commit: m[3], paths: [] });
    } else if ((m = /^ {2}- (\S+?)(?:#L(\d{1,8})-L(\d{1,8}))?$/.exec(l)) && refs.length) {
      refs.at(-1).paths.push(m[2] ? { path: m[1], lines: { start: Number(m[2]), end: Number(m[3]) } } : { path: m[1] });
    } else fail();
  }
  if (!refs.length || refs.length > MAX_REPO_REFS) fail();
  return refs.map(repoReference);
}
