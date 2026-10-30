"""Audit staged files and all reachable Git-history blobs; never print matches.

Use with a dedicated secret detector such as Gitleaks before publishing. This
additional project audit rejects known credential/history artifacts and enforces
blank example secret slots. Findings contain paths/rule names only.
"""
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def git(*args):
    return subprocess.run(['git', '-C', str(ROOT), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

RULES = {
    'private-key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'github-token': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{25,})\b'),
    'provider-secret': re.compile(rb'\b(?:sk_live_|sk_test_|sk-proj-|whsec_)[A-Za-z0-9+/=_-]{24,}'),
    'encoded-jwt': re.compile(rb'\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}'),
    'oauth-flow-url': re.compile(rb'https://[^\s\x22\x27]+[?&](?:code|state|access_token|refresh_token|code_verifier|client_secret)='),
    'message-or-real-user-id': re.compile(rb'\b(?:Sentinel_[0-9a-f]+|user_[A-Za-z0-9]{20,})\b'),
    'private-contact-email': re.compile(rb'[A-Za-z0-9._%+-]+@(?:gmail|outlook|hotmail|icloud)\.com\b'),
}
# Current-tree-only identity rules. Git history predates the open-source scrub
# and is rewritten separately, so these are not applied to history blobs.
# Patterns are assembled so this file does not match itself.
INDEX_RULES = {
    'deployment-resource-id': re.compile(rb'\b(?:team|prj)_[A-Za-z0-9]{20,}\b'),
    'provider-dev-instance': re.compile(rb'\b[a-z]+-[a-z]+-[0-9]+\.clerk\.accounts\.dev\b'),
    'retired-deployment-name': re.compile(b'rn-' + b'jarvis-friday-discovery'),
    'personal-name': re.compile(b'Arav' + b' Jain'),
}
DB_URI = re.compile(rb'postgres(?:ql)?://[^\s\x22\x27]+:[^\s\x22\x27]+@[^\s\x22\x27]+')
findings = []
seen = set()

def inspect(path, data, source):
    identity = (path, data)
    if identity in seen:
        return
    seen.add(identity)
    p = PurePosixPath(path)
    forbidden = any(part in {'.vercel', 'node_modules', '.reports', 'transcripts', 'message-history', 'evidence'} for part in p.parts)
    forbidden |= p.name.startswith('.env') and p.name != '.env.example'
    forbidden |= p.suffix in {'.pem', '.key', '.p12', '.pfx', '.zip'}
    if forbidden:
        findings.append({'source': source, 'path': path, 'rule': 'excluded-artifact'})
    for name, pattern in RULES.items():
        if pattern.search(data):
            findings.append({'source': source, 'path': path, 'rule': name})
    if source == 'index':
        for name, pattern in INDEX_RULES.items():
            if pattern.search(data):
                findings.append({'source': source, 'path': path, 'rule': name})
    for match in DB_URI.finditer(data):
        # The existing unit fixture is deliberately fake and has no authority.
        fixture_prefix = b'postgresql:' + b'//fixture:' + b'fixture@fixture.neon.tech/'
        if path == 'test/runtime.test.mjs' and match.group().startswith(fixture_prefix):
            continue
        findings.append({'source': source, 'path': path, 'rule': 'database-credential-url'})
    if p.name == '.env.example':
        for line in data.decode().splitlines():
            if '=' not in line or line.lstrip().startswith('#'):
                continue
            key, value = line.split('=', 1)
            if re.search(r'(?:SECRET|PASSWORD|WEBHOOK_KEY|STORAGE_KEY|DATABASE_URL|ALLOWED_SUBJECT)', key) and value.strip():
                findings.append({'source': source, 'path': path, 'rule': 'nonblank-example-secret'})

staged = git('ls-files', '--stage', '-z').split(b'\0')
staged_count = 0
for row in filter(None, staged):
    info, path_bytes = row.split(b'\t', 1)
    mode, oid, stage = info.split()
    path = path_bytes.decode()
    if mode == b'120000' or stage != b'0':
        findings.append({'source': 'index', 'path': path, 'rule': 'symlink-or-unmerged-file'})
        continue
    inspect(path, git('cat-file', 'blob', oid.decode()), 'index')
    staged_count += 1

history_count = 0
for row in git('rev-list', '--objects', '--all').decode().splitlines():
    if ' ' not in row:
        continue
    oid, path = row.split(' ', 1)
    if git('cat-file', '-t', oid).strip() != b'blob':
        continue
    inspect(path, git('cat-file', 'blob', oid), 'history')
    history_count += 1

print(json.dumps({'staged_files': staged_count, 'history_blobs': history_count,
                  'findings': findings, 'passed': not findings}, indent=2))
raise SystemExit(bool(findings))
