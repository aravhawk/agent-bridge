"""Render/package v1 using actual approved PUBLIC OAuth metadata; never upload."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlparse
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--issuer', required=True)
parser.add_argument('--jarvis-client-id', required=True)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
u = urlparse(args.issuer)
if (args.issuer != 'https://' + (u.hostname or '') or u.scheme != 'https' or not u.hostname or not u.hostname.endswith('.jarvis-friday-bridge.aravhawk.com')
        or u.username or u.password or u.port or u.path not in ('', '/') or u.query or u.fragment):
    parser.error('Use the actual approved production issuer origin in the service namespace.')
if not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', args.jarvis_client_id):
    parser.error('A verified public Jarvis client ID is required.')
issuer = args.issuer.rstrip('/')
root = Path(__file__).resolve().parents[1]
source = root / 'plugin'
manifest = json.loads((source / 'plugin.json').read_text())
config = json.loads((source / 'mcp.template.json').read_text().replace('{{OAUTH_ISSUER}}', issuer).replace('{{JARVIS_CLIENT_ID}}', args.jarvis_client_id))
compat = {'mcpServers': config['mcpServers']}
files = {'plugin.json': manifest, 'mcp.json': config, '.mcp.json': compat,
         '.codex-plugin/plugin.json': json.loads((source / '.codex-plugin/plugin.json').read_text())}
out = args.output or root / '.reports' / ('plugin-' + manifest['version'] + '.zip')
out.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for name, value in files.items():
        archive.writestr(manifest['name'] + '/' + name, json.dumps(value, indent=2) + '\n')
print(out)
