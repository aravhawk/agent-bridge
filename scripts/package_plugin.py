"""Render/package the MCP plugin using actual approved PUBLIC OAuth metadata; never upload."""
import argparse
import json
import os
from pathlib import Path
import re
from urllib.parse import urlparse
import zipfile

PEER = re.compile(r'[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?')
parser = argparse.ArgumentParser()
parser.add_argument('--origin', default=os.environ.get('BRIDGE_PUBLIC_ORIGIN'),
                    help='Deployed public origin (default: $BRIDGE_PUBLIC_ORIGIN)')
parser.add_argument('--peer', default='jarvis', help='Peer ID this plugin connects as (default: jarvis)')
parser.add_argument('--counterpart', default='friday', help='The other peer ID (default: friday)')
parser.add_argument('--issuer', required=True, help='Actual approved OAuth issuer origin')
parser.add_argument('--client-id', '--jarvis-client-id', dest='client_id', required=True,
                    help='Verified public OAuth client ID for this peer')
parser.add_argument('--require-issuer-under-origin', action='store_true',
                    help='Reject an issuer that is not a subdomain of the origin')
parser.add_argument('--output', type=Path)
args = parser.parse_args()

def bare_origin(value):
    u = urlparse(value or '')
    return (u.scheme == 'https' and u.hostname and value == 'https://' + u.hostname and not u.username
            and not u.password and not u.port and u.path in ('', '/') and not u.query and not u.fragment)

if not bare_origin(args.origin):
    parser.error('Pass --origin https://<host> or set BRIDGE_PUBLIC_ORIGIN.')
if not bare_origin(args.issuer) or (args.require_issuer_under_origin and
        not urlparse(args.issuer).hostname.endswith('.' + urlparse(args.origin).hostname)):
    parser.error('Use the actual approved issuer origin (HTTPS, no path, port or credentials).')
if not PEER.fullmatch(args.peer) or not PEER.fullmatch(args.counterpart) or args.peer == args.counterpart:
    parser.error('Peer IDs must be two distinct lowercase identifiers.')
if not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', args.client_id):
    parser.error('A verified public client ID is required.')
values = {'{{OAUTH_ISSUER}}': args.issuer.rstrip('/'), '{{CLIENT_ID}}': args.client_id,
          '{{RESOURCE}}': args.origin + '/bridge/' + args.peer + '/mcp',
          '{{ACK_SCOPE}}': 'bridge:ack:' + args.peer, '{{SEND_SCOPE}}': 'bridge:send:' + args.counterpart}
root = Path(__file__).resolve().parents[1]
source = root / 'plugin'
manifest = json.loads((source / 'plugin.json').read_text())
template = (source / 'mcp.template.json').read_text()
for placeholder, value in values.items():
    template = template.replace(placeholder, value)
config = json.loads(template)
compat = {'mcpServers': config['mcpServers']}
files = {'plugin.json': manifest, 'mcp.json': config, '.mcp.json': compat,
         '.codex-plugin/plugin.json': json.loads((source / '.codex-plugin/plugin.json').read_text())}
out = args.output or root / '.reports' / ('plugin-' + manifest['version'] + '.zip')
out.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for name, value in files.items():
        archive.writestr(manifest['name'] + '/' + name, json.dumps(value, indent=2) + '\n')
    archive.writestr(manifest['name'] + '/LICENSE', (root / 'LICENSE').read_bytes())
print(out)
