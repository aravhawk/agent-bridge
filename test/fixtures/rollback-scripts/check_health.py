"""Fixed synthetic requests against ONLY this task's isolated deployment."""
import datetime
import json
from pathlib import Path
Path(__file__).resolve().parents[1].joinpath('.reports/remote').mkdir(parents=True, exist_ok=True)
import urllib.error
import urllib.request

BASE = 'https://rn-jarvis-friday-discovery-20261018.vercel.app'
HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

opener = urllib.request.build_opener(NoRedirect)
results = []

def request(path, body=None, extra=None):
    headers = dict(HEADERS) if body is not None else {}
    headers.update(extra or {})
    req = urllib.request.Request(BASE + path,
        data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read(16384)
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    return response.status, parsed

def check(name, path, body, expected_status, predicate=lambda result: True, extra=None):
    status, result = request(path, body, extra)
    passed = status == expected_status and predicate(result)
    results.append({'test': name, 'status': status, 'passed': passed})
    if not passed:
        raise RuntimeError('Fixed synthetic check failed: ' + name)
    return result

def rpc(method, params=None):
    return {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}

try:
    check('public health', '/health', None, 200,
          lambda r: r['status'] == 'ok' and not r['messageDelivery'] and not r['events'])
    check('initialize HTTP MCP', '/mcp', rpc('initialize', {'protocolVersion': '2025-06-18'}), 200,
          lambda r: r['result']['protocolVersion'] == '2025-06-18')
    check('initialized notification', '/mcp', {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, 202)
    check('list only health tool', '/mcp', rpc('tools/list'), 200,
          lambda r: [t['name'] for t in r['result']['tools']] == ['probe_health'])
    check('call only health tool', '/mcp', rpc('tools/call', {'name': 'probe_health', 'arguments': {}}), 200,
          lambda r: json.loads(r['result']['content'][0]['text'])['status'] == 'ok')
    check('delivery tool unavailable', '/mcp', rpc('tools/call', {'name': 'send_message', 'arguments': {'payload': 'SYNTHETIC'}}), 200,
          lambda r: r['error']['code'] == -32602)
    check('events unavailable', '/mcp', rpc('events/subscribe'), 200,
          lambda r: r['error']['code'] == -32601)
    check('OAuth unconfigured', '/.well-known/oauth-protected-resource', None, 503,
          lambda r: r['error'] == 'oauth_not_configured')
    check('protected endpoint closed', '/protected/mcp', None, 503)
    check('cross-origin blocked', '/mcp', rpc('ping'), 403, extra={'Origin': 'https://unrelated.example'})
    check('GET MCP unsupported', '/mcp', None, 405)
    check('no token issuance', '/oauth/token', rpc('synthetic'), 404)
finally:
    evidence = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'base_url': BASE, 'follow_redirects': False, 'authorization_sent': False,
                'results': results, 'all_passed': len(results) == 12 and all(r['passed'] for r in results)}
    Path(__file__).resolve().parents[1].joinpath('.reports/remote/vercel-remote-checks-20261018.json').write_text(
        json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(evidence, indent=2))
