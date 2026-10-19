"""Fixed no-credential checks against only the approved isolated diagnostic."""
import datetime
import json
from pathlib import Path
Path(__file__).resolve().parents[1].joinpath('.reports/remote').mkdir(parents=True, exist_ok=True)
import urllib.error
import urllib.request

BASE = 'https://rn-jarvis-friday-discovery-20261018.vercel.app'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None
opener = urllib.request.build_opener(NoRedirect)
results = []
def check(name, path, status, expected, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type': 'application/json'} if body is not None else {})
    try: response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as error: response = error
    value = json.loads(response.read(16384))
    passed = response.status == status and expected(value)
    results.append({'test': name, 'status': response.status, 'passed': passed})
    if not passed: raise RuntimeError('Fixed diagnostic check failed: ' + name)

try:
    for mode in ['dcr', 'cimd', 'public']:
        root = '/oauth-diag/' + mode
        check(mode + ' resource rejects', root + '/mcp', 401, lambda b: b['noGrantsOrTokens'])
        check(mode + ' protected metadata', '/.well-known/oauth-protected-resource' + root + '/mcp', 200,
            lambda b: b['authorization_servers'] == [BASE + root])
        check(mode + ' AS metadata', '/.well-known/oauth-authorization-server' + root, 200,
            lambda b: b['code_challenge_methods_supported'] == ['S256'] and
                b['client_id_metadata_document_supported'] == (mode == 'cimd') and
                ('registration_endpoint' in b) == (mode != 'public'))
    check('synthetic DCR refuses without client ID', '/oauth-diag/dcr/register', 400,
        lambda b: b['error'] == 'invalid_client_metadata' and 'client_id' not in b,
        {'redirect_uris': ['https://public-test.invalid/callback'], 'token_endpoint_auth_method': 'none'})
    check('empty token request refuses', '/oauth-diag/cimd/token', 400,
        lambda b: b['error'] == 'access_denied' and 'access_token' not in b, {})
finally:
    evidence = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source': 'fixed local-client synthetic diagnostic checks, distinct from Friday',
        'base_url': BASE, 'follow_redirects': False, 'credentials_sent': False,
        'results': results, 'all_passed': len(results) == 11 and all(r['passed'] for r in results)}
    Path(__file__).resolve().parents[1].joinpath('.reports/remote/oauth-diagnostic-remote-checks.json').write_text(
        json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(evidence, indent=2))
