"""Credential-free fixed checks of only this approved isolated deployment."""
import datetime
import json
import urllib.request
import urllib.error
from pathlib import Path
Path(__file__).resolve().parents[1].joinpath('.reports/remote').mkdir(parents=True, exist_ok=True)

BASE = 'https://rn-jarvis-friday-discovery-20261018.vercel.app'
ISSUER = 'https://musical-bee-9978.clerk.accounts.dev'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None
opener = urllib.request.build_opener(NoRedirect)
results = []
def check(name, path, expected, predicate=lambda body, headers: True, post=False, headers=None):
    req = urllib.request.Request(BASE + path, data=b'{}' if post else None, headers=headers or {})
    try: res = opener.open(req, timeout=20)
    except urllib.error.HTTPError as e: res = e
    raw = res.read(16384)
    try: body = json.loads(raw)
    except ValueError: body = None
    passed = res.status == expected and predicate(body, res.headers)
    results.append({'test': name, 'status': res.status, 'passed': passed})
    if not passed: raise RuntimeError('Fixed bridge check failed: ' + name)
try:
    for role in ['friday', 'jarvis']:
        resource = '/bridge/' + role + '/mcp'
        metadata = '/.well-known/oauth-protected-resource' + resource
        check(role + ' GET auth challenge', resource, 401,
              lambda b,h: h.get('WWW-Authenticate') == 'Bearer resource_metadata="' + BASE + metadata + '"')
        check(role + ' POST auth challenge', resource, 401, post=True)
        check(role + ' actual-provider metadata', metadata, 200,
              lambda b,h: b['resource'] == BASE + resource and b['authorization_servers'] == [ISSUER]
              and len(b['scopes_supported']) == 2 and 'registration_endpoint' not in b)
        check(role + ' cross-origin rejected', resource, 403,
              headers={'Origin':'https://unrelated.example'})
        # Deliberately invalid, nonsecret fixture marker. Never send a real token.
        check(role + ' invalid token rejected by verified policy', resource, 401, post=True,
              headers={'Authorization':'Bearer FIXTURE_INVALID_NOT_A_TOKEN','Content-Type':'application/json'})
    # A queue/v2beta consumer has no public URL; only queue infrastructure can
    # invoke it. Its disabled execution gate is checked separately in Node tests.
    check('private queue consumer has no public URL', '/api/queue', 404, post=True,
          predicate=lambda b,h: h.get('Content-Type','').startswith('text/plain'))
finally:
    evidence = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'base_url': BASE, 'follow_redirects': False, 'real_credentials_sent': False,
                'real_delivery_attempted': False, 'results': results,
                'all_passed': len(results) == 11 and all(x['passed'] for x in results)}
    Path(__file__).resolve().parents[1].joinpath('.reports/remote/managed-bridge-remote-checks-20261018.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(evidence,indent=2))
