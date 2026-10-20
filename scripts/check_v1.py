"""Credential-free canonical v1 checks; never tokens, grants or delivery."""
import argparse
import datetime
import json
from pathlib import Path
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--issuer', help='Actual approved public issuer, for metadata comparison only')
parser.add_argument('--auth-configured', action='store_true', help='Expect real JWT policy to reject the invalid fixture with401')
args = parser.parse_args()
BASE = 'https://jarvis-friday-bridge.aravhawk.com'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None
opener = urllib.request.build_opener(NoRedirect)
results = []
def check(name, path, expected, predicate=lambda b,h: True, post=False, headers=None):
    req=urllib.request.Request(BASE+path, data=b'{}' if post else None, headers=headers or {})
    try: response=opener.open(req, timeout=15)
    except urllib.error.HTTPError as e: response=e
    raw=response.read(16384)
    try: body=json.loads(raw)
    except ValueError: body=None
    passed=response.status==expected and predicate(body,response.headers)
    results.append({'test':name,'status':response.status,'passed':passed})
    if not passed: raise RuntimeError('v1 check failed: '+name)
try:
    check('clean v1 health','/health',200,lambda b,h:b['version']=='1.0.0' and b['service']=='Jarvis Friday Bridge')
    for role in ['jarvis','friday']:
        path='/bridge/'+role+'/mcp'
        meta='/.well-known/oauth-protected-resource'+path
        for post in [False,True]:
            check(role+' authentication challenge '+str(post),path,401,
                  lambda b,h:h.get('WWW-Authenticate')=='Bearer resource_metadata="'+BASE+meta+'"',post=post)
        check(role+' metadata',meta,200 if args.issuer else 503,
              (lambda b,h:b['resource']==BASE+path and b['authorization_servers']==[args.issuer]) if args.issuer else lambda b,h:b['error']=='identity_provider_not_configured')
        check(role+' cross-origin rejected',path,403,headers={'Origin':'https://unrelated.example'})
        check(role+' invalid fixture rejected',path,401 if args.auth_configured else 503,post=True,
              headers={'Content-Type':'application/json','Authorization':'Bearer FIXTURE_INVALID_NOT_A_TOKEN'})
    for path in ['/mcp','/oauth-diag/public/mcp','/.well-known/oauth-authorization-server']:
        check('legacy path absent '+path,path,404)
    check('private queue has no public URL','/api/queue',404,post=True)
finally:
    evidence={'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base_url':BASE,
              'real_credentials_sent':False,'application_messages_sent':False,'results':results,
              'all_passed':len(results)==15 and all(r['passed'] for r in results)}
    out=Path(__file__).resolve().parents[1]/'.reports'/'v1-boundaries.json'
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(evidence,indent=2))
