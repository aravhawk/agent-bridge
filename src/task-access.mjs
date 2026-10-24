import { createHash } from 'node:crypto';
import { authorizationPolicyId, BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from './policy.mjs';
import { resourceFor } from './resource.mjs';
import { resourceDenied } from './access.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const writes = new Set(['create', 'assign', 'claim', 'progress', 'finish', 'block', 'cancel', 'start', 'reconcile']);

// Trusted server configuration only, matching the current resource verifiers.
// No caller identity, policy selector, grant registry or execution permission.
export function createTaskAccess({ issuer, subject, subjectHash, scopeClaim = 'scope' } = {}) {
  const invalid = () => { throw new BridgeError('task_access_configuration_required', 503); };
  if (typeof issuer !== 'string' || !['scope', 'scp', 'scopes'].includes(scopeClaim) ||
      !((typeof subject === 'string' && subject.length > 0 && subjectHash === undefined) ||
        (subject === undefined && hash(subjectHash)))) invalid();
  let url;
  try { url = new URL(issuer); } catch { invalid(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) invalid();
  const pin = subject === undefined ? subjectHash : digest(subject);
  const ownerKey = digest(JSON.stringify(['bridge-task-owner/v1', issuer, pin]));
  const policies = Object.fromEntries(['jarvis', 'friday'].map(role => [role,
    authorizationPolicyId({ issuer, subject, subjectHash, scopeClaim, role, audience: resourceFor(role) })]));
  return (principal, request, now, state) => {
    const role = principal?.role, scopes = SCOPES[role], proof = principal?.[VERIFIED_AUTHORIZATION];
    const write = writes.has(request?.operation);
    if (!['jarvis', 'friday'].includes(role) || !scopes || (!write && request?.operation !== 'read') || !Number.isSafeInteger(now) ||
        state?.version !== 1 || !hash(principal.principalKey) || !Array.isArray(principal.scopes) ||
        proof?.policyId !== policies[role] || !Number.isSafeInteger(proof?.expiresAt) || proof.expiresAt <= now ||
        !principal.scopes.includes(scopes.ack) || (write && !principal.scopes.includes(scopes.probe)) ||
        resourceDenied(state, principal.principalKey)) return { dataAllowed: false };
    return { dataAllowed: true, ownerKey, role, coordinate: write };
  };
}
