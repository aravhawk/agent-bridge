import { createHash } from 'node:crypto';
import { authorizationPolicyId, BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from './policy.ts';
import { resourceFor } from './resource.ts';
import { resourceDenied } from './access.ts';
import { PEER_IDS } from './config.ts';
import type { PeerScopes } from './config.ts';
import type { BridgeState, Millis, Principal } from './types.ts';

const digest = (value: string): string => createHash('sha256').update(value).digest('hex');
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const writes = new Set(['create', 'assign', 'claim', 'progress', 'finish', 'block', 'cancel', 'start', 'reconcile']);

// Trusted server configuration only, matching the current resource verifiers.
// No caller identity, policy selector, grant registry or execution permission.
export interface TaskAccessPolicy { issuer?: string | undefined; subject?: string | undefined; subjectHash?: string | undefined; scopeClaim?: string }
export interface TaskAccessRequest { operation?: string }
export type TaskAccessDecision = { dataAllowed: false } | { dataAllowed: true; ownerKey: string; role: string; coordinate: boolean };
export type TaskAuthorizer = (principal: Principal | null | undefined, request: TaskAccessRequest | null | undefined, now: Millis,
  state?: BridgeState | null | undefined) => TaskAccessDecision;
export function createTaskAccess({ issuer, subject, subjectHash, scopeClaim = 'scope' }: TaskAccessPolicy = {}): TaskAuthorizer {
  // Explicitly typed so a bare invalid() statement narrows control flow.
  const invalid: () => never = () => { throw new BridgeError('task_access_configuration_required', 503); };
  if (typeof issuer !== 'string' || !['scope', 'scp', 'scopes'].includes(scopeClaim) ||
      !((typeof subject === 'string' && subject.length > 0 && subjectHash === undefined) ||
        (subject === undefined && hash(subjectHash)))) invalid();
  let url!: URL;
  try { url = new URL(issuer as string); } catch { invalid(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) invalid();
  const pin = subject === undefined ? subjectHash : digest(subject);
  // issuer was validated above.
  const ownerKey = digest(JSON.stringify(['bridge-task-owner/v1', issuer, pin]));
  const policies = Object.fromEntries(PEER_IDS.map(role => [role,
    authorizationPolicyId({ issuer: issuer as string, subject, subjectHash, scopeClaim, role, audience: resourceFor(role) })]));
  return (principal, request, now, state) => {
    const role = principal?.role, scopes = SCOPES[role as string], proof = principal?.[VERIFIED_AUTHORIZATION];
    const write = writes.has(request?.operation as string);
    if (!PEER_IDS.includes(role as string) || !scopes || (!write && request?.operation !== 'read') || !Number.isSafeInteger(now) ||
        // A defined role (a peer ID) implies a principal; a version-1 state is present.
        state?.version !== 1 || !hash(principal!.principalKey) || !Array.isArray(principal!.scopes) ||
        proof?.policyId !== policies[role as string] || !Number.isSafeInteger(proof?.expiresAt) || proof!.expiresAt <= now ||
        !principal!.scopes.includes(scopes.ack) || (write && !principal!.scopes.includes(scopes.probe)) ||
        resourceDenied(state, principal!.principalKey)) return { dataAllowed: false };
    return { dataAllowed: true, ownerKey, role: role as string, coordinate: write };
  };
}
