import { createHash } from 'node:crypto';
import { SCOPES } from './policy.mjs';
import { ISSUER, resourceFor } from './resource.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
export const JARVIS_CLIENT_ID = 'f58dfaNi1qX2vtdx';

// readCurrentGrant is a trusted provider integration, never caller-supplied
// metadata or a saved JWT assertion. It must read current grant/revocation facts
// on each call. An absent reader is a closed configuration, not an allow-all.
export function createJarvisAccessAllowed({ subject, subjectHash, readCurrentGrant,
  clock = Date.now } = {}) {
  const pinned = (typeof subject === 'string' && !!subject && !subjectHash) ||
    (!subject && /^[a-f0-9]{64}$/.test(subjectHash || ''));
  const configured = !!pinned && typeof readCurrentGrant === 'function';
  const check = async ({ owner, recipient } = {}) => {
    if (!configured || recipient !== 'jarvis' || typeof owner !== 'string' || !/^[a-f0-9]{64}$/.test(owner)) return false;
    const now = clock();
    try {
      const grant = await readCurrentGrant(Object.freeze({ issuer: ISSUER,
        clientId: JARVIS_CLIENT_ID, resource: resourceFor('jarvis'),
        requiredScope: SCOPES.jarvis.ack, owner }));
      if (!grant || grant.active !== true || grant.revoked !== false ||
          grant.issuer !== ISSUER || grant.clientId !== JARVIS_CLIENT_ID ||
          grant.resource !== resourceFor('jarvis') || typeof grant.subject !== 'string' ||
          (subject ? grant.subject !== subject : digest(grant.subject) !== subjectHash) ||
          !Array.isArray(grant.scopes) || !grant.scopes.includes(SCOPES.jarvis.ack) ||
          !Number.isSafeInteger(grant.expiresAt) || grant.expiresAt <= clock() ||
          !Number.isSafeInteger(grant.checkedAt) || grant.checkedAt < now - 30000 ||
          grant.checkedAt > now + 5000) return false;
      return owner === digest(JSON.stringify([ISSUER, resourceFor('jarvis'), grant.subject, 'jarvis']));
    } catch {
      // Never propagate provider errors, credentials, identities or raw claims.
      return false;
    }
  };
  Object.defineProperty(check, 'configured', { value: configured });
  return check;
}
