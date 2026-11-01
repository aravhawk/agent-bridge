import { ORIGIN } from '../../src/resource.ts';

// Nonsecret in-process fixture, not a deployed or guessed production issuer.
// A subdomain of the configured origin, so it also satisfies the optional
// issuer-under-origin constraint.
export const ISSUER = 'https://identity.' + new URL(ORIGIN).hostname;
