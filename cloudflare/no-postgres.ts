// Worker build alias only: constructor injection is mandatory; no TCP/pg fallback.
export default { Pool: class { constructor() { throw Error('cloudflare_store_injection_required'); } } };
