#!/usr/bin/env node
// Prints, and never performs, the QStash schedule request for the bridge's
// scheduled tick. Dry run only: this script has no network code, reads no
// token or signing key, and creates, changes or activates nothing. Creating
// the schedule is a separate operator action (see docs/scheduler.md).
//
//   node scripts/qstash-schedule-plan.mjs --dry-run --destination https://<host>/api/cron
import { QSTASH_TICK_BODY } from '../src/qstash.mjs';

const args = process.argv.slice(2);
const usage = message => { process.stderr.write(`${message}\nusage: qstash-schedule-plan.mjs --dry-run --destination https://<host>/api/cron\n`); process.exit(2); };
if (!args.includes('--dry-run')) usage('refusing to run: only --dry-run is supported');
// The destination must be exactly https://<lowercase DNS name>/api/cron. WHATWG
// URL parsing alone is not enough: it accepts hosts such as `$(id)` or a
// backquoted command, which a shell would run if the template were copied.
// Only letters, digits, '-' and '.' are allowed in the host, and the
// destination is still single-quoted in the template below.
const DNS_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const at = args.indexOf('--destination'), destination = at >= 0 ? args[at + 1] : undefined;
let url = null;
try { url = new URL(destination); } catch { /* refused below */ }
if (!url || !DNS_NAME.test(url.hostname) || destination !== `https://${url.hostname}/api/cron`) {
  usage('--destination must be exactly https://<dns-name>/api/cron');
}

// Every 5 minutes (UTC); the bridge decides what is due (Chicago even hours,
// the 2 h maximum wait, expiry) and reconciles overdue outbox work, so extra
// or late ticks are harmless no-ops.
const CRON = '*/5 * * * *', RETRIES = 2;
const ticksPerDay = 24 * 60 / 5, attemptsPerTick = 1 + RETRIES;
const headers = {
  Authorization: 'Bearer $QSTASH_TOKEN',
  'Content-Type': 'application/json',
  'Upstash-Cron': CRON,
  'Upstash-Schedule-Id': 'bridge-tick-5m',
  'Upstash-Method': 'POST',
  'Upstash-Retries': String(RETRIES),
  // Milliseconds; 15 s then 30 s, well inside the 5-minute tick interval.
  'Upstash-Retry-Delay': 'min(60000, pow(2, retried) * 15000)',
  'Upstash-Timeout': '60s',
  'Upstash-Label': 'bridge-tick',
};
const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const plan = {
  dryRun: true,
  note: 'Nothing was sent. Review the plan before running the curl command to create or update the schedule.',
  request: { method: 'POST', url: `$QSTASH_URL/v2/schedules/${destination}`, headers, body: QSTASH_TICK_BODY },
  curl: ['curl --fail-with-body --proto =https -X POST', ...Object.entries(headers).map(([k, v]) =>
    k === 'Authorization' ? `-H "Authorization: Bearer $QSTASH_TOKEN"` : `-H ${quote(`${k}: ${v}`)}`),
  // Only $QSTASH_URL is expanded by the shell; the destination is a separate,
  // single-quoted literal word joined to it.
  `--data ${quote(QSTASH_TICK_BODY)}`, `"$QSTASH_URL/v2/schedules/"${quote(destination)}`].join(' \\\n  '),
  budget: {
    ticksPerDay, ticksPer30Days: ticksPerDay * 30,
    maxAttemptsPerDay: ticksPerDay * attemptsPerTick, maxAttemptsPer30Days: ticksPerDay * 30 * attemptsPerTick,
    usdPer100kAttempts: 1,
    maxUsdPer30Days: Math.ceil(ticksPerDay * 30 * attemptsPerTick / 100000 * 100) / 100,
  },
  bridgeEnvironment: ['QSTASH_CURRENT_SIGNING_KEY', 'QSTASH_NEXT_SIGNING_KEY', 'BRIDGE_QSTASH_DESTINATION_URL'],
};
process.stdout.write(JSON.stringify(plan, null, 2) + '\n');
