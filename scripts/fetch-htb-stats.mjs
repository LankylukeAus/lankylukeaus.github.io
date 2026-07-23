/**
 * Refresh assets/stats.json from the Hack The Box API.
 *
 * Run by .github/workflows/update-stats.yml on a schedule. The HTB token comes
 * from the HTB_TOKEN repo secret and never reaches the published site: this
 * script writes only derived numbers into assets/stats.json, which the page
 * fetches same-origin on load.
 *
 * Design notes:
 *  - Merges into the existing stats.json. If an endpoint fails or a field is
 *    missing we keep the previous value rather than blanking the page.
 *  - Logs every request status so a failing endpoint is obvious in the run log.
 *
 * Env: HTB_TOKEN (required), HTB_USER_ID (default 677735)
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const TOKEN = process.env.HTB_TOKEN;
const USER_ID = process.env.HTB_USER_ID || '677735';
const OUT = 'assets/stats.json';
const API = 'https://labs.hackthebox.com/api/v4';

if (!TOKEN) {
  // Skip quietly rather than failing the scheduled run every few hours.
  console.log('HTB_TOKEN is not set — skipping refresh (add it as a repo secret to enable).');
  process.exit(0);
}

const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: 'application/json',
  'User-Agent': 'lanky-portfolio-stats/1.0',
};

async function get(path) {
  const url = API + path;
  try {
    const r = await fetch(url, { headers, redirect: 'manual' });
    const status = r.status;
    diag.endpoints[path] = status;
    if (status !== 200) {
      console.log(`  [${status}] ${path}`);
      return null;
    }
    const body = await r.json();
    const keys = Object.keys(body);
    diag.discovered[path] = keys;
    // one level deeper for wrapper objects, to reveal real field names
    if (body.profile) diag.discovered[path + '.profile'] = Object.keys(body.profile);
    if (body.data && !Array.isArray(body.data)) diag.discovered[path + '.data'] = Object.keys(body.data);
    console.log(`  [200] ${path}  keys=${keys.join(',').slice(0, 90)}`);
    return body;
  } catch (e) {
    diag.endpoints[path] = 'ERR:' + e.message;
    console.log(`  [ERR] ${path}  ${e.message}`);
    return null;
  }
}

const pick = (...vals) => vals.find((v) => v !== undefined && v !== null && v !== '');

const prev = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : { htb: {} };
const htb = { ...(prev.htb || {}) };
// Diagnostics get written into the (public) stats.json so the field mapping can
// be verified from the published file, without needing the private run logs.
const diag = { endpoints: {}, discovered: {} };

console.log(`Fetching HTB data for user ${USER_ID}...`);

// --- core profile -----------------------------------------------------------
const basic = await get(`/user/profile/basic/${USER_ID}`);
const p = basic?.profile ?? basic ?? {};
if (Object.keys(p).length) {
  htb.level = pick(p.current_rank_progress !== undefined ? p.level : undefined, p.level, htb.level);
  htb.hacker_rank = pick(p.rank, htb.hacker_rank);
  htb.global = pick(p.ranking != null ? `#${p.ranking}` : undefined, htb.global);
  htb.machines = pick(p.system_owns, htb.machines);
  htb.user_owns = pick(p.user_owns, htb.user_owns);
  htb.points = pick(p.points, htb.points);
}

// --- season -----------------------------------------------------------------
const seasons = await get('/season/list');
const active = Array.isArray(seasons?.data)
  ? seasons.data.find((s) => s.active || s.state === 'active') || seasons.data.at(-1)
  : null;
if (active?.id) {
  htb.season_name = pick(active.name, htb.season_name);
  const rank = await get(`/season/user/rank/${active.id}`);
  const d = rank?.data ?? {};
  htb.tier = pick(d.tier, d.league, htb.tier);
  htb.points = pick(d.total_season_points, d.points, htb.points);
  htb.global = pick(d.rank != null ? `#${d.rank}` : undefined, htb.global);
  if (d.flags_owned != null && d.total_flags != null) {
    htb.flags = `${d.flags_owned}/${d.total_flags}`;
  }
}

// --- derived display strings ------------------------------------------------
if (htb.level && htb.tier && htb.season_name) {
  htb.subline = `<b>◆ Professional</b> · Level ${htb.level} · ${htb.season_name} ${htb.tier}`;
}

const out = { ...prev, updated: new Date().toISOString(), htb, _diag: diag };
writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');

console.log('\nResult written to ' + OUT + ':');
console.log(JSON.stringify(out, null, 2));
