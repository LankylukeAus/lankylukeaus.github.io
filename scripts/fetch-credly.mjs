/**
 * Refresh assets/credly.json from Luke's public Credly profile.
 *
 * No token is required: only badges explicitly published on the public profile
 * are copied. Existing data is preserved if Credly is unavailable or returns an
 * unexpected response.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const PROFILE = 'luke-gerritsen';
const OUT = 'assets/credly.json';
const URL = `https://www.credly.com/users/${PROFILE}/badges.json`;

try {
  const response = await fetch(URL, {
    headers: {
      Accept: 'application/json',
      'User-Agent': 'lanky-portfolio-credly-sync/1.0',
    },
  });

  if (!response.ok) throw new Error(`Credly returned HTTP ${response.status}`);

  const body = await response.json();
  if (!Array.isArray(body.data)) throw new Error('Credly response did not contain a badge list');

  const badges = body.data
    .filter((badge) => badge.public !== false && badge.state === 'accepted')
    .map((badge) => {
      const template = badge.badge_template || {};
      const issuer = badge.issuer?.entities?.find((item) => item.primary)?.entity
        || badge.issuer?.entities?.[0]?.entity
        || {};
      return {
        id: badge.id,
        name: template.name || 'Credly badge',
        issuer: issuer.name || 'Credly',
        issued: badge.issued_at_date || badge.issued_at || null,
        expires: badge.expires_at_date || badge.expires_at || null,
        image: template.image_url || null,
        url: `https://www.credly.com/badges/${badge.id}`,
      };
    })
    .filter((badge) => badge.id && badge.image)
    .sort((a, b) => String(b.issued || '').localeCompare(String(a.issued || '')));

  if (!badges.length && existsSync(OUT)) {
    throw new Error('Credly returned no public accepted badges; preserving existing data');
  }

  const output = {
    profile: `https://www.credly.com/users/${PROFILE}`,
    updated: new Date().toISOString(),
    count: badges.length,
    badges,
  };

  writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');
  console.log(`Synced ${badges.length} public Credly badge(s) to ${OUT}`);
} catch (error) {
  console.warn(`Credly sync skipped: ${error.message}`);
  if (!existsSync(OUT)) process.exitCode = 1;
}
