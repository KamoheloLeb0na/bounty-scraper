#!/usr/bin/env node
/**
 * Bug Bounty Scope Aggregator
 * Scrapes: HackerOne, Bugcrowd, Intigriti
 * Filters: API, Android, Domain scopes
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// ============================================================================
// CACHE SYSTEM
// ============================================================================

class Cache {
  constructor(dir = '.cache') {
    this.dir = dir;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  key(platform) {
    return path.join(this.dir, `${platform}.json`);
  }

  valid(platform, ttl = 86400000) {
    const file = this.key(platform);
    if (!fs.existsSync(file)) return false;
    const age = Date.now() - fs.statSync(file).mtimeMs;
    return age < ttl;
  }

  get(platform) {
    const file = this.key(platform);
    if (fs.existsSync(file)) {
      try {
        return JSON.parse(fs.readFileSync(file, 'utf-8'));
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  set(platform, data) {
    fs.writeFileSync(this.key(platform), JSON.stringify(data));
  }
}

// ============================================================================
// WEB SCRAPER
// ============================================================================

class WebScraper {
  static fetch(url) {
    return new Promise((resolve) => {
      try {
        const urlObj = new URL(url);
        const client = urlObj.protocol === 'https:' ? https : http;
        
        const opts = {
          method: 'GET',
          timeout: 15000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Cache-Control': 'no-cache'
          }
        };

        client.request(url, opts, (res) => {
          if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
            const nextUrl = new URL(res.headers.location, url).toString();
            resolve(WebScraper.fetch(nextUrl));
            return;
          }

          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            resolve(res.statusCode >= 200 && res.statusCode < 300 ? data : '');
          });
        }).on('error', (err) => {
          resolve('');
        }).end();
      } catch (e) {
        resolve('');
      }
    });
  }

  static async fetchJson(url) {
    const body = await WebScraper.fetch(url);
    if (!body) return null;

    try {
      return JSON.parse(body);
    } catch (e) {
      return null;
    }
  }
}

// ============================================================================
// SCOPE DETECTION
// ============================================================================

const DATA_SOURCES = {
  hackerone: 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/hackerone_data.json',
  bugcrowd: 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/bugcrowd_data.json',
  intigriti: 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/intigriti_data.json'
};

function detectScopes(text) {
  if (!text) return [];
  const scopes = new Set();
  const str = text.toLowerCase();

  if (str.includes('api') || str.includes('rest') || str.includes('graphql') || str.includes('endpoint')) {
    scopes.add('api');
  }
  if (str.includes('android') || str.includes('apk') || str.includes('ios') || str.includes('mobile') || str.includes('app')) {
    scopes.add('android');
  }
  if (str.includes('domain') || str.includes('web') || str.includes('http') || str.includes('website') || str.includes('.com') || str.includes('.io')) {
    scopes.add('domain');
  }

  return Array.from(scopes);
}

function cachedPrograms(cache, platform) {
  if (!cache.valid(platform)) return null;

  const data = cache.get(platform);
  return Array.isArray(data) && data.length > 0 ? data : null;
}

function slug(value, fallback = 'program') {
  const normalized = String(value || fallback)
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  return normalized || fallback;
}

function compact(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function targetText(target) {
  return [
    target.asset_type,
    target.type,
    target.asset_identifier,
    target.target,
    target.endpoint,
    target.uri,
    target.name,
    target.instruction,
    target.description
  ].map(compact).filter(Boolean).join(' ');
}

function targetValue(target) {
  return compact(target.asset_identifier || target.target || target.endpoint || target.uri || target.name);
}

function scopesFromTargets(targets = {}) {
  const scopes = new Set();

  for (const target of targets.in_scope || []) {
    const type = compact(target.asset_type || target.type).toLowerCase();
    const text = targetText(target).toLowerCase();

    if (type.includes('api') || /\b(api|graphql|rest)\b/.test(text)) {
      scopes.add('api');
    }

    if (
      type.includes('android') ||
      type.includes('google_play') ||
      type.includes('apk') ||
      /\b(android|google play|apk)\b/.test(text)
    ) {
      scopes.add('android');
    }

    if (
      ['url', 'website', 'wildcard'].includes(type) ||
      type.includes('url') ||
      type.includes('website') ||
      type.includes('wildcard') ||
      /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i.test(targetValue(target)) ||
      /^https?:\/\//i.test(targetValue(target))
    ) {
      scopes.add('domain');
    }
  }

  return Array.from(scopes);
}

function sampleTargets(targets = {}, limit = 5) {
  return (targets.in_scope || [])
    .map(targetValue)
    .filter(Boolean)
    .slice(0, limit);
}

function normalizeProgram(program, platform) {
  const scopes = scopesFromTargets(program.targets);
  if (scopes.length === 0) return null;

  const handle = program.handle || slug(program.url || program.name);
  return {
    id: `${platform.toLowerCase()}-${handle || slug(program.name)}`,
    name: compact(program.name) || handle,
    platform,
    url: program.url,
    scopes,
    handle,
    targetCount: (program.targets && Array.isArray(program.targets.in_scope)) ? program.targets.in_scope.length : 0,
    sampleTargets: sampleTargets(program.targets)
  };
}

async function fetchPlatformData(key) {
  const data = await WebScraper.fetchJson(DATA_SOURCES[key]);
  if (!Array.isArray(data)) {
    throw new Error(`Could not fetch ${key} scope data`);
  }

  return data;
}

// ============================================================================
// SCRAPERS
// ============================================================================

async function scrapeHackerOne(cache) {
  console.log('  ⟳ HackerOne...');

  const cached = cachedPrograms(cache, 'hackerone');
  if (cached) return cached;

  const programs = [];
  try {
    const data = await fetchPlatformData('hackerone');

    for (const program of data) {
      const normalized = normalizeProgram(program, 'HackerOne');
      if (normalized) programs.push(normalized);
    }
    
    console.log(`    Found ${programs.length} programs`);
  } catch (e) {
    console.log(`    ⚠ Error: ${e.message}`);
  }

  cache.set('hackerone', programs);
  return programs;
}

async function scrapeBugcrowd(cache) {
  console.log('  ⟳ Bugcrowd...');

  const cached = cachedPrograms(cache, 'bugcrowd');
  if (cached) return cached;

  const programs = [];
  try {
    const data = await fetchPlatformData('bugcrowd');

    for (const program of data) {
      const normalized = normalizeProgram(program, 'Bugcrowd');
      if (normalized) programs.push(normalized);
    }
    
    console.log(`    Found ${programs.length} programs`);
  } catch (e) {
    console.log(`    ⚠ Error: ${e.message}`);
  }

  cache.set('bugcrowd', programs);
  return programs;
}

async function scrapeIntigriti(cache) {
  console.log('  ⟳ Intigriti...');

  const cached = cachedPrograms(cache, 'intigriti');
  if (cached) return cached;

  const programs = [];
  try {
    const data = await fetchPlatformData('intigriti');

    for (const program of data) {
      const normalized = normalizeProgram(program, 'Intigriti');
      if (normalized) programs.push(normalized);
    }
    
    console.log(`    Found ${programs.length} programs`);
  } catch (e) {
    console.log(`    ⚠ Error: ${e.message}`);
  }

  cache.set('intigriti', programs);
  return programs;
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log('\n🐛 Bug Bounty Scope Aggregator\n');
  console.log('Scraping platforms...');

  const cache = new Cache();
  const h1 = await scrapeHackerOne(cache);
  const bc = await scrapeBugcrowd(cache);
  const it = await scrapeIntigriti(cache);

  const all = [...h1, ...bc, ...it];

  // Save data
  fs.writeFileSync('data.json', JSON.stringify(all, null, 2));

  // Stats
  const api = all.filter(p => p.scopes.includes('api')).length;
  const android = all.filter(p => p.scopes.includes('android')).length;
  const domain = all.filter(p => p.scopes.includes('domain')).length;

  console.log('\n✓ Scraping complete\n');
  console.log(`Total programs: ${all.length}`);
  console.log(`  API: ${api}`);
  console.log(`  Android: ${android}`);
  console.log(`  Domain: ${domain}\n`);
}

main().catch(console.error);
