import { pathToFileURL } from 'node:url';

const PROFILE_ORIGIN = 'https://www.snapchat.com';
const MEDIA_ORIGIN = 'https://cf-st.sc-cdn.net';
const PROFILE_LIMIT = 1024 * 1024;
const MEDIA_PREFIX = 4096;
const MEDIA_LIMIT = 50 * 1024 * 1024;
const MAX_ENTRIES = 30;

class ProbeError extends Error {}

function requireProbe(condition, code) {
  if (!condition) throw new ProbeError(code);
}

function dateTime(value) {
  requireProbe(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(value), 'invalid_time');
  const epoch = Date.parse(value);
  const wall = value.slice(0, 19);
  const utc = Date.parse(`${wall}Z`);
  requireProbe(Number.isFinite(epoch) && Number.isFinite(utc) && new Date(utc).toISOString().slice(0, 19) === wall, 'invalid_time');
  return epoch;
}

async function readPrefix(response, limit) {
  requireProbe(response.body, 'empty_response');
  const reader = response.body.getReader();
  const parts = [];
  let size = 0;
  try {
    while (size < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      const part = value.subarray(0, limit - size);
      parts.push(part);
      size += part.length;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(parts, size);
}

async function loadProfile(username, get) {
  const start = new URL(`/add/${username}`, PROFILE_ORIGIN);
  const canonical = new URL(`/@${username}`, PROFILE_ORIGIN);
  const redirect = await get(start);
  const location = redirect.headers.get('location');
  await redirect.body?.cancel();
  requireProbe([301, 302, 303, 307, 308].includes(redirect.status) && location, 'profile_redirect_missing');
  requireProbe(new URL(location, start).href === canonical.href, 'profile_redirect_rejected');

  const page = await get(canonical);
  if (page.status !== 200 || !page.headers.get('content-type')?.startsWith('text/html')) {
    await page.body?.cancel();
    throw new ProbeError('profile_unavailable');
  }
  const markup = await readPrefix(page, PROFILE_LIMIT + 1);
  requireProbe(markup.length <= PROFILE_LIMIT, 'profile_size_exceeded');
  const payload = markup.toString('utf8').match(/<script id="__NEXT_DATA__" type="application\/json">([^<]+)<\/script>/)?.[1];
  requireProbe(payload, 'profile_schema_changed');
  const profile = JSON.parse(payload)?.props?.pageProps;
  requireProbe(profile?.userProfile?.publicProfileInfo?.username?.toLowerCase() === username, 'profile_identity_unverified');
  return profile;
}

function mediaSignature(bytes, type) {
  switch (type) {
    case 'video/mp4': return bytes.subarray(4, 8).toString('ascii') === 'ftyp';
    case 'image/jpeg': return bytes.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]));
    case 'image/png': return bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    case 'image/webp': return bytes.subarray(0, 4).toString('ascii') === 'RIFF'
      && bytes.subarray(8, 12).toString('ascii') === 'WEBP';
    default: return false;
  }
}

async function checkMedia(entry, get) {
  const rawUrl = entry.snapUrls?.mediaUrl;
  requireProbe(typeof rawUrl === 'string' && rawUrl.length <= 4096 && !/[\s\x00-\x1f\x7f]/.test(rawUrl), 'media_url_rejected');
  const url = new URL(rawUrl);
  requireProbe(url.origin === MEDIA_ORIGIN && !url.username && !url.password && !url.hash, 'media_url_rejected');
  const response = await get(url, { range: `bytes=0-${MEDIA_PREFIX - 1}` });
  try {
    const contentType = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
    requireProbe(entry.snapMediaType === 1 ? contentType === 'video/mp4' : contentType?.startsWith('image/'), 'media_type_unexpected');
    const range = response.headers.get('content-range')?.match(/^bytes 0-(\d+)\/(\d+)$/);
    const total = Number(range?.[2]);
    requireProbe(response.status === 206 && Number.isSafeInteger(total) && total > 0 && total <= MEDIA_LIMIT, 'media_range_unverified');
    const expected = Math.min(total, MEDIA_PREFIX);
    requireProbe(Number(range[1]) + 1 === expected, 'media_range_unverified');
    const prefix = await readPrefix(response, expected + 1);
    requireProbe(prefix.length === expected && mediaSignature(prefix, contentType), 'media_signature_unverified');
  } finally {
    if (response.body && !response.body.locked) await response.body.cancel().catch(() => {});
  }
}

export async function probe(username, from, until, fetchImpl = fetch) {
  requireProbe(typeof username === 'string' && /^[a-z0-9][a-z0-9._-]{1,30}$/i.test(username), 'invalid_username');
  const start = dateTime(from);
  const end = dateTime(until);
  requireProbe(end > start && end - start <= 86_400_000, 'invalid_time_window');
  const deadline = Date.now() + 30_000;
  const get = (url, headers = {}) => {
    const remaining = deadline - Date.now();
    requireProbe(remaining > 0, 'probe_timeout');
    return fetchImpl(url, {
      method: 'GET', redirect: 'manual', credentials: 'omit',
      headers: { 'cache-control': 'no-cache', 'accept-encoding': 'identity', ...headers },
      signal: AbortSignal.timeout(Math.min(8000, remaining)),
    });
  };

  const profile = await loadProfile(username.toLowerCase(), get);
  const story = profile.story;
  const records = story == null ? [] : story.snapList;
  requireProbe(Array.isArray(records) && records.length <= 500, 'story_schema_changed');
  const matching = records.map((entry) => {
    const seconds = Number(entry?.timestampInSec?.value);
    requireProbe(Number.isSafeInteger(seconds) && seconds > 0 && seconds < 100_000_000_000, 'story_timestamp_unverified');
    return { entry, milliseconds: seconds * 1000 };
  }).filter(({ milliseconds }) => milliseconds >= start && milliseconds < end);
  requireProbe(matching.length <= MAX_ENTRIES, 'too_many_matches');

  const entries = [];
  for (const { entry, milliseconds } of matching) {
    requireProbe(entry.snapMediaType === 0 || entry.snapMediaType === 1, 'media_type_unexpected');
    await checkMedia(entry, get);
    entries.push({ time_utc: new Date(milliseconds).toISOString(), media: entry.snapMediaType === 1 ? 'video' : 'image' });
  }
  return {
    status: entries.length ? 'public_media_prefix_verified' : 'no_public_story_entries_in_window',
    profile_verified: true,
    match_count: entries.length,
    entries,
    platform_post_id_linkage: 'unverified_no_public_mapping',
  };
}

// Public storyId.value, snapId.value, and optional storyShareId are distinct
// fields. The current public payload exposes no provider platformPostId mapping.
// This read verifies visibility and a first-party media signature, not content
// identity, audio, full playback, or a specific provider publication event.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node public_story_probe.mjs USERNAME FROM_ISO UNTIL_ISO');
    console.log('Use a timezone offset or Z. The window includes FROM and excludes UNTIL.');
  } else {
    try {
      requireProbe(args.length === 3, 'invalid_arguments');
      console.log(JSON.stringify(await probe(...args)));
    } catch (error) {
      // Never print remote response bodies, URLs, account IDs or exception stacks.
      console.log(JSON.stringify({ status: 'unverified', reason: error instanceof ProbeError ? error.message : 'network_or_schema_error' }));
      process.exitCode = 1;
    }
  }
}
