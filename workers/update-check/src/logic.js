// The pure part of the update-check Worker: request parsing, pointer
// validation and the data point. index.js binds it to the platform.

/** The channels the bucket publishes pointers for. Anything else is a 404. */
export const CHANNELS = new Set(["stable", "unstable", "nightly"]);

/** Where the channel pointers live; `<base><channel>` is a text file holding the key. */
export const POINTER_BASE = "https://storage.googleapis.com/minimal-one/";

/** How long an edge keeps a pointer. A promotion is seen within this. */
export const POINTER_CACHE_SECONDS = 300;

// A key, os, arch or install value: the installer's own charset for a
// target or version. Bounded so a data point stays small.
const TOKEN = /^[A-Za-z0-9._-]{1,64}$/;
// The install id the client mints: a UUID, any version.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Parses `GET /v1/<channel>/<key>?os&arch&install&id`. Returns the eight
 * request fields, or null when anything is off: wrong shape, a channel
 * outside the allow-list, a value outside its charset, a missing field.
 * Nothing about a refused request is recorded.
 */
export function parseRequest(url) {
  const u = url instanceof URL ? url : new URL(url);
  const parts = u.pathname.split("/");
  // ["", "v1", channel, key]
  if (parts.length !== 4 || parts[0] !== "" || parts[1] !== "v1") return null;
  const [, , channel, key] = parts;
  if (!CHANNELS.has(channel) || !TOKEN.test(key)) return null;
  const os = u.searchParams.get("os");
  const arch = u.searchParams.get("arch");
  const install = u.searchParams.get("install");
  const id = u.searchParams.get("id");
  for (const v of [os, arch, install]) if (v === null || !TOKEN.test(v)) return null;
  if (id === null || !UUID.test(id)) return null;
  return { channel, key, os, arch, install, id: id.toLowerCase() };
}

/**
 * The channel's current pointer, through `fetchFn` (the platform fetch, with
 * the edge cache asked for). `null` when the bucket does not answer or the
 * file is not a key: a bad pointer must never reach a client as "latest".
 */
export async function latestFor(channel, fetchFn) {
  if (!CHANNELS.has(channel)) return null;
  let resp;
  try {
    resp = await fetchFn(POINTER_BASE + channel, {
      cf: { cacheTtl: POINTER_CACHE_SECONDS, cacheEverything: true },
    });
  } catch {
    return null;
  }
  if (!resp || !resp.ok) return null;
  const text = (await resp.text()).trim();
  return TOKEN.test(text) ? text : null;
}

/**
 * Whether `key` is the channel's current pointer. The installer records the
 * pointer it installed as the key, so on stable that is a version (`0.7.1`)
 * and on unstable and nightly a short commit hash (`5a93a07a`), and equality
 * is the test. A build with no install record sends the hash its version
 * string embeds; a client that sent the whole version string instead
 * (`0.7.2-dev.12.g5a93a07a`) is still up to date when its `g<hash>` suffix
 * is the pointer.
 */
export function upToDate(key, latest) {
  return key === latest || key.endsWith(`.g${latest}`);
}

/**
 * The data point for one answered request: the eight fields, then what the
 * edge knows of where it came from (country, ASN). Not the address. The
 * install id is the index, so `count(DISTINCT blob1)` is the install count.
 */
export function dataPoint(fields, cf) {
  const country = (cf && cf.country) || "";
  const asn = cf && cf.asn !== undefined && cf.asn !== null ? String(cf.asn) : "";
  return {
    blobs: [fields.id, fields.channel, fields.key, fields.os, fields.arch, fields.install, country, asn],
    doubles: [upToDate(fields.key, fields.latest) ? 1 : 0],
    indexes: [fields.id],
  };
}

/**
 * Handles one request against `env` (the Analytics Engine binding) using
 * `fetchFn` for the pointer and `cf` for the request's edge metadata.
 * Returns a Response. Every refusal is a bare status with no body of note.
 */
export async function handle(request, env, fetchFn, cf) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response(null, { status: 405, headers: { Allow: "GET, HEAD" } });
  }
  const fields = parseRequest(request.url);
  if (fields === null) return new Response(null, { status: 404 });
  const latest = await latestFor(fields.channel, fetchFn);
  if (latest === null) return new Response(null, { status: 503, headers: { "Retry-After": "300" } });
  // Only a GET is a check. A HEAD is a probe (an uptime monitor, a link
  // checker) and is answered without a data point, so probes never count
  // as installs.
  if (request.method === "GET" && env && env.UPDATE_CHECKS && typeof env.UPDATE_CHECKS.writeDataPoint === "function") {
    try {
      env.UPDATE_CHECKS.writeDataPoint(dataPoint({ ...fields, latest }, cf));
    } catch {
      // A sink that refuses the point does not refuse the answer.
    }
  }
  const body = JSON.stringify({ channel: fields.channel, latest });
  return new Response(request.method === "HEAD" ? null : body, {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
