import { test } from "node:test";
import assert from "node:assert/strict";
import { CHANNELS, POINTER_BASE, dataPoint, handle, latestFor, parseRequest, upToDate } from "../src/logic.js";

const good = "https://update.minimal.dev/v1/stable/0.7.1?os=linux&arch=x86_64&install=installer&id=d66d041a-66bc-43f9-97c2-09f071ae7686";

test("a well-formed request parses into its eight fields", () => {
  assert.deepEqual(parseRequest(good), {
    channel: "stable",
    key: "0.7.1",
    os: "linux",
    arch: "x86_64",
    install: "installer",
    id: "d66d041a-66bc-43f9-97c2-09f071ae7686",
  });
});

test("the channel allow-list, the charsets and the shape each refuse", () => {
  const bad = [
    good.replace("/stable/", "/source/"),
    good.replace("/stable/", "/pinned/"),
    good.replace("/v1/", "/v2/"),
    good.replace("0.7.1", "0.7.1/extra"),
    good.replace("0.7.1", "..%2F"),
    good.replace("os=linux", "os=linux;drop"),
    good.replace("&id=d66d041a-66bc-43f9-97c2-09f071ae7686", "&id=not-a-uuid"),
    good.replace("&id=d66d041a-66bc-43f9-97c2-09f071ae7686", ""),
    good.replace("&install=installer", ""),
    "https://update.minimal.dev/",
  ];
  for (const url of bad) assert.equal(parseRequest(url), null, url);
  assert.deepEqual([...CHANNELS].sort(), ["nightly", "stable", "unstable"]);
});

const pointer = (body, ok = true) => async (url, init) => {
  assert.ok(url.startsWith(POINTER_BASE), url);
  assert.deepEqual(init.cf.cacheTtlByStatus, { "200-299": 300, "400-599": 0 }, "a pointer is cached, a bucket error is not");
  return { ok, text: async () => body };
};

test("the pointer is read from the bucket through the edge cache and validated", async () => {
  assert.equal(await latestFor("stable", pointer("0.7.2\n")), "0.7.2");
  assert.equal(await latestFor("nightly", pointer("5a93a07a")), "5a93a07a");
  assert.equal(await latestFor("stable", pointer("<html>oops</html>")), null);
  assert.equal(await latestFor("stable", pointer("", false)), null);
  assert.equal(await latestFor("stable", async () => { throw new Error("down"); }), null);
  assert.equal(await latestFor("source", pointer("x")), null);
});

test("an answered request records the eight fields plus country and ASN, never the address", async () => {
  const points = [];
  const env = { UPDATE_CHECKS: { writeDataPoint: (p) => points.push(p) } };
  const resp = await handle(new Request(good), env, pointer("0.7.2"), { country: "DE", asn: 3320, ip: "203.0.113.9" });
  assert.equal(resp.status, 200);
  assert.equal(resp.headers.get("Cache-Control"), "no-store");
  assert.deepEqual(await resp.json(), { channel: "stable", latest: "0.7.2" });
  assert.equal(points.length, 1);
  assert.deepEqual(points[0].blobs, [
    "d66d041a-66bc-43f9-97c2-09f071ae7686", "stable", "0.7.1", "linux", "x86_64", "installer", "DE", "3320",
  ]);
  assert.deepEqual(points[0].indexes, ["d66d041a-66bc-43f9-97c2-09f071ae7686"]);
  assert.deepEqual(points[0].doubles, [0], "0.7.1 is behind 0.7.2");
  assert.ok(!JSON.stringify(points[0]).includes("203.0.113.9"), "no address in the point");
});

test("up to date is the pointer itself, or the hash a version string embeds", () => {
  assert.equal(upToDate("0.7.1", "0.7.1"), true, "stable: the version");
  assert.equal(upToDate("5a93a07a", "5a93a07a"), true, "unstable and nightly: the short hash the installer recorded");
  assert.equal(upToDate("0.7.2-dev.12.g5a93a07a", "5a93a07a"), true, "a whole version string with that hash");
  assert.equal(upToDate("0.7.1", "0.7.2"), false);
  assert.equal(upToDate("0.7.2-dev.12.g5a93a07a", "e8f53f6e"), false);
  assert.equal(upToDate("5a93a07a", "0.7.1"), false, "a hash never equals a version");
});

test("a HEAD is answered without a data point", async () => {
  const points = [];
  const env = { UPDATE_CHECKS: { writeDataPoint: (p) => points.push(p) } };
  const resp = await handle(new Request(good, { method: "HEAD" }), env, pointer("0.7.2"), { country: "DE", asn: 1 });
  assert.equal(resp.status, 200);
  assert.equal(points.length, 0, "a probe is not an install");
});

test("an up-to-date install is marked so in the point", () => {
  const p = dataPoint({ id: "i", channel: "stable", key: "0.7.2", latest: "0.7.2", os: "o", arch: "a", install: "x" }, undefined);
  assert.deepEqual(p.doubles, [1]);
  assert.deepEqual(p.blobs.slice(6), ["", ""], "no edge metadata, empty strings");
});

test("a refused request is a 404 with nothing recorded; a missing pointer is a 503", async () => {
  const points = [];
  const env = { UPDATE_CHECKS: { writeDataPoint: (p) => points.push(p) } };
  const r404 = await handle(new Request(good.replace("/stable/", "/beta/")), env, pointer("0.7.2"), {});
  assert.equal(r404.status, 404);
  const r503 = await handle(new Request(good), env, pointer("", false), {});
  assert.equal(r503.status, 503);
  assert.equal(r503.headers.get("Retry-After"), "300");
  const r405 = await handle(new Request(good, { method: "POST" }), env, pointer("0.7.2"), {});
  assert.equal(r405.status, 405);
  assert.equal(points.length, 0);
});

test("a sink that throws does not refuse the answer", async () => {
  const env = { UPDATE_CHECKS: { writeDataPoint: () => { throw new Error("quota"); } } };
  const resp = await handle(new Request(good), env, pointer("0.7.2"), {});
  assert.equal(resp.status, 200);
});
