import assert from "node:assert/strict";
import { test } from "node:test";
import {
  BlockedUrlError,
  assertRequestable,
  headRequest,
  isPublicAddress,
} from "../lib/phishguard/site/net";

test("private, loopback, link-local and metadata addresses are not public", () => {
  const internal = [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata service
    "100.64.0.1",
    "0.0.0.0",
    "224.0.0.1",
    "255.255.255.255",
    "::1",
    "::",
    "fc00::1",
    "fd12:3456::1",
    "fe80::1",
    "ff02::1",
  ];
  for (const address of internal) assert.equal(isPublicAddress(address), false, address);
});

test("IPv4 addresses written as IPv6 are still recognised as internal", () => {
  assert.equal(isPublicAddress("::ffff:127.0.0.1"), false);
  assert.equal(isPublicAddress("::ffff:7f00:1"), false);
  assert.equal(isPublicAddress("::ffff:10.0.0.1"), false);
  assert.equal(isPublicAddress("::ffff:8.8.8.8"), true);
});

test("ordinary internet addresses are public; non-addresses are not", () => {
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("172.32.0.1"), true, "just outside 172.16/12");
  assert.equal(isPublicAddress("2606:4700:4700::1111"), true);
  assert.equal(isPublicAddress("example.com"), false);
  assert.equal(isPublicAddress(""), false);
});

test("only plain http(s) links on default ports are requestable", () => {
  const refused = [
    "ftp://example.com/file",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "https://user:pass@example.com/",
    "http://example.com:8080/",
    "http://example.com:22/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://2130706433/", // 127.0.0.1 as a decimal number
    "http://0x7f.0.0.1/", // 127.0.0.1 in hex
    "http://169.254.169.254/latest/meta-data/",
  ];
  for (const address of refused) {
    assert.throws(() => assertRequestable(new URL(address)), BlockedUrlError, address);
  }
  assert.doesNotThrow(() => assertRequestable(new URL("https://example.com/path?x=1")));
  assert.doesNotThrow(() => assertRequestable(new URL("http://8.8.8.8/")));
});

test("headRequest refuses an internal address before connecting", async () => {
  await assert.rejects(headRequest(new URL("http://127.0.0.1/admin")), BlockedUrlError);
  await assert.rejects(headRequest(new URL("http://10.0.0.5/")), BlockedUrlError);
});

test("a hostname that resolves to an internal address is refused at connection time", async () => {
  // "localhost" resolves to loopback without any network access.
  await assert.rejects(headRequest(new URL("http://localhost/")), BlockedUrlError);
});
