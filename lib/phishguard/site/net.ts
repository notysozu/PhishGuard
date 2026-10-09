import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";

// Outbound requests to addresses a user supplied. Everything here exists to
// stop the server being used to reach private networks (SSRF): only public
// addresses, only http(s) on default ports, headers only, never a body.

const blocked = new net.BlockList();
const IPV4_BLOCKED: [string, number][] = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, cloud metadata
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 3], // multicast and reserved
];
const IPV6_BLOCKED: [string, number][] = [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96], // NAT64
  ["100::", 64],
  ["2001:db8::", 32],
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["ff00::", 8], // multicast
];
for (const [address, prefix] of IPV4_BLOCKED) blocked.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of IPV6_BLOCKED) blocked.addSubnet(address, prefix, "ipv6");

/** True for an IP address on the public internet. IPv4-mapped IPv6 is checked as IPv4. */
export function isPublicAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 0) return false;
  return !blocked.check(address, family === 4 ? "ipv4" : "ipv6");
}

/** Thrown when a link is refused before any request is made. */
export class BlockedUrlError extends Error {}

/** Checks a URL is one we are willing to request. Throws BlockedUrlError if not. */
export function assertRequestable(url: URL): void {
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new BlockedUrlError("Only http and https links are opened.");
  if (url.username || url.password)
    throw new BlockedUrlError("Links with embedded credentials are not opened.");
  if (url.port) throw new BlockedUrlError("Links to non-standard ports are not opened.");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host) && !isPublicAddress(host))
    throw new BlockedUrlError("The link points to a private or internal address.");
}

// Runs at connection time, so a hostname cannot pass a check and then
// resolve somewhere else (DNS rebinding).
const guardedLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (error, addresses) => {
    if (error) return callback(error, []);
    if (!addresses.length || addresses.some((entry) => !isPublicAddress(entry.address))) {
      const refusal = new BlockedUrlError("The link points to a private or internal address.");
      return callback(refusal as NodeJS.ErrnoException, []);
    }
    if (options.all) callback(null, addresses);
    else callback(null, addresses[0].address, addresses[0].family);
  });
};

export type HeadResponse = { status: number; location: string | null };
export type HeadRequest = (url: URL) => Promise<HeadResponse>;

/**
 * Sends one HEAD request and returns the status and Location header. HEAD is
 * used so that nothing is downloaded and the request is as inert as possible.
 */
export const headRequest: HeadRequest = (url) =>
  new Promise((resolve, reject) => {
    try {
      assertRequestable(url);
    } catch (error) {
      return reject(error);
    }
    const client = url.protocol === "https:" ? https : http;
    const request = client.request(
      url,
      {
        method: "HEAD",
        lookup: guardedLookup,
        agent: false,
        timeout: 4000,
        headers: { "User-Agent": "PhishGuard-LinkCheck/1.0", Accept: "*/*" },
      },
      (response) => {
        const location = response.headers.location ?? null;
        resolve({ status: response.statusCode ?? 0, location });
        response.resume();
        request.destroy();
      },
    );
    request.on("timeout", () =>
      request.destroy(new Error("The website took too long to respond.")),
    );
    request.on("error", reject);
    request.end();
  });
