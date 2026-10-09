// Lookups against third-party reputation services. Each returns a Lookup so
// "we could not check" is never confused with "we checked and found nothing".

export type Lookup<T> =
  | { state: "found"; data: T }
  | { state: "not_found" }
  | { state: "not_configured" }
  | { state: "error"; reason: string };

type Fetch = typeof fetch;

const TIMEOUT_MS = 6000;
const UNREACHABLE = "The service did not respond.";

async function getJson(fetchFn: Fetch, url: string, init: RequestInit = {}) {
  const response = await fetchFn(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const body = response.ok ? await response.json() : null;
  return { status: response.status, body };
}

// ── Domain registration (RDAP, the successor to WHOIS; public, no key) ───────

export type Registration = {
  /** ISO date the domain was first registered, if published. */
  registeredAt: string | null;
  registrar: string | null;
  /** Owner name, only when the registry publishes it. Usually private. */
  registrant: string | null;
};

const RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;
let bootstrap: { loadedAt: number; servers: Map<string, string> } | null = null;

/** IANA's list of which RDAP server is authoritative for each domain ending. */
async function rdapServers(fetchFn: Fetch): Promise<Map<string, string>> {
  if (bootstrap && Date.now() - bootstrap.loadedAt < BOOTSTRAP_TTL_MS) return bootstrap.servers;
  const { body } = await getJson(fetchFn, RDAP_BOOTSTRAP);
  const servers = new Map<string, string>();
  for (const [endings, urls] of (body?.services ?? []) as [string[], string[]][]) {
    const base = urls.find((url) => url.startsWith("https://"));
    if (base) for (const ending of endings) servers.set(ending.toLowerCase(), base);
  }
  bootstrap = { loadedAt: Date.now(), servers };
  return servers;
}

type VcardField = [name: string, params: unknown, type: string, value: unknown];
type RdapEntity = { roles?: string[]; vcardArray?: [string, VcardField[]] };

const PRIVATE_OWNER = /redacted|privacy|private|protected|withheld|not disclosed|gdpr|proxy/i;

function entityName(entities: RdapEntity[], role: string): string | null {
  const entity = entities.find((candidate) => candidate.roles?.includes(role));
  const fields = entity?.vcardArray?.[1] ?? [];
  const field = fields.find(([name]) => name === "org") ?? fields.find(([name]) => name === "fn");
  const value = typeof field?.[3] === "string" ? field[3].trim() : "";
  return value && !PRIVATE_OWNER.test(value) ? value : null;
}

export async function lookupRegistration(
  domain: string,
  fetchFn: Fetch = fetch,
): Promise<Lookup<Registration>> {
  try {
    const server = (await rdapServers(fetchFn)).get(domain.split(".").pop() ?? "");
    if (!server) {
      return { state: "error", reason: "This domain ending has no public registration lookup." };
    }
    const { status, body } = await getJson(
      fetchFn,
      `${server}domain/${encodeURIComponent(domain)}`,
    );
    if (status === 404) return { state: "not_found" };
    if (!body) return { state: "error", reason: UNREACHABLE };

    const events = (body.events ?? []) as { eventAction?: string; eventDate?: string }[];
    const entities = (body.entities ?? []) as RdapEntity[];
    return {
      state: "found",
      data: {
        registeredAt:
          events.find((event) => event.eventAction === "registration")?.eventDate ?? null,
        registrar: entityName(entities, "registrar"),
        registrant: entityName(entities, "registrant"),
      },
    };
  } catch {
    return { state: "error", reason: UNREACHABLE };
  }
}

// ── Trustpilot (official Business Units API; needs TRUSTPILOT_API_KEY) ───────

export type TrustpilotProfile = {
  name: string;
  /** The domain Trustpilot files this business under. */
  identifyingName: string;
  /** 1 to 5. */
  trustScore: number;
  reviews: number;
  profileUrl: string;
};

const bareHost = (value: string) =>
  value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/[/?#].*$/, "");

export async function lookupTrustpilot(
  domain: string,
  apiKey = process.env.TRUSTPILOT_API_KEY,
  fetchFn: Fetch = fetch,
): Promise<Lookup<TrustpilotProfile>> {
  if (!apiKey) return { state: "not_configured" };
  try {
    const { status, body } = await getJson(
      fetchFn,
      `https://api.trustpilot.com/v1/business-units/find?name=${encodeURIComponent(domain)}`,
      { headers: { apikey: apiKey } },
    );
    if (status === 404) return { state: "not_found" };
    if (status === 401 || status === 403)
      return { state: "error", reason: "Trustpilot rejected the API key." };
    if (!body) return { state: "error", reason: UNREACHABLE };

    // Only accept a profile filed under this exact domain. A business with a
    // similar name on a different website tells us nothing about this one.
    const identifyingName = bareHost(String(body.name?.identifying ?? ""));
    const website = bareHost(String(body.websiteUrl ?? ""));
    if (identifyingName !== domain && website !== domain) return { state: "not_found" };

    return {
      state: "found",
      data: {
        name: String(body.displayName ?? identifyingName),
        identifyingName,
        trustScore: Number(body.score?.trustScore ?? 0),
        reviews: Number(body.numberOfReviews?.total ?? 0),
        profileUrl: `https://www.trustpilot.com/review/${encodeURIComponent(identifyingName)}`,
      },
    };
  } catch {
    return { state: "error", reason: UNREACHABLE };
  }
}

// ── Google Safe Browsing (Lookup API v4; needs GOOGLE_SAFE_BROWSING_API_KEY) ─

export type SafeBrowsingResult = { threats: string[] };

/** `urls` should already have query strings removed. An empty `threats` means not listed. */
export async function lookupSafeBrowsing(
  urls: string[],
  apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY,
  fetchFn: Fetch = fetch,
): Promise<Lookup<SafeBrowsingResult>> {
  if (!apiKey) return { state: "not_configured" };
  try {
    const { body } = await getJson(
      fetchFn,
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "phishguard", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: urls.map((url) => ({ url })),
          },
        }),
      },
    );
    if (!body) return { state: "error", reason: "Google Safe Browsing rejected the request." };
    const matches = (body.matches ?? []) as { threatType?: string }[];
    const threats = [...new Set(matches.map((match) => match.threatType ?? "UNKNOWN"))];
    return { state: "found", data: { threats } };
  } catch {
    return { state: "error", reason: UNREACHABLE };
  }
}

// ── VirusTotal (API v3 domain report; needs VIRUSTOTAL_API_KEY) ──────────────

export type VirusTotalResult = {
  malicious: number;
  suspicious: number;
  /** Vendors that analysed the domain at all. */
  total: number;
};

export async function lookupVirusTotal(
  domain: string,
  apiKey = process.env.VIRUSTOTAL_API_KEY,
  fetchFn: Fetch = fetch,
): Promise<Lookup<VirusTotalResult>> {
  if (!apiKey) return { state: "not_configured" };
  try {
    const { status, body } = await getJson(
      fetchFn,
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      { headers: { "x-apikey": apiKey } },
    );
    if (status === 404) return { state: "not_found" };
    if (status === 401 || status === 403)
      return { state: "error", reason: "VirusTotal rejected the API key." };
    if (status === 429)
      return { state: "error", reason: "VirusTotal's request limit was reached." };
    const stats = body?.data?.attributes?.last_analysis_stats as Record<string, number> | undefined;
    if (!stats) return { state: "error", reason: UNREACHABLE };
    const total = Object.values(stats).reduce((sum, count) => sum + (Number(count) || 0), 0);
    if (total === 0) return { state: "not_found" };
    return {
      state: "found",
      data: { malicious: stats.malicious ?? 0, suspicious: stats.suspicious ?? 0, total },
    };
  } catch {
    return { state: "error", reason: UNREACHABLE };
  }
}

/** Clears cached lookups. For tests. */
export function resetIntelCache() {
  bootstrap = null;
}
