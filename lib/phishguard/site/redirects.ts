import { BlockedUrlError, headRequest, type HeadRequest } from "./net";

const MAX_HOPS = 6;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export type RedirectTrace = {
  /** False when not even the first address could be requested. */
  followed: boolean;
  /** Every address requested, starting with the input. */
  chain: string[];
  /** The last address reached. Equals the input when nothing was followed. */
  finalUrl: string;
  /** Why tracing stopped early, in words the user can read. */
  note?: string;
};

/**
 * Follows a link's HTTP redirects with HEAD requests and reports where it
 * ends up. Redirects done by scripts or page content are not followed,
 * because no page is ever downloaded or run.
 */
export async function traceRedirects(
  start: string,
  request: HeadRequest = headRequest,
): Promise<RedirectTrace> {
  const chain = [start];
  let current: URL;
  try {
    current = new URL(start);
  } catch {
    return { followed: false, chain, finalUrl: start, note: "This is not a valid web address." };
  }

  let followed = false;
  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    let response;
    try {
      response = await request(current);
    } catch (error) {
      const note =
        error instanceof BlockedUrlError
          ? `${error.message} It was not opened.`
          : "The website did not respond, so the link could not be followed.";
      return { followed, chain, finalUrl: current.href, note };
    }
    followed = true;

    if (!REDIRECT_STATUSES.has(response.status) || !response.location) {
      return { followed, chain, finalUrl: current.href };
    }
    let next: URL;
    try {
      next = new URL(response.location, current);
    } catch {
      return { followed, chain, finalUrl: current.href, note: "A redirect was malformed." };
    }
    if (chain.includes(next.href)) {
      return { followed, chain, finalUrl: current.href, note: "The link redirects in a loop." };
    }
    chain.push(next.href);
    current = next;
  }
  return {
    followed,
    chain,
    finalUrl: current.href,
    note: `Stopped after ${MAX_HOPS} redirects. Long chains are used to hide a destination.`,
  };
}
