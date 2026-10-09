// Official lottery organizers and the only domains they publish results on.
// A lottery is "verified" here only when the website is the organizer's own.

export type Lottery = {
  name: string;
  organizer: string;
  /** Matches the lottery's name in message text or a web address. */
  pattern: RegExp;
  officialDomains: string[];
  /** Where the organizer publishes results and how to claim. */
  verifyUrl: string;
};

const LOTTERIES: Lottery[] = [
  {
    name: "Powerball",
    organizer: "the Multi-State Lottery Association",
    pattern: /\bpower\s?ball\b/i,
    officialDomains: ["powerball.com"],
    verifyUrl: "https://www.powerball.com/",
  },
  {
    name: "Mega Millions",
    organizer: "the Mega Millions consortium of US state lotteries",
    pattern: /\bmega\s?millions?\b/i,
    officialDomains: ["megamillions.com"],
    verifyUrl: "https://www.megamillions.com/",
  },
  {
    name: "The National Lottery (UK)",
    organizer: "Allwyn, the UK National Lottery operator",
    pattern: /\b(uk )?national lottery\b|\bthunderball\b/i,
    officialDomains: ["national-lottery.co.uk"],
    verifyUrl: "https://www.national-lottery.co.uk/results",
  },
  {
    name: "EuroMillions",
    organizer: "the participating national lotteries",
    pattern: /\beuro\s?millions?\b/i,
    officialDomains: [
      "national-lottery.co.uk",
      "fdj.fr",
      "loteriasyapuestas.es",
      "lottery.ie",
      "loterie-nationale.be",
      "swisslos.ch",
      "jogossantacasa.pt",
    ],
    verifyUrl: "https://www.national-lottery.co.uk/results/euromillions",
  },
  {
    name: "Irish National Lottery",
    organizer: "Premier Lotteries Ireland",
    pattern: /\birish (national )?lott(ery|o)\b/i,
    officialDomains: ["lottery.ie"],
    verifyUrl: "https://www.lottery.ie/results",
  },
  {
    name: "The Lott (Australia)",
    organizer: "The Lottery Corporation",
    pattern: /\b(the lott|oz lotto|tattslotto)\b/i,
    officialDomains: ["thelott.com"],
    verifyUrl: "https://www.thelott.com/results",
  },
  {
    name: "Lotto Max / Lotto 6/49 (Canada)",
    organizer: "the Canadian provincial lottery corporations",
    pattern: /\blotto (max|6[/ ]?49)\b/i,
    officialDomains: ["olg.ca", "lotoquebec.com", "bclc.com", "playnow.com", "wclc.com", "alc.ca"],
    verifyUrl: "https://www.olg.ca/en/lottery/winning-numbers-results.html",
  },
  {
    name: "Kerala State Lotteries",
    organizer: "the Government of Kerala's Directorate of State Lotteries",
    pattern: /\bkerala (state )?lotter(y|ies)\b/i,
    officialDomains: ["statelottery.kerala.gov.in", "keralalotteries.com"],
    verifyUrl: "https://statelottery.kerala.gov.in/",
  },
  {
    name: "Publishers Clearing House",
    organizer: "Publishers Clearing House",
    pattern: /\b(publishers clearing house|pch (sweepstakes|prize|winner))\b/i,
    officialDomains: ["pch.com"],
    verifyUrl: "https://www.pch.com/",
  },
];

/** "Lotteries" that are a long-running scam theme: the named brand runs no such draw. */
const SCAM_THEMES: { name: string; pattern: RegExp }[] = [
  {
    name: "KBC lottery",
    pattern: /\b(kbc|kaun banega crorepati)\b[\s\S]{0,40}\b(lottery|lucky draw|winner)\b/i,
  },
  { name: "WhatsApp lottery", pattern: /\bwhats\s?app\b[\s\S]{0,30}\b(lottery|lucky draw)\b/i },
  {
    name: "Microsoft lottery",
    pattern: /\bmicrosoft\b[\s\S]{0,30}\b(lottery|lucky draw|sweepstakes?)\b/i,
  },
  {
    name: "Google lottery",
    pattern: /\bgoogle\b[\s\S]{0,30}\b(lottery|lucky draw|anniversary (award|prize))\b/i,
  },
];

const LOTTERY_TALK =
  /\b(lotter(y|ies)|lotto|lucky\s?draw|jackpot|sweepstakes?|raffle|giveaway|prize draw|you('ve| have) won|claim your (prize|winnings|reward))\b/i;

const WIN_CLAIM =
  /\b(you('ve| have| are)? (won|been selected|the winner)|winner|winning (ticket|number)|congratulations|claim (your|the))\b/i;

export type LotteryResult =
  | { kind: "not_lottery" }
  /** The website is the organizer's own. */
  | { kind: "official"; lottery: Lottery }
  /** Claims a win in a real lottery, but from somewhere other than its organizer. */
  | { kind: "impersonation"; lottery: Lottery }
  | { kind: "scam_theme"; name: string }
  /** Lottery talk, but no organizer we can confirm. `lottery` is set when a real one is merely mentioned. */
  | { kind: "unknown_organizer"; lottery?: Lottery };

/**
 * Decides whether the text or address is about a lottery and, if so, whether
 * `domain` belongs to that lottery's official organizer.
 */
export function checkLottery(text: string, url: string, domain: string): LotteryResult {
  const official = LOTTERIES.find((lottery) => lottery.officialDomains.includes(domain));
  if (official) return { kind: "official", lottery: official };

  // Words inside the address count too: "powerball-winners.top" names Powerball.
  const words = (value: string) => value.replace(/[^a-z0-9]+/gi, " ");
  const haystack = `${text} ${words(url)}`;

  const named = LOTTERIES.find((lottery) => lottery.pattern.test(haystack));
  if (named) {
    // A news page may mention a lottery in its path. Only the site's own name,
    // or a claim that the reader has won, makes it an impersonation.
    const claimsWin = WIN_CLAIM.test(text) || named.pattern.test(words(domain));
    return claimsWin
      ? { kind: "impersonation", lottery: named }
      : { kind: "unknown_organizer", lottery: named };
  }

  const theme = SCAM_THEMES.find((candidate) => candidate.pattern.test(haystack));
  if (theme) return { kind: "scam_theme", name: theme.name };

  return LOTTERY_TALK.test(haystack) ? { kind: "unknown_organizer" } : { kind: "not_lottery" };
}

export const KNOWN_LOTTERY_COUNT = LOTTERIES.length;
