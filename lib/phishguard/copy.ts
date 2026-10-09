import type { Category, ReportVerdict } from "./types";

// Fixed wording used when the AI explainer is not available: either no API key
// is configured, or a model call failed.

type Guidance = {
  headline: string;
  summary: string;
  safetySteps: string[];
  ifAlreadyClicked: string[];
};

const CAUTION_STEPS = [
  "Don't click any links, open attachments, or call numbers in the message.",
  'Don\'t reply, even to say "stop" — it confirms your number or address is active.',
  "If it claims to be from a company you use, open their official app or type their website address yourself to check your account.",
  "Report it as spam or phishing in your email or messaging app, then delete it.",
];

const RECOVERY_STEPS = [
  "If you entered a password, change it now on the real website, and anywhere else you reuse it.",
  "If you entered card or bank details, call your bank using the number on the back of your card.",
  "If you shared a one-time code or installed anything, contact the real company right away and run a security scan on your device.",
];

const GUIDANCE: Record<ReportVerdict, Guidance> = {
  unverified: {
    headline: "We couldn't verify this website.",
    summary:
      "We found no known threats, but nothing confirms who is behind this website either. That doesn't make it a scam. Treat it with care until you have checked it another way.",
    safetySteps: [
      "Don't enter passwords, card details or one-time codes on it yet.",
      "Look up the organisation independently and compare the website address letter by letter.",
      "If it promises a prize, find the announcement and winner list on the organizer's official website. Real lotteries never ask winners to pay a fee first.",
    ],
    ifAlreadyClicked: [],
  },
  dangerous: {
    headline: "This looks like a scam. Don't click or reply.",
    summary:
      "This message shows several of the classic tricks scammers use. You did the right thing by checking first. The safest move is to not interact with it at all.",
    safetySteps: CAUTION_STEPS,
    ifAlreadyClicked: RECOVERY_STEPS,
  },
  suspicious: {
    headline: "Something is off here. Treat it with caution.",
    summary:
      "This message has some warning signs, though it isn't certain to be a scam. Don't use any links or phone numbers in it until you've confirmed it through a channel you already trust.",
    safetySteps: CAUTION_STEPS,
    ifAlreadyClicked: RECOVERY_STEPS,
  },
  likely_safe: {
    headline: "No obvious warning signs found.",
    summary:
      "Nothing in this message matches the common scam patterns we check for. That isn't a guarantee, so if it asks for money, passwords or codes, confirm with the sender another way first.",
    safetySteps: [
      "If you weren't expecting this message, contact the sender using a phone number or website you already know.",
      "Never share passwords or one-time codes, even with someone who seems genuine.",
    ],
    ifAlreadyClicked: [],
  },
};

/** Headline, summary and steps for a verdict when no AI explanation exists. */
export const fallbackGuidance = (verdict: ReportVerdict): Guidance => GUIDANCE[verdict];

/** Plain-language label and the "why scammers do this" lesson per category. */
export const CATEGORY_COPY: Record<Category, { title: string; why: string }> = {
  urgency: {
    title: "Pressure to act fast",
    why: "Scammers rush you so you don't stop to think or ask someone. Real organisations give you time.",
  },
  threat: {
    title: "Scare tactics",
    why: "Fear makes people act without checking. A real company won't threaten you out of the blue in a message.",
  },
  suspicious_link: {
    title: "Link isn't what it seems",
    why: "The part of a web address just before the first single slash is where it really goes. Scammers dress that up to look familiar.",
  },
  spoofed_sender: {
    title: "Sender isn't who they claim",
    why: "The display name can be typed as anything. The address after the @ is what counts.",
  },
  credential_request: {
    title: "Asks for private details",
    why: "Genuine companies never ask for passwords or one-time codes by message.",
  },
  payment_request: {
    title: "Asks for unusual payment",
    why: "Gift cards, crypto and wire transfers can't be reversed, which is exactly why scammers ask for them.",
  },
  too_good_to_be_true: {
    title: "Too good to be true",
    why: 'You can\'t win a prize draw you never entered. The "reward" is bait to get your details or a fee.',
  },
  impersonation: {
    title: "Pretends to be someone trusted",
    why: "Borrowing a familiar name or logo is the easiest way to lower your guard.",
  },
  attachment: {
    title: "Risky attachment",
    why: "Unexpected files can install harmful software when opened.",
  },
  generic_greeting: {
    title: "Doesn't know your name",
    why: "Companies you have an account with normally address you by name. Mass scams can't.",
  },
  other: { title: "Other warning sign", why: "" },
};
