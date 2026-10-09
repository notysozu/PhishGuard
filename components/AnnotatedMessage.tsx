import { segmentMessage } from "@/lib/phishguard/highlight";
import type { RedFlag } from "@/lib/phishguard/types";
import { CARD, SEVERITY_STYLE, flagId } from "./styles";

type Props = {
  message: string;
  redFlags: RedFlag[];
  activeFlag: number | null;
  onActiveFlagChange: (flag: number | null) => void;
};

/**
 * The original message with each piece of evidence highlighted. Every
 * highlight is a link to its explanation, so it works with a keyboard and a
 * screen reader as well as on hover.
 */
export function AnnotatedMessage({ message, redFlags, activeFlag, onActiveFlagChange }: Props) {
  const segments = segmentMessage(
    message,
    redFlags.map((flag) => flag.evidence),
  );

  return (
    <div
      role="region"
      aria-label="Your message, with warning signs highlighted"
      tabIndex={0}
      className={`${CARD} mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl p-4 font-mono text-sm leading-7`}
    >
      {segments.map((segment, index) => {
        if (segment.flag === undefined) return <span key={index}>{segment.text}</span>;
        const flag = segment.flag;
        const { severity, title } = redFlags[flag];
        return (
          <mark
            key={index}
            className={`rounded px-0.5 text-inherit ${SEVERITY_STYLE[severity].mark} ${
              activeFlag === flag ? "ring-2 ring-teal-600" : ""
            }`}
          >
            <a
              href={`#${flagId(flag)}`}
              className="underline decoration-inherit decoration-2 underline-offset-4"
              onMouseEnter={() => onActiveFlagChange(flag)}
              onMouseLeave={() => onActiveFlagChange(null)}
              onFocus={() => onActiveFlagChange(flag)}
              onBlur={() => onActiveFlagChange(null)}
            >
              {segment.text}
              <sup aria-hidden="true" className="ml-0.5 font-sans text-[10px] font-bold">
                {flag + 1}
              </sup>
              <span className="sr-only">
                {" "}
                (warning sign {flag + 1}: {title})
              </span>
            </a>
          </mark>
        );
      })}
    </div>
  );
}
