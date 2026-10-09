/** The PhishGuard mark. Same artwork as app/icon.svg (the favicon). */
export function ShieldIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <rect width="32" height="32" rx="7" fill="#0F766E" />
      <path
        fill="#fff"
        d="M16 5.5 7.5 8.7v6.4c0 5.4 3.6 10.4 8.5 11.7 4.9-1.3 8.5-6.3 8.5-11.7V8.7L16 5.5Z"
      />
      <path
        fill="none"
        stroke="#0F766E"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
        d="m12 16 3 3 5.5-5.5"
      />
    </svg>
  );
}
