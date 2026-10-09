import { SAMPLES } from "@/app/samples";
import { MAX_INPUT_CHARS } from "@/lib/phishguard/types";
import { CARD, MUTED } from "./styles";

type Props = {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  busy: boolean;
};

/** The paste box, example buttons and submit button. */
export function MessageForm({ value, onChange, onSubmit, busy }: Props) {
  return (
    <form
      className={`${CARD} p-4 shadow-sm sm:p-5`}
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <label htmlFor="message" className="block text-sm font-medium">
        Message to check
      </label>
      <textarea
        id="message"
        name="message"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
            event.currentTarget.form?.requestSubmit();
          }
        }}
        maxLength={MAX_INPUT_CHARS}
        rows={8}
        spellCheck={false}
        aria-describedby="message-hint"
        placeholder="Paste the email, text message or link here…"
        className="mt-2 w-full resize-y rounded-lg border border-slate-300 bg-slate-50 p-3 font-mono text-sm leading-relaxed placeholder:font-sans placeholder:text-slate-500 dark:border-slate-700 dark:bg-slate-950 dark:placeholder:text-slate-400"
      />

      <div
        role="group"
        aria-labelledby="examples-label"
        className="mt-3 flex flex-wrap items-center gap-2"
      >
        <span id="examples-label" className={`text-sm ${MUTED}`}>
          Try an example:
        </span>
        {SAMPLES.map((sample) => (
          <button
            key={sample.label}
            type="button"
            onClick={() => onChange(sample.text)}
            className="rounded-full border border-slate-300 px-3 py-1 text-sm text-slate-700 hover:border-teal-600 hover:text-teal-700 dark:border-slate-700 dark:text-slate-300 dark:hover:text-teal-400"
          >
            {sample.label}
          </button>
        ))}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <p id="message-hint" className={`text-xs ${MUTED}`}>
          We never open links in your message, and nothing you paste is stored.
        </p>
        <button
          type="submit"
          disabled={busy || !value.trim()}
          className="rounded-lg bg-teal-700 px-5 py-2.5 text-sm font-semibold text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? "Checking…" : "Check this message"}
        </button>
      </div>
    </form>
  );
}
