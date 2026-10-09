import { PhishChecker } from "@/components/PhishChecker";
import { ShieldIcon } from "@/components/ShieldIcon";

export default function Home() {
  return (
    <main id="main" className="mx-auto w-full max-w-3xl px-4 py-10 sm:py-16">
      <header className="mb-8">
        <p className="flex items-center gap-2 text-sm font-semibold tracking-wide text-teal-700 dark:text-teal-400">
          <ShieldIcon /> PhishGuard
        </p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
          Not sure about a message? Check it before you click.
        </h1>
        <p className="mt-3 text-base text-slate-600 dark:text-slate-400">
          Paste a suspicious email, text or website link. We&apos;ll tell you whether it looks like
          a scam, show the evidence for every finding, and what to do next.
        </p>
      </header>

      <PhishChecker />
    </main>
  );
}
