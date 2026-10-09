import { CARD } from "./styles";

type Props = { title: string; items: string[]; ordered?: boolean };

/** A titled list of steps or observations. */
export function ListCard({ title, items, ordered = false }: Props) {
  const List = ordered ? "ol" : "ul";
  return (
    <section className={`${CARD} p-5`}>
      <h3 className="text-lg font-semibold">{title}</h3>
      <List
        className={`mt-3 space-y-2 pl-5 text-slate-700 dark:text-slate-300 ${
          ordered ? "list-decimal" : "list-disc"
        }`}
      >
        {items.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </List>
    </section>
  );
}
