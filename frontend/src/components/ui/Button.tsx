import { clsx } from "clsx";
import type { ButtonHTMLAttributes } from "react";

export function Button({ className, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={clsx(
        "inline-flex items-center justify-center gap-2 rounded-md border border-cyanfire/30 bg-cyanfire/10 px-4 py-2 text-sm font-semibold text-cyan-100 transition hover:border-cyanfire hover:bg-cyanfire/20 disabled:cursor-not-allowed disabled:opacity-50",
        className
      )}
      {...props}
    />
  );
}

