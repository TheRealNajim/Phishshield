import { useEffect, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";

export interface FilterOption<T extends string | number> {
  value: T;
  label: string;
}

/**
 * Custom dropdown matching the dashboard range filter: trigger button with a
 * rotating chevron plus a panel menu. Used everywhere instead of native
 * selects so every menu looks and behaves the same.
 */
export function FilterDropdown<T extends string | number>({
  label,
  icon: Icon,
  prefix,
  value,
  options,
  onChange,
  menuAlign = "left",
}: {
  label: string;
  icon?: typeof ChevronDown;
  prefix?: string;
  value: T;
  options: readonly FilterOption<T>[];
  onChange: (value: T) => void;
  menuAlign?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open ]);

  const selectedLabel = options.find((o) => o.value === value)?.label ?? "";

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-4 py-2.5 text-sm"
      >
        {Icon && <Icon size={14} />}
        {prefix ? `${prefix} ${selectedLabel}` : selectedLabel}
        <ChevronDown size={14} className={`transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div role="menu" className={`panel absolute top-full z-20 mt-2 w-40 p-1 text-sm ${menuAlign === "right" ? "right-0" : "left-0"}`}>
          {options.map((o) => (
            <button
              key={o.value}
              type="button"
              role="menuitem"
              onClick={() => {
                onChange(o.value);
                setOpen(false);
              }}
              className={`flex w-full cursor-pointer items-center justify-between rounded-[3px] px-3 py-2 text-left ${o.value === value ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground"}`}
            >
              {o.label}
              {o.value === value && <span className="h-1.5 w-1.5 rounded-full bg-primary" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
