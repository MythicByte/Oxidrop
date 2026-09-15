import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function displayAdapterName(name: string): string {
  return name === "unknown_or_down" ? "Unknown or down" : name;
}
