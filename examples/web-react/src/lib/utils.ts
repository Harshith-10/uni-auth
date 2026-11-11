export { cn } from "cn";

/**
 * Safely parses ISO-8601, RFC 3339, or legacy non-standard space-delimited date strings.
 */
export function parseDate(dateInput?: string | Date | null): Date | null {
  if (!dateInput) return null;
  if (dateInput instanceof Date) {
    return isNaN(dateInput.getTime()) ? null : dateInput;
  }
  const str = String(dateInput).trim();
  if (!str) return null;

  // Try direct parsing first
  const parsed = new Date(str);
  if (!isNaN(parsed.getTime())) {
    return parsed;
  }

  // Handle fallback formats like "YYYY-MM-DD HH:MM:SS.NNNNNNNNN +00:00:00"
  try {
    const normalized = str
      .replace(" ", "T")
      .replace(/ \+00:00(:00)?$/, "Z")
      .replace(/ \+(\d{2}):(\d{2})(:00)?$/, "+$1:$2");
    const fallback = new Date(normalized);
    if (!isNaN(fallback.getTime())) {
      return fallback;
    }
  } catch {
    // Ignore normalization errors
  }

  return null;
}

/**
 * Safely formats date and time into locale string (e.g. "18/11/2026, 4:14:36 pm").
 */
export function formatDateTime(dateInput?: string | Date | null): string {
  const d = parseDate(dateInput);
  if (!d) return "N/A";
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

/**
 * Safely formats time only into locale string (e.g. "4:14:36 pm").
 */
export function formatTime(dateInput?: string | Date | null): string {
  const d = parseDate(dateInput);
  if (!d) return "N/A";
  return d.toLocaleTimeString();
}
