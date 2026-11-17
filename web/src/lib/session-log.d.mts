export interface SessionEntry { at: string; category: string; score: number }
export interface SessionSummary { total: number; average: number; highPriority: number; patterns: { category: string; count: number }[] }
export const SESSION_LOG_KEY: string;
export const MAX_ENTRIES: number;
export const HIGH_PRIORITY_THRESHOLD: number;
export function parseLog(serialized: string | null | undefined): SessionEntry[];
export function appendEntry(entries: SessionEntry[], input: { category: string; score: number; now?: Date }): SessionEntry[];
export function summarize(entries: SessionEntry[]): SessionSummary;
export function summaryText(entries: SessionEntry[], now?: Date): string;
