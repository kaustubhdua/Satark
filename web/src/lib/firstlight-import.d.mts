export type ImportedCsvEvent = { id: string; timestamp: string; source: string; kind: string; summary: string; };
export function parseCsv(text: string): ImportedCsvEvent[];
