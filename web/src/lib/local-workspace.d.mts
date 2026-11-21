export interface LocalStore {
  kind: string;
  load(): Promise<any | null>;
  save(state: any): Promise<void>;
  putBlob(id: string, bytes: Uint8Array | ArrayBuffer): Promise<void>;
  getBlob(id: string): Promise<Uint8Array | null>;
  listBlobIds(): Promise<string[]>;
  clear(): Promise<void>;
}
export interface LocalRequest { method: string; path: string; query?: URLSearchParams; body?: any; form?: FormData }
export interface LocalResponse { status: number; json?: any; bytes?: Uint8Array; filename?: string; contentType?: string }
export const LOCAL_ROUTES: string[];
export const MAX_EVIDENCE_BYTES: number;
export function isLocalRoute(pathname: string): boolean;
export function canonicalJson(value: unknown): string;
export function sha256Hex(input: string | ArrayBuffer | Uint8Array): Promise<string>;
export function createMemoryStore(): LocalStore;
export function emptyState(): any;
export function verifyAuditChain(state: any): Promise<any>;
export function handleLocalRequest(store: LocalStore, request: LocalRequest): Promise<LocalResponse>;
export function exportWorkspace(store: LocalStore): Promise<any>;
export function importWorkspace(store: LocalStore, backup: any): Promise<{ cases: number; evidence: number; reports: number; audit_events: number }>;
