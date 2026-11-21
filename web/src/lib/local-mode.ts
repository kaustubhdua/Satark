// Browser-only workspace bridge.
//
// If the deployment has no hosted SATARK API (GET /api/health reports
// persistentStorage.configured === false), same-origin workspace routes are
// answered from IndexedDB in this browser instead of failing with 503. When a
// backend IS configured this module does nothing and requests go to the server.
import {
  createMemoryStore, exportWorkspace, handleLocalRequest, importWorkspace, isLocalRoute, type LocalStore,
} from './local-workspace.mjs';

const DB_NAME = 'satark-local-workspace';
const LOCK = 'satark-local-workspace';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore('state');
      request.result.createObjectStore('blobs');
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB is unavailable.'));
    request.onblocked = () => reject(new Error('IndexedDB is blocked.'));
  });
}

function run<T>(db: IDBDatabase, store: string, mode: IDBTransactionMode, op: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const req = op(tx.objectStore(store));
    tx.oncomplete = () => resolve(req.result);
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB write failed.'));
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB write aborted.'));
  });
}

function indexedDbStore(db: IDBDatabase): LocalStore {
  return {
    kind: 'indexeddb',
    async load() { return (await run(db, 'state', 'readonly', s => s.get('main'))) ?? null; },
    async save(state) { await run(db, 'state', 'readwrite', s => s.put(state, 'main')); },
    async putBlob(id, bytes) { await run(db, 'blobs', 'readwrite', s => s.put(new Uint8Array(bytes as ArrayBuffer), id)); },
    async getBlob(id) { const v = await run(db, 'blobs', 'readonly', s => s.get(id)); return v ? new Uint8Array(v as ArrayBuffer) : null; },
    async listBlobIds() { return (await run(db, 'blobs', 'readonly', s => s.getAllKeys())).map(String); },
    async clear() { await run(db, 'state', 'readwrite', s => s.clear()); await run(db, 'blobs', 'readwrite', s => s.clear()); },
  };
}

export type LocalModeStatus = { active: boolean; durable: boolean };
let status: LocalModeStatus = { active: false, durable: false };
let storePromise: Promise<LocalStore> | null = null;
let detectPromise: Promise<boolean> | null = null;
let nativeFetch: typeof fetch | null = null;

export function getLocalModeStatus(): LocalModeStatus { return status; }

function setStatus(next: LocalModeStatus) {
  status = next;
  if (typeof window !== 'undefined') window.dispatchEvent(new CustomEvent('satark-local-mode', { detail: next }));
}

function getStore(): Promise<LocalStore> {
  storePromise ??= openDb().then(indexedDbStore).then(store => { setStatus({ ...status, durable: true }); return store; })
    .catch(() => { setStatus({ ...status, durable: false }); return createMemoryStore(); });
  return storePromise;
}

function detect(): Promise<boolean> {
  detectPromise ??= (async () => {
    try {
      const response = await (nativeFetch as typeof fetch)('/api/health', { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) return false;
      const data = await response.json();
      const active = data?.checks?.persistentStorage?.configured === false;
      if (active) { await getStore(); setStatus({ ...status, active: true }); }
      return active;
    } catch { return false; }
  })();
  return detectPromise;
}

async function withLock<T>(task: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: { request: <R>(name: string, cb: () => Promise<R>) => Promise<R> } }).locks;
  return locks ? locks.request(LOCK, task) : task();
}

async function answer(url: URL, init: RequestInit | undefined): Promise<Response> {
  const store = await getStore();
  let body: unknown; let form: FormData | undefined;
  if (init?.body instanceof FormData) form = init.body;
  else if (typeof init?.body === 'string' && init.body) {
    try { body = JSON.parse(init.body); } catch { return Response.json({ error: 'Invalid JSON body.' }, { status: 400 }); }
  }
  const result = await withLock(() => handleLocalRequest(store, { method: (init?.method || 'GET').toUpperCase(), path: url.pathname, query: url.searchParams, body, form }));
  if (result.bytes) {
    return new Response(result.bytes as BlobPart, { status: result.status, headers: {
      'Content-Type': result.contentType || 'application/octet-stream', 'Cache-Control': 'no-store',
      'Content-Disposition': 'attachment; filename="' + String(result.filename || 'evidence.bin').replace(/[^A-Za-z0-9._-]/g, '_') + '"' } });
  }
  return Response.json(result.json ?? {}, { status: result.status, headers: { 'Cache-Control': 'no-store' } });
}

/** Idempotent; safe to call from any client module. */
export function installLocalMode() {
  if (typeof window === 'undefined' || nativeFetch) return;
  nativeFetch = window.fetch.bind(window);
  const native = nativeFetch;
  window.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (typeof input === 'string' || input instanceof URL) {
      const url = new URL(String(input), window.location.origin);
      if (url.origin === window.location.origin && isLocalRoute(url.pathname) && await detect()) return answer(url, init);
    }
    return native(input as RequestInfo, init);
  }) as typeof fetch;
  void detect();
}

export async function exportLocalWorkspace() { return exportWorkspace(await getStore()); }
export async function importLocalWorkspace(file: File) {
  let parsed: unknown;
  try { parsed = JSON.parse(await file.text()); } catch { throw new Error('That file is not valid JSON.'); }
  return withLock(async () => importWorkspace(await getStore(), parsed));
}
export async function eraseLocalWorkspace() { await withLock(async () => (await getStore()).clear()); }
export async function requestPersistentStorage(): Promise<boolean> {
  try { return Boolean(await navigator.storage?.persist?.()); } catch { return false; }
}
