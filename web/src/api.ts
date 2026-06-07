import type {
  DeletedFilePreview,
  DeletedFileSummary,
  DeletedFilesResponse,
  DevicesResponse,
  DirectoryResponse,
  FileDossier,
  ForensicArtifactsResponse,
  ForensicSearchResponse,
  ForensicTimelineResponse,
  HexRead,
  HistoryStatus,
  ImageCaptureJob,
  OwnerResponse,
  ParsedStructure,
  SearchResult,
  SourceStatus,
} from "./types";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8765";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error ?? "Ошибка API");
  }
  return payload as T;
}

async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: "Ошибка API" }));
    throw new Error(payload.error ?? "Ошибка API");
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

type Abortable = {
  signal?: AbortSignal;
  cancelToken?: string;
};

function params(values: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && String(value) !== "") {
      search.set(key, String(value));
    }
  });
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  status: () => request<SourceStatus>("/api/status"),
  open: (path: string, writable: boolean) =>
    request<SourceStatus>("/api/open", {
      method: "POST",
      body: JSON.stringify({ path, writable }),
    }),
  openDemo: () => request<SourceStatus>("/api/demo", { method: "POST" }),
  close: () => request<SourceStatus>("/api/close", { method: "POST" }),
  read: (offset: number, length: number) =>
    request<HexRead>(`/api/read?offset=${offset}&length=${length}`),
  structure: (kind: string, index?: number) => {
    const suffix = typeof index === "number" ? `&index=${index}` : "";
    return request<ParsedStructure>(`/api/structure?kind=${kind}${suffix}`);
  },
  directory: (inode: number) => request<DirectoryResponse>(`/api/directory?inode=${inode}`),
  search: (pattern: string, encoding: string, start: number) =>
    request<SearchResult>(
      `/api/search?pattern=${encodeURIComponent(pattern)}&encoding=${encoding}&start=${start}`,
    ),
  owners: (offset: number) =>
    request<OwnerResponse>(`/api/owners?offset=${offset}&limit=20`),
  deletedFiles: (limit: number, cursor: number, minSize: number) =>
    request<DeletedFilesResponse>(
      `/api/forensics/deleted-files?limit=${limit}&cursor=${cursor}&min_size=${minSize}`,
    ),
  deletedFile: (inode: number) =>
    request<DeletedFileSummary>(`/api/forensics/deleted-files/${inode}`),
  deletedFilePreview: (inode: number, length = 4096) =>
    request<DeletedFilePreview>(`/api/forensics/deleted-files/${inode}/preview?length=${length}`),
  downloadRecoveredFile: (inode: number) =>
    download(`/api/forensics/deleted-files/${inode}/recover`, `recovered_inode_${inode}.bin`),
  downloadDeletedFileReport: (inode: number) =>
    download(`/api/forensics/deleted-files/${inode}/report`, `forensics_inode_${inode}.md`),
  forensicArtifacts: (query: string, limit = 100, cursorBlock = 0) =>
    request<ForensicArtifactsResponse>(
      `/api/forensics/artifacts?query=${encodeURIComponent(query)}&limit=${limit}&cursor_block=${cursorBlock}`,
    ),
  forensicSearch: (
    query: string,
    options: { from?: string; to?: string; types?: string; limit?: number } & Abortable = {},
  ) =>
    request<ForensicSearchResponse>(
      `/api/forensics/search${params({
        query,
        from: options.from,
        to: options.to,
        types: options.types,
        limit: options.limit ?? 100,
        cancel_token: options.cancelToken,
      })}`,
      { signal: options.signal },
    ),
  forensicTimeline: (
    options: { query?: string; from?: string; to?: string; eventTypes?: string; limit?: number } & Abortable = {},
  ) =>
    request<ForensicTimelineResponse>(
      `/api/forensics/timeline${params({
        query: options.query,
        from: options.from,
        to: options.to,
        event_types: options.eventTypes,
        limit: options.limit ?? 1000,
        cancel_token: options.cancelToken,
      })}`,
      { signal: options.signal },
    ),
  fileDossier: (options: { inode?: number; name?: string; offset?: number } & Abortable) =>
    request<FileDossier>(
      `/api/forensics/file-dossier${params({
        inode: options.inode,
        name: options.name,
        offset: options.offset,
        cancel_token: options.cancelToken,
      })}`,
      { signal: options.signal },
    ),
  cancelForensics: (token: string) =>
    request<{ cancelled: boolean; token: string }>("/api/forensics/cancel", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  downloadForensicsReport: (format: "markdown" | "json", query: string, from?: string, to?: string) =>
    download(
      `/api/forensics/report${params({ format, query, from, to })}`,
      format === "json" ? "hexcorruptor-forensics.json" : "hexcorruptor-forensics.md",
    ),
  devices: () => request<DevicesResponse>("/api/devices"),
  startCapture: (source: string, destination: string, unmount: boolean) =>
    request<ImageCaptureJob>("/api/images/capture", {
      method: "POST",
      body: JSON.stringify({ source, destination, unmount }),
    }),
  captureJob: (jobId: string) => request<ImageCaptureJob>(`/api/images/capture/${jobId}`),
  cancelCapture: (jobId: string) =>
    request<ImageCaptureJob>(`/api/images/capture/${jobId}/cancel`, { method: "POST" }),
  write: (offset: number, data: string) =>
    request<HistoryStatus>("/api/write", {
      method: "POST",
      body: JSON.stringify({ offset, data, encoding: "hex" }),
    }),
  replace: (oldValue: string, newValue: string, encoding: string, start: number, all: boolean) =>
    request<{ count: number; offsets: number[]; history: string[]; status: SourceStatus }>(
      "/api/replace",
      {
        method: "POST",
        body: JSON.stringify({ old: oldValue, new: newValue, encoding, start, all }),
      },
    ),
  undo: () => request<HistoryStatus>("/api/undo", { method: "POST" }),
  redo: () => request<HistoryStatus>("/api/redo", { method: "POST" }),
};
