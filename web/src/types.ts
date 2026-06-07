export type SourceStatus = {
  isOpen: boolean;
  path: string | null;
  name: string | null;
  size: number;
  sizeHuman: string;
  mode: "closed" | "read" | "read-write";
  isBlockDevice: boolean;
  filesystem: string | null;
  fsInfo: Record<string, string>;
  rootInode: number | null;
  blockSize: number;
  inodeCount: number;
  groupCount: number;
  canUndo: boolean;
  canRedo: boolean;
  history: string[];
  capabilities: FilesystemCapability;
};

export type FilesystemCapability = {
  filesystem: string | null;
  metadata: boolean;
  timeline: boolean;
  rawSearch: boolean;
  deletedRecovery: boolean;
  directoryArtifacts: boolean;
  imaging: boolean;
  notes: string[];
};

export type HexRead = {
  offset: number;
  length: number;
  hex: string;
  ascii: string;
  endOffset: number;
  isEnd: boolean;
};

export type ParsedField = {
  name: string;
  offset: number;
  absoluteOffset: number | null;
  size: number;
  rawHex: string;
  value: string | number | boolean | null;
  description: string;
};

export type ParsedStructure = {
  name: string;
  diskOffset: number;
  size: number;
  fields: ParsedField[];
};

export type DirectoryEntry = {
  name: string;
  inode: number;
  fileType: string;
  diskOffset: number;
  recordLength: number;
  isDirectory: boolean;
};

export type DirectoryResponse = {
  inode: number;
  entries: DirectoryEntry[];
};

export type SearchResult = {
  found: boolean;
  offset: number | null;
  length: number;
};

export type OwnerCandidate = {
  inode: number;
  mode: string;
  size: string;
  links: number;
  atime: string;
  ctime: string;
  mtime: string;
  dtime: string;
  crtime: string;
  flags: string;
  blockIndex: number;
  physicalBlock: number;
  blockStart: number;
  byteOffsetInBlock: number;
  deleted: boolean;
};

export type OwnerResponse = {
  offset: number;
  blockSize: number;
  physicalBlock: number;
  byteOffsetInBlock: number;
  scannedInodes: number;
  truncated: boolean;
  candidates: OwnerCandidate[];
};

export type DeletedFileExtent = {
  logical: number;
  physical: number;
  length: number;
  uninitialized: boolean;
  blockStart: number;
};

export type DeletedFileSummary = {
  inode: number;
  filename: string;
  size: number;
  sizeHuman: string;
  mode: string;
  uid: number;
  gid: number;
  links: number;
  atime: string | null;
  ctime: string | null;
  mtime: string | null;
  dtime: string | null;
  crtime: string | null;
  deleted: boolean;
  confidence: string;
  blockCount: number;
  firstBlock: number | null;
  extentSummary: string;
  recoverableBytes: number;
  recoverability: "full" | "partial";
  warnings: string[];
  extents: DeletedFileExtent[];
};

export type DeletedFilesResponse = {
  items: DeletedFileSummary[];
  cursor: number;
  nextCursor: number | null;
  scanned: number;
  totalInodes: number;
  truncated: boolean;
  nameHintApplied: boolean;
};

export type DeletedFilePreview = {
  inode: number;
  length: number;
  hex: string;
  ascii: string;
  warnings: string[];
};

export type DirectoryArtifact = {
  name: string;
  pathHint: string;
  inode: number;
  fileType: string;
  recordLength: number;
  nameLength: number;
  diskOffset: number;
  block: number;
  blockOffset: number;
  containerInode: number | null;
  parentInode: number | null;
  evidence: string;
  confidence: string;
  inodeState: {
    state: "active" | "deleted" | "wiped" | "unreadable";
    mode: string | null;
    size: number;
    sizeHuman: string;
    links: number;
    dtime: string | null;
    crtime: string | null;
    mtime: string | null;
    recoverable: boolean;
    extentCount: number;
    warnings: string[];
  };
};

export type RawArtifact = {
  offset: number;
  length: number;
  previewOffset: number;
  previewAscii: string;
  previewHex: string;
};

export type ForensicArtifactsResponse = {
  query: string;
  directoryEntries: {
    items: DirectoryArtifact[];
    cursorBlock: number;
    nextCursorBlock: number | null;
    scannedBlocks: number;
    totalBlocks: number;
    truncated: boolean;
    nameHint: string;
  };
  rawMatches: {
    items: RawArtifact[];
    scannedBytes: number;
    truncated: boolean;
  };
};

export type ForensicEventType =
  | "created"
  | "modified"
  | "metadata_changed"
  | "accessed"
  | "deleted"
  | "name_trace"
  | "content_match"
  | "image_created";

export type ForensicEvent = {
  eventType: ForensicEventType;
  timestampEpoch: number | null;
  timestampLocal: string | null;
  sourceFs: string | null;
  evidenceType: string;
  inode: number | null;
  name: string | null;
  pathHint: string | null;
  offset: number | null;
  confidence: string;
  warnings: string[];
  details: Record<string, unknown>;
};

export type ForensicTimelineResponse = {
  query: string;
  from: string | null;
  to: string | null;
  events: ForensicEvent[];
  total: number;
  undated: number;
  capabilities: FilesystemCapability;
};

export type ForensicSearchResponse = {
  query: string;
  names: DirectoryArtifact[];
  content: RawArtifact[];
  timelineEvents: ForensicEvent[];
  recoverableInodes: DeletedFileSummary[];
  capabilities: FilesystemCapability;
};

export type FileDossier = {
  sourceFs: string | null;
  query: string;
  inode: number | null;
  names: DirectoryArtifact[];
  rawMatches: RawArtifact[];
  inodeRecord: Record<string, unknown> | null;
  recoverableFile: DeletedFileSummary | null;
  offsetPreview: RawArtifact | null;
  timeline: ForensicEvent[];
  capabilities: FilesystemCapability;
};

export type DeviceInfo = {
  id: string;
  path: string;
  displayName: string;
  size: number;
  sizeHuman: string;
  model: string;
  filesystem: string;
  mountpoints: string[];
  removable: boolean;
  readOnly: boolean;
  wholeDisk: boolean;
};

export type DevicesResponse = {
  platform: string;
  devices: DeviceInfo[];
};

export type ImageCaptureJob = {
  jobId: string;
  status: "queued" | "running" | "complete" | "cancelled" | "error";
  source: string;
  destination: string;
  unmount: boolean;
  bytesCopied: number;
  totalBytes: number;
  progress: number;
  speedBytesPerSec: number;
  etaSeconds: number | null;
  sha256: string | null;
  error: string | null;
  startedAt: number;
  completedAt: number | null;
  cancelRequested: boolean;
};

export type HistoryStatus = {
  changed?: boolean;
  description?: string | null;
  history: string[];
  status: SourceStatus;
};

export type HighlightRange = {
  offset: number;
  size: number;
  tone: "field" | "search" | "edit";
};

declare global {
  interface Window {
    hexCorruptor?: {
      openImageDialog: () => Promise<string | null>;
      saveImageDialog: () => Promise<string | null>;
    };
  }
}
