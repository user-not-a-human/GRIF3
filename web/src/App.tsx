import {
  AlertTriangle,
  Binary,
  ChevronDown,
  ChevronRight,
  Database,
  Download,
  FileCode2,
  FileSearch,
  FileText,
  FolderOpen,
  HardDrive,
  Hash,
  Inspect,
  Layers3,
  LocateFixed,
  Pencil,
  RotateCcw,
  RotateCw,
  Search,
  ShieldCheck,
  Square,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type {
  DeviceInfo,
  DeletedFilePreview,
  DeletedFileSummary,
  DeletedFilesResponse,
  DirectoryEntry,
  DirectoryArtifact,
  FileDossier,
  FilesystemCapability,
  ForensicArtifactsResponse,
  ForensicEvent,
  ForensicSearchResponse,
  ForensicTimelineResponse,
  HexRead,
  HighlightRange,
  ImageCaptureJob,
  ParsedStructure,
  RawArtifact,
  SourceStatus,
} from "./types";

const READ_LENGTH = 4096;
const BYTES_PER_ROW = 16;

type InspectorState =
  | { mode: "welcome" }
  | { mode: "info"; title: string; info: Record<string, string> }
  | { mode: "structure"; structure: ParsedStructure };

type AppPage = "source" | "filesystem" | "hex" | "forensics" | "imaging";

function toBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let index = 0; index < hex.length; index += 2) {
    bytes.push(Number.parseInt(hex.slice(index, index + 2), 16));
  }
  return bytes;
}

function formatOffset(offset: number) {
  return `0x${offset.toString(16).toUpperCase().padStart(8, "0")}`;
}

function parseOffset(text: string): number {
  const value = text.trim();
  if (!value) {
    return 0;
  }
  return Number.parseInt(value, value.toLowerCase().startsWith("0x") ? 16 : 10);
}

function decodedByteLength(value: string, encoding: string): number {
  if (encoding === "hex" || value.toLowerCase().startsWith("0x")) {
    const text = value.toLowerCase().startsWith("0x") ? value.slice(2) : value;
    return Math.max(1, Math.floor(text.replace(/\s+/g, "").length / 2));
  }
  return new TextEncoder().encode(value).length;
}

function inodeKind(mode: string): string {
  if (mode.includes("(d")) {
    return "каталог";
  }
  if (mode.includes("(-")) {
    return "обычный файл";
  }
  if (mode.includes("(l")) {
    return "симлинк";
  }
  return "неизвестно";
}

function normalizeStatus(status: SourceStatus, history?: string[]): SourceStatus {
  return {
    ...status,
    history: history ?? status.history ?? [],
    capabilities: status.capabilities ?? emptyCapabilities(),
  };
}

function emptyCapabilities(): FilesystemCapability {
  return {
    filesystem: null,
    metadata: false,
    timeline: false,
    rawSearch: false,
    deletedRecovery: false,
    directoryArtifacts: false,
    imaging: true,
    notes: [],
  };
}

function formatSpeed(bytesPerSecond: number): string {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) {
    return "0 B/s";
  }
  return `${formatSize(bytesPerSecond)}/s`;
}

function formatSize(size: number): string {
  if (size < 1024) {
    return `${Math.round(size)} B`;
  }
  if (size < 1024 ** 2) {
    return `${(size / 1024).toFixed(1)} KiB`;
  }
  if (size < 1024 ** 3) {
    return `${(size / 1024 ** 2).toFixed(1)} MiB`;
  }
  return `${(size / 1024 ** 3).toFixed(1)} GiB`;
}

const EMPTY_VALUE = "—";

function deviceTypeLabel(device: DeviceInfo): string {
  return device.removable ? "съёмный" : "несъёмный";
}

function mountpointsLabel(device: DeviceInfo): string {
  return device.mountpoints.length > 0 ? device.mountpoints.join(", ") : "не подключено";
}

function captureStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    queued: "в очереди",
    running: "выполняется",
    complete: "готово",
    cancelled: "отменено",
    error: "ошибка",
  };
  return labels[status] ?? status;
}

function knownText(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const text = value.trim();
  return text && text.toLowerCase() !== "unknown" ? text : undefined;
}

function eventLabel(type: string): string {
  const labels: Record<string, string> = {
    created: "создан",
    modified: "изменён",
    metadata_changed: "свойства",
    accessed: "доступ",
    deleted: "удалён",
    name_trace: "имя/путь",
    content_match: "совпадение в байтах",
    image_created: "образ",
  };
  return labels[type] ?? type;
}

function eventTarget(event: ForensicEvent): string {
  return knownText(event.pathHint) || knownText(event.name) || (event.inode ? `inode #${event.inode}` : EMPTY_VALUE);
}

function maybeNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function maybeString(value: unknown): string {
  return knownText(value) ?? EMPTY_VALUE;
}

function stateLabel(value: unknown): string {
  const labels: Record<string, string> = {
    active: "активен",
    deleted: "удалён",
    wiped: "затёрт",
    unreadable: "не читается",
    unknown: EMPTY_VALUE,
  };
  const text = knownText(value);
  return text ? labels[text] ?? text : EMPTY_VALUE;
}

function evidenceLabel(value: string): string {
  const labels: Record<string, string> = {
    inode_metadata: "свойства inode",
    directory_entry: "запись каталога",
    raw_match: "байты",
    deleted_inode: "удалённый inode",
    image_capture: "снятие образа",
  };
  return labels[value] ?? value;
}

function confidenceLabel(value: string): string {
  const labels: Record<string, string> = {
    high: "высокая",
    medium: "средняя",
    low: "низкая",
  };
  return labels[value] ?? value;
}

function recoverabilityLabel(value: string): string {
  const labels: Record<string, string> = {
    full: "полное",
    partial: "частичное",
    none: "нет",
  };
  return labels[value] ?? value;
}

function makeOperationToken(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

function AppHeader({
  status,
  onOpenDialog,
  onClose,
}: {
  status: SourceStatus;
  onOpenDialog: () => void;
  onClose: () => void;
}) {
  return (
    <header className="app-header">
      <div className="brand-mark" aria-hidden="true">
        <Binary size={22} />
      </div>
      <div className="brand-copy">
        <strong>HexCorruptor</strong>
        <span>анализ образов дисков</span>
      </div>
      <div className="source-pill" title={status.path ?? "Источник не открыт"}>
        <HardDrive size={15} />
        <span>{status.isOpen ? status.name : "Источник не открыт"}</span>
      </div>
      <div className="header-actions">
        <button className="icon-button" type="button" title="Открыть через Electron" onClick={onOpenDialog}>
          <FolderOpen size={16} />
          <span>Открыть</span>
        </button>
        <button className="icon-button quiet" type="button" title="Закрыть источник" onClick={onClose} disabled={!status.isOpen}>
          <Square size={15} />
        </button>
      </div>
    </header>
  );
}

function AppNav({
  activePage,
  status,
  onNavigate,
}: {
  activePage: AppPage;
  status: SourceStatus;
  onNavigate: (page: AppPage) => void;
}) {
  const pages: Array<{ id: AppPage; label: string; icon: React.ReactNode; disabled?: boolean }> = [
    { id: "source", label: "Источник", icon: <FolderOpen size={16} /> },
    { id: "filesystem", label: "ФС", icon: <Database size={16} />, disabled: !status.isOpen },
    { id: "hex", label: "Байты", icon: <Binary size={16} />, disabled: !status.isOpen },
    { id: "forensics", label: "Следы", icon: <FileSearch size={16} />, disabled: !status.isOpen },
    { id: "imaging", label: "Образ", icon: <HardDrive size={16} /> },
  ];

  return (
    <nav className="app-nav" aria-label="Разделы HexCorruptor">
      {pages.map((page) => (
        <button
          className={activePage === page.id ? "active" : ""}
          type="button"
          key={page.id}
          onClick={() => onNavigate(page.id)}
          disabled={page.disabled}
        >
          {page.icon}
          <span>{page.label}</span>
        </button>
      ))}
    </nav>
  );
}

function OpenSourcePanel({
  path,
  writable,
  setPath,
  setWritable,
  onSubmit,
}: {
  path: string;
  writable: boolean;
  setPath: (value: string) => void;
  setWritable: (value: boolean) => void;
  onSubmit: (event: FormEvent) => void;
}) {
  return (
    <form className="open-source" onSubmit={onSubmit}>
      <label htmlFor="path-input">Путь к образу или устройству</label>
      <div className="path-row">
        <input
          id="path-input"
          value={path}
          onChange={(event) => setPath(event.target.value)}
          placeholder="Введите путь к образу или устройству"
          spellCheck={false}
        />
        <button type="submit" className="primary-button">
          Открыть
        </button>
      </div>
      <label className="check-row">
        <input
          type="checkbox"
          checked={writable}
          onChange={(event) => setWritable(event.target.checked)}
        />
        <span>Открыть с записью</span>
      </label>
    </form>
  );
}

function SourceSummary({ status }: { status: SourceStatus }) {
  const rows = [
    ["Режим", status.mode === "read-write" ? "чтение/запись" : status.mode === "read" ? "только чтение" : "закрыт"],
    ["Размер", status.sizeHuman],
    ["Тип", status.isBlockDevice ? "блочное устройство" : "образ/файл"],
    ["ФС", status.filesystem ?? "не распознана"],
  ];

  return (
    <section className="source-summary" aria-label="Сводка источника">
      {rows.map(([label, value]) => (
        <div className="metric" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </section>
  );
}

function NavigationTree({
  status,
  onInfo,
  onStructure,
  onDirectoryInode,
}: {
  status: SourceStatus;
  onInfo: () => void;
  onStructure: (kind: string, index?: number) => void;
  onDirectoryInode: (inode: number) => void;
}) {
  const inodeItems = useMemo(() => {
    const count = Math.min(status.inodeCount || 0, 100);
    return Array.from({ length: count }, (_, index) => index + 1);
  }, [status.inodeCount]);

  const groupItems = useMemo(() => {
    const count = Math.min(status.groupCount || 0, 128);
    return Array.from({ length: count }, (_, index) => index);
  }, [status.groupCount]);

  return (
    <nav className="tree-panel" aria-label="Навигация по файловой системе">
      <button className="tree-row root" type="button" onClick={onInfo}>
        <Database size={16} />
        <span>{status.filesystem ?? "Файловая система"}</span>
      </button>
      <button className="tree-row" type="button" onClick={() => onStructure("superblock")}>
        <FileCode2 size={16} />
        <span>Суперблок</span>
      </button>
      <Collapsible label="Таблица инодов" detail={`${status.inodeCount || 0} шт.`}>
        {inodeItems.map((inode) => (
          <button className="tree-row child" key={inode} type="button" onClick={() => onStructure("inode", inode)}>
            <Hash size={14} />
            <span>Инод #{inode}</span>
          </button>
        ))}
        {status.inodeCount > 100 ? <div className="tree-note">ещё {status.inodeCount - 100}</div> : null}
      </Collapsible>
      <Collapsible label={status.filesystem === "XFS" ? "Группы размещения" : "Группы блоков"} detail={`${status.groupCount || 0} шт.`}>
        {groupItems.map((group) => (
          <button className="tree-row child" key={group} type="button" onClick={() => onStructure("block_group", group)}>
            <Layers3 size={14} />
            <span>Группа #{group}</span>
          </button>
        ))}
        {status.groupCount > 128 ? <div className="tree-note">ещё {status.groupCount - 128}</div> : null}
      </Collapsible>
      {typeof status.rootInode === "number" ? (
        <DirectoryNode inode={status.rootInode} label="Корневой каталог /" onStructure={onStructure} onDirectoryInode={onDirectoryInode} />
      ) : null}
    </nav>
  );
}

function Collapsible({ label, detail, children }: { label: string; detail?: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="tree-group">
      <button className="tree-row" type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        <span>{label}</span>
        {detail ? <em>{detail}</em> : null}
      </button>
      {open ? <div className="tree-children">{children}</div> : null}
    </div>
  );
}

function DirectoryNode({
  inode,
  label,
  onStructure,
  onDirectoryInode,
  depth = 0,
}: {
  inode: number;
  label: string;
  onStructure: (kind: string, index?: number) => void;
  onDirectoryInode: (inode: number) => void;
  depth?: number;
}) {
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<DirectoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    onDirectoryInode(inode);
    if (next && entries.length === 0 && !loading) {
      setLoading(true);
      setError(null);
      try {
        const response = await api.directory(inode);
        setEntries(response.entries.filter((entry) => entry.name !== "." && entry.name !== ".."));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Ошибка чтения каталога");
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div className="tree-group">
      <button className="tree-row" type="button" onClick={toggle} aria-expanded={open}>
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        <span>{label}</span>
        <em>#{inode}</em>
      </button>
      {open ? (
        <div className="tree-children">
          {loading ? <div className="tree-note">загрузка</div> : null}
          {error ? <div className="tree-error">{error}</div> : null}
          {entries.map((entry) =>
            entry.isDirectory && depth < 8 ? (
              <DirectoryNode
                key={`${entry.inode}-${entry.name}`}
                inode={entry.inode}
                label={entry.name}
                depth={depth + 1}
                onStructure={onStructure}
                onDirectoryInode={onDirectoryInode}
              />
            ) : (
              <button className="tree-row child" key={`${entry.inode}-${entry.name}`} type="button" onClick={() => onStructure("inode", entry.inode)}>
                <FileCode2 size={14} />
                <span>{entry.name}</span>
                <em>#{entry.inode}</em>
              </button>
            ),
          )}
          {!loading && entries.length === 0 && !error ? <div className="tree-note">пусто или не прочитано</div> : null}
        </div>
      ) : null}
    </div>
  );
}

function HexView({
  data,
  cursor,
  highlights,
  onSelectByte,
}: {
  data: HexRead | null;
  cursor: number;
  highlights: HighlightRange[];
  onSelectByte: (offset: number, value: number) => void;
}) {
  const bytes = useMemo(() => (data ? toBytes(data.hex) : []), [data]);

  if (!data) {
    return (
      <div className="hex-empty">
        <Binary size={34} />
        <span>Откройте источник, чтобы увидеть hex-дамп</span>
      </div>
    );
  }

  const rows = [];
  for (let rowStart = 0; rowStart < bytes.length; rowStart += BYTES_PER_ROW) {
    const rowBytes = bytes.slice(rowStart, rowStart + BYTES_PER_ROW);
    const rowOffset = data.offset + rowStart;
    rows.push(
      <div className="hex-row" key={rowOffset}>
        <div className="hex-offset">{formatOffset(rowOffset)}</div>
        <div className="hex-bytes">
          {rowBytes.map((byte, index) => {
            const absolute = rowOffset + index;
            const highlight = highlights.find((range) => absolute >= range.offset && absolute < range.offset + range.size);
            return (
              <button
                className={`hex-byte ${absolute === cursor ? "selected" : ""} ${highlight ? `highlight-${highlight.tone}` : ""}`}
                key={absolute}
                type="button"
                onClick={() => onSelectByte(absolute, byte)}
                title={`${formatOffset(absolute)} = ${byte.toString(16).padStart(2, "0").toUpperCase()}`}
              >
                {byte.toString(16).padStart(2, "0").toUpperCase()}
              </button>
            );
          })}
        </div>
        <div className="hex-ascii">
          {rowBytes.map((byte, index) => (
            <span key={`${rowOffset}-${index}`}>{byte >= 32 && byte < 127 ? String.fromCharCode(byte) : "."}</span>
          ))}
        </div>
      </div>,
    );
  }

  return <div className="hex-table">{rows}</div>;
}

function Inspector({
  inspector,
  onFieldSelected,
  history,
}: {
  inspector: InspectorState;
  onFieldSelected: (offset: number, size: number) => void;
  history: string[];
}) {
  if (inspector.mode === "welcome") {
    return (
      <aside className="inspector welcome">
        <div className="inspector-empty">
          <Inspect size={32} />
          <strong>Выберите структуру</strong>
          <span>Суперблок, инод, группу блоков или поле в таблице.</span>
        </div>
        <ChangeJournal history={history} />
      </aside>
    );
  }

  if (inspector.mode === "info") {
    return (
      <aside className="inspector">
        <div className="inspector-head">
          <strong>{inspector.title}</strong>
        </div>
        <div className="info-list">
          {Object.entries(inspector.info).map(([key, value]) => (
            <div className="info-row" key={key}>
              <span>{key}</span>
              <strong>{String(value)}</strong>
            </div>
          ))}
        </div>
        <ChangeJournal history={history} />
      </aside>
    );
  }

  return (
    <aside className="inspector">
      <div className="inspector-head">
        <strong>{inspector.structure.name}</strong>
        {inspector.structure.diskOffset > 0 ? <span>{formatOffset(inspector.structure.diskOffset)}</span> : null}
      </div>
      <div className="field-table" role="table" aria-label="Поля структуры">
        <div className="field-row heading" role="row">
          <span>Поле</span>
          <span>Off</span>
          <span>Hex</span>
          <span>Значение</span>
        </div>
        {inspector.structure.fields.map((field) => (
          <button
            className="field-row"
            key={`${field.name}-${field.offset}`}
            type="button"
            title={`${field.name}: ${String(field.value)}${field.description ? `\n${field.description}` : ""}`}
            onClick={() => {
              if (typeof field.absoluteOffset === "number" && field.size > 0) {
                onFieldSelected(field.absoluteOffset, field.size);
              }
            }}
          >
            <span>{field.name}</span>
            <span>{field.offset >= 0 ? `0x${field.offset.toString(16).toUpperCase()}` : "calc"}</span>
            <span>{field.rawHex || "-"}</span>
            <strong>{String(field.value)}</strong>
          </button>
        ))}
      </div>
      <ChangeJournal history={history} />
    </aside>
  );
}

function ChangeJournal({ history }: { history: string[] }) {
  const recent = history.slice(-5).reverse();
  return (
    <section className="change-journal" aria-label="Журнал изменений">
      <div className="journal-head">
        <span>Журнал изменений</span>
        <strong>{history.length}</strong>
      </div>
      {recent.length > 0 ? (
        <ol>
          {recent.map((entry, index) => (
            <li key={`${entry}-${index}`}>{entry}</li>
          ))}
        </ol>
      ) : (
        <p>Нет операций записи</p>
      )}
    </section>
  );
}

const eventTypeOptions = [
  ["created", "создан"],
  ["modified", "изменён"],
  ["metadata_changed", "свойства"],
  ["accessed", "доступ"],
  ["deleted", "удалён"],
  ["name_trace", "имя"],
  ["content_match", "контент"],
];

function CapabilityStrip({ capabilities }: { capabilities: FilesystemCapability }) {
  const chips = [
    ["свойства файлов", capabilities.metadata],
    ["хронология", capabilities.timeline],
    ["поиск по байтам", capabilities.rawSearch],
    ["восстановление", capabilities.deletedRecovery],
    ["следы имён", capabilities.directoryArtifacts],
    ["снятие образа", capabilities.imaging],
  ];
  return (
    <div className="capability-strip" aria-label="Возможности текущей файловой системы">
      {chips.map(([label, enabled]) => (
        <span className={enabled ? "enabled" : ""} key={String(label)}>
          {enabled ? "✓" : "–"} {label}
        </span>
      ))}
      {capabilities.notes.map((note) => (
        <span className="capability-note" key={note}>{note}</span>
      ))}
    </div>
  );
}

function TimelineList({
  events,
  onOpenDossier,
}: {
  events: ForensicEvent[];
  onOpenDossier: (input: { inode?: number; name?: string; offset?: number }) => void;
}) {
  if (events.length === 0) {
    return (
      <div className="forensics-empty compact">
        <FileSearch size={28} />
        <span>События не найдены для текущего фильтра</span>
      </div>
    );
  }

  return (
    <div className="timeline-list">
      {events.map((event, index) => (
        <button
          className={`timeline-row ${event.timestampEpoch === null ? "undated" : ""}`}
          type="button"
          key={`${event.eventType}-${event.timestampEpoch ?? "none"}-${event.offset ?? ""}-${event.inode ?? ""}-${index}`}
          onClick={() => onOpenDossier({
            inode: event.inode ?? undefined,
            name: event.pathHint || event.name || undefined,
            offset: event.offset ?? undefined,
          })}
        >
          <span>{event.timestampLocal ?? "без времени"}</span>
          <strong>{eventLabel(event.eventType)}</strong>
          <em>{eventTarget(event)}</em>
          <small>{evidenceLabel(event.evidenceType)} · {confidenceLabel(event.confidence)}</small>
        </button>
      ))}
    </div>
  );
}

function DossierView({
  dossier,
  preview,
  loading,
  onOpenInode,
  onGoToBlock,
  onGoToOffset,
  onError,
}: {
  dossier: FileDossier | null;
  preview: DeletedFilePreview | null;
  loading: boolean;
  onOpenInode: (inode: number) => void;
  onGoToBlock: (block: number) => void;
  onGoToOffset: (offset: number) => void;
  onError: (message: string) => void;
}) {
  if (!dossier) {
    return (
      <div className="forensics-empty compact">
        <FileSearch size={28} />
        <span>{loading ? "Загрузка dossier..." : "Выберите след слева, чтобы открыть dossier"}</span>
      </div>
    );
  }

  const inodeRecord = dossier.inodeRecord ?? {};
  const recoverable = dossier.recoverableFile;
  const record = recoverable ?? inodeRecord;
  const inode = recoverable?.inode ?? dossier.inode ?? maybeNumber(inodeRecord.inode);
  const firstBlock = recoverable?.firstBlock ?? null;
  const firstOffset = dossier.offsetPreview?.offset ?? dossier.rawMatches[0]?.offset ?? dossier.names[0]?.diskOffset ?? null;
  const warnings = [
    ...(recoverable?.warnings ?? []),
    ...((Array.isArray(inodeRecord.warnings) ? inodeRecord.warnings : []) as string[]),
  ];
  const extents = recoverable?.extents ?? [];
  const inodeDiskOffset = maybeNumber((record as Record<string, unknown>)["diskOffset"]);
  const dossierTitle = dossier.names[0]?.pathHint || dossier.names[0]?.name || dossier.query || (inode ? `inode #${inode}` : "Байтовый след");
  const sizeText = typeof record.sizeHuman === "string" && record.sizeHuman
    ? record.sizeHuman
    : typeof record.size === "number"
      ? `${record.size} B`
      : EMPTY_VALUE;
  const linksText = record.links !== undefined && record.links !== null ? String(record.links) : EMPTY_VALUE;
  const ownerText = record.uid !== undefined ? `${record.uid}/${record.gid ?? EMPTY_VALUE}` : EMPTY_VALUE;
  const recoveryText = recoverable
    ? `${recoverabilityLabel(recoverable.recoverability)} · ${recoverable.recoverableBytes} B`
    : "нет привязки к inode";
  const currentState = stateLabel(inodeRecord.state);

  return (
    <div className="dossier-view">
      <div className="deleted-detail-head">
        <div>
          <strong>{dossierTitle}</strong>
          <span>ФС: {dossier.sourceFs ?? EMPTY_VALUE} · состояние: {currentState}</span>
        </div>
        <div className="detail-actions">
          <button className="icon-button secondary" type="button" onClick={() => inode && onOpenInode(inode)} disabled={!inode}>
            <Hash size={15} />
            <span>Открыть inode</span>
          </button>
          <button className="icon-button secondary" type="button" onClick={() => firstBlock !== null && onGoToBlock(firstBlock)} disabled={firstBlock === null}>
            <Layers3 size={15} />
            <span>Первый блок</span>
          </button>
          <button className="icon-button secondary" type="button" onClick={() => firstOffset !== null && onGoToOffset(firstOffset)} disabled={firstOffset === null}>
            <LocateFixed size={15} />
            <span>Показать offset</span>
          </button>
          <button className="icon-button" type="button" onClick={() => inode && api.downloadRecoveredFile(inode).catch((err) => onError(err instanceof Error ? err.message : "Ошибка скачивания"))} disabled={!recoverable || !inode}>
            <Download size={15} />
            <span>Скачать файл</span>
          </button>
          <button className="icon-button secondary" type="button" onClick={() => inode && api.downloadDeletedFileReport(inode).catch((err) => onError(err instanceof Error ? err.message : "Ошибка отчёта"))} disabled={!recoverable || !inode}>
            <FileText size={15} />
            <span>Отчёт inode</span>
          </button>
        </div>
      </div>

      <p className="forensics-disclaimer">
        Карточка объединяет свойства inode, следы каталогов и совпадения в байтах. Имя и исходный путь считаются доказанными только при наличии следа каталога или журнала.
      </p>

      <div className="timeline-grid">
        <div><span>номер inode</span><strong>{inode ? `#${inode}` : EMPTY_VALUE}</strong></div>
        <div><span>размер</span><strong>{sizeText}</strong></div>
        <div><span>тип и права</span><strong>{maybeString(record.mode)}</strong></div>
        <div title="Сколько имён каталога или hard links указывает на inode. 0 часто означает удалённый файл.">
          <span>имён/ссылок</span><strong>{linksText}</strong>
        </div>
        <div><span>владелец/группа</span><strong>{ownerText}</strong></div>
        <div><span>восстановление</span><strong>{recoveryText}</strong></div>
        <div><span>создан</span><strong>{maybeString(record.crtime)}</strong></div>
        <div><span>содержимое изменено</span><strong>{maybeString(record.mtime)}</strong></div>
        <div title="Когда менялись свойства файла: права, владелец, размер, ссылки или удаление.">
          <span>свойства изменены</span><strong>{maybeString(record.ctime)}</strong>
        </div>
        <div><span>последний доступ</span><strong>{maybeString(record.atime)}</strong></div>
        <div><span>удалён</span><strong>{maybeString(record.dtime)}</strong></div>
        <div><span>offset записи inode</span><strong>{inodeDiskOffset !== undefined ? formatOffset(inodeDiskOffset) : EMPTY_VALUE}</strong></div>
      </div>

      <div className="dossier-section">
        <div className="artifact-section-title first">
          <strong>Найденные имена</strong>
          <span>{dossier.names.length}</span>
        </div>
        {dossier.names.map((item) => (
          <button className="artifact-row" type="button" key={`${item.diskOffset}-${item.name}`} onClick={() => onGoToOffset(item.diskOffset)}>
            <span>{item.pathHint || item.name}</span>
            <span>{item.inode ? `inode #${item.inode}` : `inode ${EMPTY_VALUE}`}</span>
            <span>{stateLabel(item.inodeState.state)}</span>
            <span>{formatOffset(item.diskOffset)}</span>
          </button>
        ))}
        {dossier.names.length === 0 ? <div className="forensics-note">Имя/path не доказаны для этого следа</div> : null}
      </div>

      <div className="extent-box">
        <strong>Карта блоков</strong>
        <span>{recoverable?.extentSummary ?? "Нет карты блоков для этой ФС или inode"}</span>
        {extents.length > 0 ? (
          <div className="extent-table">
            {extents.slice(0, 16).map((extent) => (
              <button type="button" key={`${extent.logical}-${extent.physical}`} onClick={() => onGoToBlock(extent.physical)}>
                <span>L{extent.logical}</span>
                <span>B{extent.physical}</span>
                <span>×{extent.length}</span>
                <span>{formatOffset(extent.blockStart)}</span>
              </button>
            ))}
          </div>
        ) : null}
      </div>

      <div className="preview-box">
        <strong>Предпросмотр байт</strong>
        <code>{preview?.ascii || dossier.offsetPreview?.previewAscii || dossier.rawMatches[0]?.previewAscii || "preview недоступен"}</code>
        <code>{preview?.hex || dossier.offsetPreview?.previewHex || dossier.rawMatches[0]?.previewHex || ""}</code>
      </div>

      <div className="dossier-section">
        <div className="artifact-section-title first">
          <strong>История следа</strong>
          <span>{dossier.timeline.length}</span>
        </div>
        <TimelineList events={dossier.timeline.slice(0, 80)} onOpenDossier={() => undefined} />
      </div>

      {warnings.length > 0 ? (
        <div className="warning-list">
          {warnings.map((warning) => <span key={warning}>{warning}</span>)}
        </div>
      ) : null}
    </div>
  );
}

function ForensicsPanel({
  status,
  onOpenInode,
  onGoToBlock,
  onGoToOffset,
  onMessage,
  onError,
}: {
  status: SourceStatus;
  onOpenInode: (inode: number) => void;
  onGoToBlock: (block: number) => void;
  onGoToOffset: (offset: number) => void;
  onMessage: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [view, setView] = useState<"search" | "timeline" | "dossier">("search");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [searchResult, setSearchResult] = useState<ForensicSearchResponse | null>(null);
  const [timeline, setTimeline] = useState<ForensicTimelineResponse | null>(null);
  const [dossier, setDossier] = useState<FileDossier | null>(null);
  const [preview, setPreview] = useState<DeletedFilePreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [operation, setOperation] = useState<"поиск" | "timeline" | "dossier" | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const cancelTokenRef = useRef<string | null>(null);

  const capabilities = status.capabilities ?? emptyCapabilities();
  const typeFilter = eventTypes.join(",");

  const beginOperation = (nextOperation: "поиск" | "timeline" | "dossier") => {
    if (abortRef.current && cancelTokenRef.current) {
      abortRef.current.abort();
      api.cancelForensics(cancelTokenRef.current).catch(() => undefined);
    }
    const controller = new AbortController();
    const token = makeOperationToken();
    abortRef.current = controller;
    cancelTokenRef.current = token;
    setLoading(true);
    setOperation(nextOperation);
    return { controller, token };
  };

  const finishOperation = (controller: AbortController) => {
    if (abortRef.current === controller) {
      abortRef.current = null;
      cancelTokenRef.current = null;
      setLoading(false);
      setOperation(null);
    }
  };

  const cancelOperation = () => {
    const token = cancelTokenRef.current;
    abortRef.current?.abort();
    if (token) {
      api.cancelForensics(token).catch(() => undefined);
    }
    abortRef.current = null;
    cancelTokenRef.current = null;
    setLoading(false);
    setOperation(null);
    onMessage("Операция отменена");
  };

  const openDossier = async (input: { inode?: number; name?: string; offset?: number }) => {
    const { controller, token } = beginOperation("dossier");
    setView("dossier");
    setDossier(null);
    setPreview(null);
    try {
      const next = await api.fileDossier({ ...input, cancelToken: token, signal: controller.signal });
      setDossier(next);
      setPreview(null);
      if (next.recoverableFile?.inode) {
        try {
          setPreview(await api.deletedFilePreview(next.recoverableFile.inode));
        } catch {
          setPreview(null);
        }
      }
      onMessage("Карточка открыта");
    } catch (err) {
      if (isAbortError(err)) {
        onMessage("Операция отменена");
      } else {
        onError(err instanceof Error ? err.message : "Ошибка карточки");
      }
    } finally {
      finishOperation(controller);
    }
  };

  const runSearch = async () => {
    if (!status.isOpen) {
      onError("Источник не открыт");
      return;
    }
    const { controller, token } = beginOperation("поиск");
    try {
      const response = await api.forensicSearch(query.trim(), {
        from: fromDate,
        to: toDate,
        types: typeFilter,
        limit: 160,
        cancelToken: token,
        signal: controller.signal,
      });
      setSearchResult(response);
      setTimeline(null);
      setDossier(null);
      setPreview(null);
      setView("search");
      onMessage(
        `Найдено: имена ${response.names.length}, байты ${response.content.length}, события ${response.timelineEvents.length}, восстановление ${response.recoverableInodes.length}`,
      );
    } catch (err) {
      if (isAbortError(err)) {
        onMessage("Операция отменена");
      } else {
        onError(err instanceof Error ? err.message : "Ошибка forensic search");
      }
    } finally {
      finishOperation(controller);
    }
  };

  const loadTimeline = async () => {
    if (!status.isOpen) {
      onError("Источник не открыт");
      return;
    }
    const { controller, token } = beginOperation("timeline");
    try {
      const response = await api.forensicTimeline({
        query: query.trim(),
        from: fromDate,
        to: toDate,
        eventTypes: typeFilter,
        limit: 1200,
        cancelToken: token,
        signal: controller.signal,
      });
      setTimeline(response);
      setView("timeline");
      onMessage(`Событий: ${response.total}; без времени: ${response.undated}`);
    } catch (err) {
      if (isAbortError(err)) {
        onMessage("Операция отменена");
      } else {
        onError(err instanceof Error ? err.message : "Ошибка хронологии");
      }
    } finally {
      finishOperation(controller);
    }
  };

  const toggleEventType = (type: string) => {
    setEventTypes((current) => (
      current.includes(type)
        ? current.filter((item) => item !== type)
        : [...current, type]
    ));
  };

  const downloadReport = (format: "markdown" | "json") => {
    api.downloadForensicsReport(format, query.trim(), fromDate, toDate)
      .catch((err) => onError(err instanceof Error ? err.message : "Ошибка экспорта отчёта"));
  };

  const names = searchResult?.names ?? [];
  const content = searchResult?.content ?? [];
  const recoverable = searchResult?.recoverableInodes ?? [];
  const timelineEvents = searchResult?.timelineEvents ?? [];
  const activeTimeline = timeline?.events ?? timelineEvents;

  if (!status.isOpen) {
    return (
      <div className="forensics-empty">
        <FileSearch size={34} />
        <strong>Откройте образ или устройство</strong>
        <span>После открытия можно искать имена, пути, текст, hex и inode.</span>
      </div>
    );
  }

  return (
    <div className="forensics-panel v2">
      <div className="forensics-head">
        <div>
          <strong>Поиск следов</strong>
          <span>Найдите совпадения, проверьте хронологию и сохраните отчёт.</span>
        </div>
        <div className="forensics-tabs" aria-label="Режим поиска следов">
          <button className={view === "search" ? "active" : ""} type="button" onClick={() => setView("search")}>Поиск</button>
          <button className={view === "timeline" ? "active" : ""} type="button" onClick={loadTimeline}>Хронология</button>
          <button className={view === "dossier" ? "active" : ""} type="button" onClick={() => setView("dossier")}>Карточка</button>
        </div>
      </div>

      <div className="forensics-searchbar v3">
        <label className="primary-search">
          <span>Имя, путь, текст, hex или inode</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => event.key === "Enter" && runSearch()}
            placeholder="Введите запрос для поиска"
          />
        </label>
        <button className="primary-button search-button" type="button" onClick={runSearch} disabled={loading || (!query.trim() && !capabilities.deletedRecovery)}>
          <Search size={16} />
          <span>{operation === "поиск" ? "Ищу" : "Найти"}</span>
        </button>
        <button className="icon-button secondary" type="button" onClick={loadTimeline} disabled={loading || !capabilities.timeline}>
          <FileSearch size={15} />
          <span>{operation === "timeline" ? "Строю" : "Хронология"}</span>
        </button>
        {loading ? (
          <button className="icon-button secondary cancel-button" type="button" onClick={cancelOperation}>
            <Square size={15} />
            <span>Отмена</span>
          </button>
        ) : null}
        <button className="icon-button secondary" type="button" onClick={() => setFiltersOpen((value) => !value)}>
          <ChevronDown size={15} />
          <span>Фильтры</span>
        </button>
        <button className="icon-button secondary" type="button" onClick={() => downloadReport("markdown")} disabled={loading}>
          <FileText size={15} />
          <span>MD</span>
        </button>
        <button className="icon-button secondary" type="button" onClick={() => downloadReport("json")} disabled={loading}>
          <Download size={15} />
          <span>JSON</span>
        </button>
      </div>

      {filtersOpen ? (
        <div className="forensics-options">
          <div className="date-filter-row">
            <label>
              <span>с даты</span>
              <input type="date" value={fromDate} onChange={(event) => setFromDate(event.target.value)} />
            </label>
            <label>
              <span>по дату</span>
              <input type="date" value={toDate} onChange={(event) => setToDate(event.target.value)} />
            </label>
          </div>
          <div className="event-filter-grid">
            {eventTypeOptions.map(([type, label]) => (
              <label className="check-row compact-check" key={type}>
                <input type="checkbox" checked={eventTypes.includes(type)} onChange={() => toggleEventType(type)} />
                <span>{label}</span>
              </label>
            ))}
          </div>
          <CapabilityStrip capabilities={capabilities} />
        </div>
      ) : null}

      <div className="forensics-result-summary" aria-label="Сводка forensic results">
        <div>
          <span>Имена</span>
          <strong>{names.length}</strong>
        </div>
        <div>
          <span>Содержимое</span>
          <strong>{content.length}</strong>
        </div>
        <div>
          <span>События</span>
          <strong>{activeTimeline.length}</strong>
        </div>
        <div>
          <span>Восстановление</span>
          <strong>{recoverable.length}</strong>
        </div>
      </div>

      <div className={`forensics-body ${view}`}>
        {view === "search" ? (
        <div className="forensics-results-page evidence-list">
          <div className="artifact-section-title first">
            <strong>Найденные имена</strong>
            <span>{searchResult ? names.length : "нет поиска"}</span>
          </div>
          {names.map((item) => (
            <button className="artifact-row" type="button" key={`${item.diskOffset}-${item.name}`} onClick={() => openDossier({ inode: item.inode, name: item.pathHint || item.name, offset: item.diskOffset })}>
              <span>{item.pathHint || item.name}</span>
              <span>{item.inode ? `inode #${item.inode}` : `inode ${EMPTY_VALUE}`}</span>
              <span>{stateLabel(item.inodeState.state)}</span>
              <span>{formatOffset(item.diskOffset)}</span>
            </button>
          ))}
          {searchResult && names.length === 0 ? <div className="forensics-note">Имена/path не найдены. Это нормально, если удаление затёрло directory entry.</div> : null}

          <div className="artifact-section-title">
            <strong>Совпадения в байтах</strong>
            <span>{searchResult ? content.length : "нет поиска"}</span>
          </div>
          {content.map((item) => (
            <button className="artifact-row raw" type="button" key={item.offset} onClick={() => openDossier({ name: query.trim(), offset: item.offset })}>
              <span>{query || "match"}</span>
              <span>{formatOffset(item.offset)}</span>
              <span>{item.length} B</span>
              <span>{item.previewAscii}</span>
            </button>
          ))}
          {searchResult && content.length === 0 ? <div className="forensics-note">Совпадений в байтах не найдено</div> : null}

          <div className="artifact-section-title">
            <strong>События</strong>
            <span>{activeTimeline.length}</span>
          </div>
          <TimelineList events={activeTimeline.slice(0, 50)} onOpenDossier={openDossier} />

          <div className="artifact-section-title">
            <strong>Восстановимые файлы</strong>
            <span>{capabilities.deletedRecovery ? recoverable.length : "не поддерживается"}</span>
          </div>
          <div className="deleted-table heading">
            <span>Inode</span>
            <span>Размер</span>
            <span>Удалён</span>
            <span>Создан</span>
            <span>Восстановление</span>
          </div>
          {recoverable.map((item) => (
            <button className="deleted-table" type="button" key={item.inode} onClick={() => openDossier({ inode: item.inode })}>
              <span>#{item.inode}</span>
              <span>{item.sizeHuman}</span>
              <span>{item.dtime ?? "ссылок: 0"}</span>
              <span>{item.crtime ?? EMPTY_VALUE}</span>
              <span>{recoverabilityLabel(item.recoverability)} · {item.recoverableBytes} B</span>
            </button>
          ))}
          {searchResult && recoverable.length === 0 ? (
            <div className="forensics-note">
              {capabilities.deletedRecovery ? "Восстановимые inode не найдены в текущем поиске" : "Глубокое восстановление удалённых файлов пока доступно только для ext4"}
            </div>
          ) : null}
        </div>
        ) : null}

        {view === "timeline" ? (
          <div className="forensics-single-view timeline-page">
            <div className="deleted-detail-head">
              <div>
                <strong>Хронология</strong>
                <span>{timeline ? `${timeline.total} событий, ${timeline.undated} без времени` : "постройте хронологию"}</span>
              </div>
            </div>
            <TimelineList events={activeTimeline} onOpenDossier={openDossier} />
          </div>
        ) : null}

        {view === "dossier" ? (
          <div className="forensics-single-view dossier-page">
            <div className="dossier-nav">
              <button className="icon-button secondary" type="button" onClick={() => setView("search")}>
                <FileSearch size={15} />
                <span>К результатам</span>
              </button>
              <span>{dossier ? "Открыта карточка выбранного следа" : "Карточка не выбрана"}</span>
            </div>
            <DossierView
              dossier={dossier}
              preview={preview}
              loading={loading && operation === "dossier"}
              onOpenInode={onOpenInode}
              onGoToBlock={onGoToBlock}
              onGoToOffset={onGoToOffset}
              onError={onError}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}

function ImageCaptureWizard({
  open,
  onClose,
  onMessage,
  onError,
  onOpenImage,
  embedded = false,
}: {
  open: boolean;
  onClose: () => void;
  onMessage: (message: string) => void;
  onError: (message: string) => void;
  onOpenImage: (path: string) => void;
  embedded?: boolean;
}) {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [platformName, setPlatformName] = useState("");
  const [selectedPath, setSelectedPath] = useState("");
  const [destination, setDestination] = useState("");
  const [unmount, setUnmount] = useState(true);
  const [job, setJob] = useState<ImageCaptureJob | null>(null);
  const [loading, setLoading] = useState(false);
  const deviceRequestRef = useRef(0);

  const selectedDevice = devices.find((device) => device.path === selectedPath) ?? null;

  const loadDevices = useCallback(async () => {
    const requestId = deviceRequestRef.current + 1;
    deviceRequestRef.current = requestId;
    setLoading(true);
    try {
      const response = await api.devices();
      if (deviceRequestRef.current !== requestId) {
        return;
      }
      setDevices(response.devices);
      setPlatformName(response.platform);
      setSelectedPath((current) => current || response.devices[0]?.path || "");
      onMessage(`Устройств найдено: ${response.devices.length}`);
    } catch (err) {
      if (deviceRequestRef.current === requestId) {
        onError(err instanceof Error ? err.message : "Ошибка списка устройств");
      }
    } finally {
      if (deviceRequestRef.current === requestId) {
        setLoading(false);
      }
    }
  }, [onError, onMessage]);

  useEffect(() => {
    if (open) {
      loadDevices().catch(() => undefined);
    }
  }, [loadDevices, open]);

  useEffect(() => {
    if (!job || !["queued", "running"].includes(job.status)) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      api.captureJob(job.jobId)
        .then(setJob)
        .catch((err) => onError(err instanceof Error ? err.message : "Ошибка статуса capture"));
    }, 900);
    return () => window.clearInterval(timer);
  }, [job, onError]);

  const chooseDestination = async () => {
    if (!window.hexCorruptor?.saveImageDialog) {
      onError("Диалог сохранения доступен через Electron. В браузере впишите путь вручную.");
      return;
    }
    const path = await window.hexCorruptor.saveImageDialog();
    if (path) {
      setDestination(path);
    }
  };

  const startCapture = async () => {
    if (!selectedPath || !destination) {
      onError("Выберите устройство и путь для нового образа");
      return;
    }
    if (selectedDevice && destination.startsWith(selectedDevice.path)) {
      onError("Новый образ нельзя сохранять на исходное устройство");
      return;
    }
    setLoading(true);
    try {
      const next = await api.startCapture(selectedPath, destination, unmount);
      setJob(next);
      onMessage("Снятие образа запущено в режиме только чтения");
    } catch (err) {
      onError(err instanceof Error ? err.message : "Ошибка запуска capture");
    } finally {
      setLoading(false);
    }
  };

  const cancelCapture = async () => {
    if (!job) {
      return;
    }
    try {
      setJob(await api.cancelCapture(job.jobId));
      onMessage("Отмена capture запрошена");
    } catch (err) {
      onError(err instanceof Error ? err.message : "Ошибка отмены capture");
    }
  };

  if (!open) {
    return null;
  }

  const progressPercent = job ? Math.round((job.progress || 0) * 100) : 0;

  const content = (
      <section className={`capture-modal ${embedded ? "embedded" : ""}`}>
        <div className="capture-head">
          <div>
            <strong>Снять образ устройства</strong>
            <span>Копирование устройства в файл с SHA256 и журналом операции</span>
          </div>
          {!embedded ? (
            <button className="icon-button quiet" type="button" onClick={onClose} title="Закрыть">
              <Square size={15} />
            </button>
          ) : null}
        </div>

        <div className="capture-actions">
          <button className="icon-button secondary" type="button" onClick={() => loadDevices()} disabled={loading}>
            <HardDrive size={15} />
            <span>Обновить</span>
          </button>
          <span>{platformName || EMPTY_VALUE}</span>
        </div>

        <div className="capture-grid">
          <div className="device-list">
            {devices.map((device) => (
              <button
                className={`device-row ${selectedPath === device.path ? "selected" : ""}`}
                type="button"
                key={device.path}
                onClick={() => setSelectedPath(device.path)}
              >
                <strong>{device.displayName || device.id}</strong>
                <span>{device.path} · {device.sizeHuman} · {device.filesystem}</span>
                <em>{deviceTypeLabel(device)} · {mountpointsLabel(device)}</em>
              </button>
            ))}
            {devices.length === 0 ? <div className="forensics-note">Устройства не найдены или нет доступа к системному списку</div> : null}
          </div>

          <div className="capture-form">
            <label>
              Исходное устройство
              <input value={selectedPath} onChange={(event) => setSelectedPath(event.target.value)} placeholder="Введите путь к устройству" />
            </label>
            <label>
              Новый образ
              <div className="path-row">
                <input value={destination} onChange={(event) => setDestination(event.target.value)} placeholder="Введите путь для нового образа" />
                <button className="icon-button secondary" type="button" onClick={chooseDestination}>
                  <FolderOpen size={15} />
                  <span>Выбрать</span>
                </button>
              </div>
            </label>
            <label className="check-row">
              <input type="checkbox" checked={unmount} onChange={(event) => setUnmount(event.target.checked)} />
              <span>Отключить перед копированием</span>
            </label>
            <div className="forensics-disclaimer">
              Исходное устройство читается только на чтение. Перед запуском проверьте путь, размер и модель.
            </div>
            <button className="primary-button" type="button" onClick={startCapture} disabled={loading || !selectedPath || !destination || job?.status === "running"}>
              <Download size={15} />
              <span>Начать снятие образа</span>
            </button>

            {job ? (
              <div className="capture-job">
                <div>
                  <span>статус</span>
                  <strong>{captureStatusLabel(job.status)}</strong>
                </div>
                <div>
                  <span>прогресс</span>
                  <strong>{progressPercent}% · {formatSize(job.bytesCopied)} / {job.totalBytes ? formatSize(job.totalBytes) : EMPTY_VALUE}</strong>
                </div>
                <div>
                  <span>скорость</span>
                  <strong>{formatSpeed(job.speedBytesPerSec)}</strong>
                </div>
                <div>
                  <span>sha256</span>
                  <strong>{job.sha256 ?? "ожидается"}</strong>
                </div>
                <div className="capture-progress"><span style={{ width: `${progressPercent}%` }} /></div>
                {job.error ? <div className="tree-error">{job.error}</div> : null}
                <div className="detail-actions">
                  <button className="icon-button secondary" type="button" onClick={cancelCapture} disabled={!["queued", "running"].includes(job.status)}>
                    Отменить
                  </button>
                  <button className="icon-button" type="button" onClick={() => onOpenImage(job.destination)} disabled={job.status !== "complete"}>
                    Открыть образ
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </section>
  );

  if (embedded) {
    return content;
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Снять образ">
      {content}
    </div>
  );
}

export function App() {
  const [status, setStatus] = useState<SourceStatus>({
    isOpen: false,
    path: null,
    name: null,
    size: 0,
    sizeHuman: "0 B",
    mode: "closed",
    isBlockDevice: false,
    filesystem: null,
    fsInfo: {},
    rootInode: null,
    blockSize: 4096,
    inodeCount: 0,
    groupCount: 0,
    canUndo: false,
    canRedo: false,
    history: [],
    capabilities: emptyCapabilities(),
  });
  const [pathInput, setPathInput] = useState("");
  const [writable, setWritable] = useState(false);
  const [hexData, setHexData] = useState<HexRead | null>(null);
  const [offsetText, setOffsetText] = useState("0");
  const [inodeText, setInodeText] = useState("2");
  const [blockText, setBlockText] = useState("0");
  const [cursor, setCursor] = useState(0);
  const [selectedByte, setSelectedByte] = useState<{ offset: number; value: number } | null>(null);
  const [byteDraft, setByteDraft] = useState("");
  const [inspector, setInspector] = useState<InspectorState>({ mode: "welcome" });
  const [highlights, setHighlights] = useState<HighlightRange[]>([]);
  const [searchValue, setSearchValue] = useState("");
  const [replaceValue, setReplaceValue] = useState("");
  const [encoding, setEncoding] = useState("ascii");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activePage, setActivePage] = useState<AppPage>("source");
  const [imagingOpen, setImagingOpen] = useState(false);
  const offsetInputRef = useRef<HTMLInputElement>(null);
  const inodeInputRef = useRef<HTMLInputElement>(null);
  const blockInputRef = useRef<HTMLInputElement>(null);

  const loadHex = useCallback(async (offset: number) => {
    const next = Math.max(0, offset);
    const data = await api.read(next, READ_LENGTH);
    setHexData(data);
    setOffsetText(String(next));
    setCursor(next);
  }, []);

  const refreshStatus = useCallback(async () => {
    const next = await api.status();
    const normalized = normalizeStatus(next);
    setStatus(normalized);
    if (next.isOpen && Object.keys(next.fsInfo).length > 0) {
      setInspector({ mode: "info", title: next.filesystem ? `Файловая система: ${next.filesystem}` : "Информация", info: next.fsInfo });
    }
  }, []);

  useEffect(() => {
    refreshStatus().catch(() => undefined);
  }, [refreshStatus]);

  const runAction = useCallback(async (action: () => Promise<void>, success?: string) => {
    setError(null);
    setMessage(null);
    try {
      await action();
      if (success) {
        setMessage(success);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Неизвестная ошибка");
    }
  }, []);

  const openSource = (event: FormEvent) => {
    event.preventDefault();
    runAction(async () => {
      const next = await api.open(pathInput, writable);
      setStatus(normalizeStatus(next));
      setInspector({ mode: "info", title: next.filesystem ? `Файловая система: ${next.filesystem}` : "Файловая система не распознана", info: next.fsInfo });
      setActivePage("filesystem");
      await loadHex(0);
    }, "Источник открыт");
  };

  const openDialog = () => {
    runAction(async () => {
      if (!window.hexCorruptor) {
        throw new Error("Диалог выбора файла доступен при запуске через Electron. В браузере вставьте путь вручную.");
      }
      const path = await window.hexCorruptor.openImageDialog();
      if (!path) {
        return;
      }
      setPathInput(path);
      const next = await api.open(path, writable);
      setStatus(normalizeStatus(next));
      setInspector({ mode: "info", title: next.filesystem ? `Файловая система: ${next.filesystem}` : "Файловая система не распознана", info: next.fsInfo });
      setActivePage("filesystem");
      await loadHex(0);
    });
  };

  const closeSource = () => {
    runAction(async () => {
      const next = await api.close();
      setStatus(normalizeStatus(next));
      setHexData(null);
      setInspector({ mode: "welcome" });
      setHighlights([]);
      setSelectedByte(null);
      setActivePage("source");
    }, "Источник закрыт");
  };

  const openCapturedImage = useCallback((path: string) => {
    runAction(async () => {
      const next = await api.open(path, false);
      setPathInput(path);
      setStatus(normalizeStatus(next));
      setInspector({ mode: "info", title: next.filesystem ? `Файловая система: ${next.filesystem}` : "Файловая система не распознана", info: next.fsInfo });
      setActivePage("filesystem");
      setImagingOpen(false);
      await loadHex(0);
    }, "Снятый образ открыт");
  }, [loadHex, runAction]);

  const showStructure = useCallback((kind: string, index?: number) => {
    runAction(async () => {
      const structure = await api.structure(kind, index);
      setInspector({ mode: "structure", structure });
      setHighlights(
        structure.fields
          .filter((field) => typeof field.absoluteOffset === "number" && field.size > 0)
          .map((field) => ({ offset: field.absoluteOffset as number, size: field.size, tone: "field" })),
      );
      if (structure.diskOffset > 0) {
        await loadHex(structure.diskOffset);
      }
    });
  }, [loadHex, runAction]);

  const showInfo = useCallback(() => {
    setInspector({ mode: "info", title: status.filesystem ? `Файловая система: ${status.filesystem}` : "Информация", info: status.fsInfo });
  }, [status.filesystem, status.fsInfo]);

  const gotoOffset = () => {
    runAction(async () => {
      await loadHex(parseOffset(offsetText));
      setHighlights([]);
    });
  };

  const gotoBlock = () => {
    runAction(async () => {
      const block = parseOffset(blockText);
      await loadHex(block * status.blockSize);
      setHighlights([]);
    });
  };

  const gotoInode = () => {
    runAction(async () => {
      const inode = parseOffset(inodeText);
      if (inode < 1) {
        throw new Error("Номер инода должен быть больше 0");
      }
      showStructure("inode", inode);
    });
  };

  const gotoRoot = useCallback(() => {
    if (typeof status.rootInode === "number") {
      setInodeText(String(status.rootInode));
      showStructure("inode", status.rootInode);
    }
  }, [showStructure, status.rootInode]);

  const onSelectByte = (offset: number, value: number) => {
    setCursor(offset);
    setSelectedByte({ offset, value });
    setByteDraft(value.toString(16).padStart(2, "0").toUpperCase());
    setHighlights([{ offset, size: 1, tone: "edit" }]);
  };

  const applyByteEdit = () => {
    runAction(async () => {
      if (!selectedByte) {
        return;
      }
      const text = byteDraft.trim();
      if (!/^[0-9a-fA-F]{2}$/.test(text)) {
        throw new Error("Байт должен быть hex-значением из двух символов");
      }
      const result = await api.write(selectedByte.offset, text);
      setStatus(normalizeStatus(result.status, result.history));
      await loadHex(hexData?.offset ?? selectedByte.offset);
      setHighlights([{ offset: selectedByte.offset, size: 1, tone: "edit" }]);
    }, "Байт записан");
  };

  const searchNext = () => {
    runAction(async () => {
      const result = await api.search(searchValue, encoding, cursor + 1);
      if (!result.found || result.offset === null) {
        setMessage("Шаблон не найден");
        return;
      }
      setHighlights([{ offset: result.offset, size: result.length, tone: "search" }]);
      await loadHex(result.offset);
      try {
        const owners = await api.owners(result.offset);
        const owner = owners.candidates[0];
        if (owner) {
          setInodeText(String(owner.inode));
          setInspector({
            mode: "info",
            title: `Кандидат владельца блока: inode #${owner.inode}`,
            info: {
              "Найденный offset": formatOffset(result.offset),
              "Физический блок": String(owners.physicalBlock),
              "Смещение в блоке": String(owners.byteOffsetInBlock),
              "Тип inode": inodeKind(owner.mode),
              "Состояние": owner.deleted ? "удалён / нет ссылок" : "активен",
              "Размер": owner.size,
              "Создан": owner.crtime,
              "Данные изменены": owner.mtime,
              "Метаданные изменены": owner.ctime,
              "Удалён": owner.dtime,
              "Последний доступ": owner.atime,
              "Ссылок": String(owner.links),
              "Логический блок файла": String(owner.blockIndex),
            },
          });
          setMessage(`Найдено ${formatOffset(result.offset)}; кандидат inode #${owner.inode}`);
        } else {
          setMessage(`Найдено ${formatOffset(result.offset)}; inode-владелец не найден`);
        }
      } catch {
        setMessage(`Найдено ${formatOffset(result.offset)}`);
      }
    });
  };

  const replace = (all: boolean) => {
    runAction(async () => {
      const result = await api.replace(searchValue, replaceValue, encoding, cursor, all);
      setStatus(normalizeStatus(result.status, result.history));
      if (result.offsets[0] !== undefined) {
        const size = decodedByteLength(replaceValue || searchValue, encoding);
        setHighlights(result.offsets.slice(0, 64).map((offset) => ({ offset, size, tone: "search" })));
        await loadHex(result.offsets[0]);
      }
      setMessage(`Заменено: ${result.count}`);
    });
  };

  const undoRedo = (type: "undo" | "redo") => {
    runAction(async () => {
      const result = type === "undo" ? await api.undo() : await api.redo();
      setStatus(normalizeStatus(result.status, result.history));
      await loadHex(hexData?.offset ?? 0);
    }, type === "undo" ? "Отменено" : "Повторено");
  };

  const onFieldSelected = (offset: number, size: number) => {
    runAction(async () => {
      setHighlights([{ offset, size, tone: "field" }]);
      await loadHex(offset);
    });
  };

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey && event.key.toLowerCase() === "g") {
        event.preventDefault();
        offsetInputRef.current?.focus();
        offsetInputRef.current?.select();
      } else if (event.ctrlKey && event.key.toLowerCase() === "i") {
        event.preventDefault();
        inodeInputRef.current?.focus();
        inodeInputRef.current?.select();
      } else if (event.ctrlKey && event.key.toLowerCase() === "b") {
        event.preventDefault();
        blockInputRef.current?.focus();
        blockInputRef.current?.select();
      } else if (event.key === "F2" && status.filesystem) {
        event.preventDefault();
        setActivePage("filesystem");
        showStructure("superblock");
      } else if (event.key === "F3" && typeof status.rootInode === "number") {
        event.preventDefault();
        setActivePage("filesystem");
        gotoRoot();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [status.filesystem, status.rootInode, showStructure, gotoRoot]);

  useEffect(() => {
    if (!message && !error) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setMessage(null);
      setError(null);
    }, error ? 8000 : 3500);
    return () => window.clearTimeout(timer);
  }, [message, error]);

  return (
    <div className="app-shell">
      <AppHeader
        status={status}
        onOpenDialog={openDialog}
        onClose={closeSource}
      />
      <ImageCaptureWizard
        open={imagingOpen}
        onClose={() => setImagingOpen(false)}
        onMessage={(nextMessage) => {
          setError(null);
          setMessage(nextMessage);
        }}
        onError={(nextError) => {
          setMessage(null);
          setError(nextError);
        }}
        onOpenImage={openCapturedImage}
      />
      <AppNav activePage={activePage} status={status} onNavigate={setActivePage} />
      <main className="workspace pages">
        {activePage === "source" ? (
          <section className="page page-source">
            <div className="page-head">
              <div>
                <strong>Источник</strong>
                <span>Откройте образ или устройство, чтобы перейти к анализу.</span>
              </div>
            </div>
            <div className="source-page-grid">
              <div className="page-panel">
                <OpenSourcePanel
                  path={pathInput}
                  writable={writable}
                  setPath={setPathInput}
                  setWritable={setWritable}
                  onSubmit={openSource}
                />
              </div>
              <div className="page-panel">
                <SourceSummary status={status} />
                <CapabilityStrip capabilities={status.capabilities ?? emptyCapabilities()} />
              </div>
              <div className="page-panel source-info-panel">
                <Inspector inspector={inspector} onFieldSelected={onFieldSelected} history={status.history ?? []} />
              </div>
            </div>
          </section>
        ) : null}

        {activePage === "filesystem" ? (
          <section className="page page-filesystem">
            <div className="page-head">
              <div>
                <strong>Файловая система</strong>
                <span>Дерево каталогов, суперблок, таблица inode и группы блоков.</span>
              </div>
              <div className="detail-actions">
                <button className="icon-button secondary" type="button" onClick={showInfo} disabled={!status.isOpen}>
                  <Database size={15} />
                  <span>Сводка</span>
                </button>
                <button className="icon-button secondary" type="button" onClick={() => showStructure("superblock")} disabled={!status.filesystem}>
                  <FileCode2 size={15} />
                  <span>Суперблок</span>
                </button>
                <button className="icon-button secondary" type="button" onClick={gotoRoot} disabled={typeof status.rootInode !== "number"}>
                  <Hash size={15} />
                  <span>Корневой inode</span>
                </button>
              </div>
            </div>
            {status.isOpen && status.filesystem ? (
              <div className="filesystem-page-grid">
                <aside className="fs-tree-panel">
                  <SourceSummary status={status} />
                  <NavigationTree
                    status={status}
                    onInfo={showInfo}
                    onStructure={showStructure}
                    onDirectoryInode={(inode) => showStructure("inode", inode)}
                  />
                </aside>
                <Inspector inspector={inspector} onFieldSelected={onFieldSelected} history={status.history ?? []} />
              </div>
            ) : (
              <div className="forensics-empty">
                <ShieldCheck size={28} />
                <strong>Источник не открыт</strong>
                <span>Откройте образ на вкладке “Источник”, затем вернитесь сюда.</span>
              </div>
            )}
          </section>
        ) : null}

        {activePage === "hex" ? (
          <section className="page page-hex">
            <div className="toolbar">
              <div className="control-group">
                <label htmlFor="offset">Смещение</label>
                <input ref={offsetInputRef} id="offset" value={offsetText} onChange={(event) => setOffsetText(event.target.value)} onKeyDown={(event) => event.key === "Enter" && gotoOffset()} />
                <button className="icon-button" type="button" title="Перейти к смещению" onClick={gotoOffset} disabled={!status.isOpen}>
                  <LocateFixed size={15} />
                </button>
              </div>
              <div className="control-group">
                <label htmlFor="inode">Inode</label>
                <input ref={inodeInputRef} className="nav-input" id="inode" value={inodeText} onChange={(event) => setInodeText(event.target.value)} onKeyDown={(event) => event.key === "Enter" && gotoInode()} />
                <button className="icon-button secondary" type="button" title="Перейти к иноду" onClick={gotoInode} disabled={!status.filesystem}>
                  <Hash size={15} />
                </button>
                <label htmlFor="block">Блок</label>
                <input ref={blockInputRef} className="nav-input" id="block" value={blockText} onChange={(event) => setBlockText(event.target.value)} onKeyDown={(event) => event.key === "Enter" && gotoBlock()} />
                <button className="icon-button secondary" type="button" title="Перейти к блоку" onClick={gotoBlock} disabled={!status.isOpen || !status.filesystem}>
                  <Layers3 size={15} />
                </button>
              </div>
              <div className="control-group">
                <button className="icon-button quiet labeled" type="button" title="Показать суперблок" aria-label="Суперблок" onClick={() => showStructure("superblock")} disabled={!status.filesystem}>
                  <FileCode2 size={15} />
                  <span>Суперблок</span>
                </button>
                <button className="icon-button quiet labeled" type="button" title="Корневой каталог" aria-label="Корневой каталог" onClick={gotoRoot} disabled={typeof status.rootInode !== "number"}>
                  <Database size={15} />
                  <span>Корень</span>
                </button>
                <button className="icon-button quiet" type="button" title="Отменить" onClick={() => undoRedo("undo")} disabled={!status.canUndo}>
                  <RotateCcw size={15} />
                </button>
                <button className="icon-button quiet" type="button" title="Вернуть" onClick={() => undoRedo("redo")} disabled={!status.canRedo}>
                  <RotateCw size={15} />
                </button>
              </div>
            </div>

            <div className="hex-page-grid">
              <div className="hex-surface">
                <HexView data={hexData} cursor={cursor} highlights={highlights} onSelectByte={onSelectByte} />
              </div>
              <Inspector inspector={inspector} onFieldSelected={onFieldSelected} history={status.history ?? []} />
            </div>

            <div className="bottom-tools">
              <div className="byte-editor">
                <Pencil size={15} />
                <span>{selectedByte ? formatOffset(selectedByte.offset) : "Байт не выбран"}</span>
                <input
                  aria-label="Значение байта"
                  value={byteDraft}
                  onChange={(event) => setByteDraft(event.target.value.toUpperCase())}
                  maxLength={2}
                  disabled={!selectedByte || status.mode !== "read-write"}
                />
                <button type="button" className="primary-button compact" onClick={applyByteEdit} disabled={!selectedByte || status.mode !== "read-write"}>
                  Записать
                </button>
              </div>
              <div className="search-strip">
                <Search size={15} />
                <select value={encoding} onChange={(event) => setEncoding(event.target.value)} aria-label="Формат поиска">
                  <option value="ascii">ASCII</option>
                  <option value="hex">Hex</option>
                </select>
                <input value={searchValue} onChange={(event) => setSearchValue(event.target.value)} placeholder={encoding === "hex" ? "Введите hex" : "Введите текст"} />
                <input value={replaceValue} onChange={(event) => setReplaceValue(event.target.value)} placeholder="замена" />
                <button type="button" className="icon-button" onClick={searchNext} disabled={!status.isOpen || !searchValue}>
                  Найти
                </button>
                <button type="button" className="icon-button secondary" onClick={() => replace(false)} disabled={status.mode !== "read-write" || !searchValue}>
                  Заменить
                </button>
                <button type="button" className="icon-button secondary" onClick={() => replace(true)} disabled={status.mode !== "read-write" || !searchValue}>
                  Все
                </button>
              </div>
            </div>
          </section>
        ) : null}

        {activePage === "forensics" ? (
          <section className="page page-forensics">
            <ForensicsPanel
              status={status}
              onOpenInode={(inode) => {
                setInodeText(String(inode));
                setActivePage("filesystem");
                showStructure("inode", inode);
              }}
              onGoToBlock={(block) => {
                setBlockText(String(block));
                setActivePage("hex");
                runAction(async () => {
                  await loadHex(block * status.blockSize);
                  setHighlights([]);
                });
              }}
              onGoToOffset={(offset) => {
                setOffsetText(String(offset));
                setActivePage("hex");
                runAction(async () => {
                  await loadHex(offset);
                  setHighlights([{ offset, size: 1, tone: "search" }]);
                });
              }}
              onMessage={(nextMessage) => {
                setError(null);
                setMessage(nextMessage);
              }}
              onError={(nextError) => {
                setMessage(null);
                setError(nextError);
              }}
            />
          </section>
        ) : null}

        {activePage === "imaging" ? (
          <section className="page page-imaging">
            <ImageCaptureWizard
              open
              embedded
              onClose={() => setActivePage("source")}
              onMessage={(nextMessage) => {
                setError(null);
                setMessage(nextMessage);
              }}
              onError={(nextError) => {
                setMessage(null);
                setError(nextError);
              }}
              onOpenImage={openCapturedImage}
            />
          </section>
        ) : null}

        {(error || message) && (
          <div className={`toast ${error ? "error" : ""}`} role="status">
            {error ? <AlertTriangle size={15} /> : <ShieldCheck size={15} />}
            <span>{error ?? message}</span>
          </div>
        )}
      </main>
    </div>
  );
}
