#!/usr/bin/env python3
"""
HTTP bridge for the React/Electron HexCorruptor interface.

The server intentionally reuses the existing Python core:
DiskReader, filesystem parsers, and CommandHistory. The browser UI can run
against this server during development; Electron can later spawn it locally.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import mmap
import os
import platform
import plistlib
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from commands import CommandHistory, ReplaceCommand
from core.disk import DiskReader
from fs.base import DirEntry, ParsedStructure, format_mode, format_size
from fs.detector import detect_filesystem


MAX_READ_LENGTH = 1024 * 1024
SEARCH_CHUNK_SIZE = 1024 * 1024
RAW_SEARCH_CHUNK_SIZE = 32 * 1024 * 1024
RAW_SEARCH_MMAP_WINDOW_SIZE = 256 * 1024 * 1024
RAW_SEARCH_EAGER_MAX_SIZE = 512 * 1024 * 1024
CAPTURE_CHUNK_SIZE = 8 * 1024 * 1024

CAPTURE_JOBS: dict[str, dict[str, Any]] = {}
CAPTURE_LOCK = threading.Lock()
FORENSIC_CANCEL_EVENTS: dict[str, threading.Event] = {}
FORENSIC_CANCEL_LOCK = threading.Lock()


class ForensicCancelled(RuntimeError):
    pass


def _cancel_event(token: str | None) -> threading.Event | None:
    if not token:
        return None
    with FORENSIC_CANCEL_LOCK:
        event = FORENSIC_CANCEL_EVENTS.get(token)
        if event is None:
            event = threading.Event()
            FORENSIC_CANCEL_EVENTS[token] = event
        return event


def _request_forensic_cancel(token: str | None) -> bool:
    if not token:
        return False
    with FORENSIC_CANCEL_LOCK:
        event = FORENSIC_CANCEL_EVENTS.get(token)
        if event is None:
            event = threading.Event()
            FORENSIC_CANCEL_EVENTS[token] = event
        event.set()
    return True


def _clear_cancel_event(token: str | None) -> None:
    if not token:
        return
    with FORENSIC_CANCEL_LOCK:
        FORENSIC_CANCEL_EVENTS.pop(token, None)


def _check_cancel(event: threading.Event | None) -> None:
    if event is not None and event.is_set():
        raise ForensicCancelled("Операция отменена")


def _json_default(value: Any) -> str:
    return str(value)


def _parse_int(value: str | None, default: int = 0) -> int:
    if value is None or value == "":
        return default
    return int(value, 0)


def _parse_optional_epoch(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.isdigit():
        return float(text)
    try:
        local_tz = _dt.datetime.now().astimezone().tzinfo
        if len(text) == 10 and text[4] == "-" and text[7] == "-":
            dt = _dt.datetime.fromisoformat(text).replace(tzinfo=local_tz)
        else:
            dt = _dt.datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=local_tz)
        return dt.timestamp()
    except ValueError:
        return None


def _format_local(epoch: float | int | None) -> str | None:
    if epoch is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(epoch)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except (OSError, OverflowError, ValueError):
        return None


def _iso_to_epoch(value: Any) -> float | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value)
    try:
        return _dt.datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _event(event_type: str, epoch: float | None, source_fs: str | None,
           evidence_type: str, **payload: Any) -> dict[str, Any]:
    return {
        "eventType": event_type,
        "timestampEpoch": epoch,
        "timestampLocal": _format_local(epoch),
        "sourceFs": source_fs,
        "evidenceType": evidence_type,
        "inode": payload.get("inode"),
        "name": payload.get("name"),
        "pathHint": payload.get("pathHint"),
        "offset": payload.get("offset"),
        "confidence": payload.get("confidence", "medium"),
        "warnings": payload.get("warnings", []),
        "details": payload.get("details", {}),
    }


def _name_variants(query: str) -> list[str]:
    text = query.strip()
    if not text or len(text) > 64 or any(char.isspace() for char in text):
        return []
    if "." in text or "/" in text or "\\" in text:
        return []
    if not text.replace("-", "").isalnum():
        return []
    variants = [
        f"{text}.txt",
        f"{text}_folder",
        f"{text}-folder",
        f"{text}_text",
    ]
    return [variant for variant in variants if variant != text]


def _decode_bytes(value: str, encoding: str = "auto") -> bytes:
    if encoding == "hex" or value.lower().startswith("0x"):
        text = value[2:] if value.lower().startswith("0x") else value
        return bytes.fromhex("".join(text.split()))
    return value.encode("utf-8", errors="ignore")


def _file_type_name(entry: DirEntry) -> str:
    try:
        return entry.file_type.name.lower()
    except AttributeError:
        return str(entry.file_type)


def _structure_to_json(structure: ParsedStructure) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    for field in structure.fields:
        absolute_offset = (
            structure.disk_offset + field.offset
            if field.offset >= 0 and structure.disk_offset >= 0
            else None
        )
        fields.append(
            {
                "name": field.name,
                "offset": field.offset,
                "absoluteOffset": absolute_offset,
                "size": field.size,
                "rawHex": field.raw.hex(" ") if field.raw else "",
                "value": field.value,
                "description": field.description,
            }
        )
    return {
        "name": structure.name,
        "diskOffset": structure.disk_offset,
        "size": structure.size,
        "fields": fields,
    }


def _field_by_name(structure: ParsedStructure, name: str) -> Any:
    for field in structure.fields:
        if field.name.strip() == name:
            return field.value
    return None


def _entry_to_json(entry: DirEntry) -> dict[str, Any]:
    return {
        "name": entry.name,
        "inode": entry.inode,
        "fileType": _file_type_name(entry),
        "diskOffset": entry.disk_offset,
        "recordLength": entry.rec_len,
        "isDirectory": _file_type_name(entry) == "directory",
    }


class HexCorruptorSession:
    def __init__(self) -> None:
        self.reader: DiskReader | None = None
        self.parser = None
        self.history = CommandHistory()
        self.path: str | None = None
        self.mode = "closed"
        self.opened_at: float | None = None

    def close(self) -> None:
        if self.reader is not None:
            self.reader.close()
        self.reader = None
        self.parser = None
        self.history.clear()
        self.path = None
        self.mode = "closed"
        self.opened_at = None

    def open_source(self, path: str, writable: bool = False) -> dict[str, Any]:
        self.close()
        read_only = not writable
        try:
            reader = DiskReader(path, read_only=read_only)
            reader.open()
        except PermissionError:
            if read_only:
                raise
            reader = DiskReader(path, read_only=True)
            reader.open()
            read_only = True

        self.reader = reader
        self.parser = detect_filesystem(reader, 0)
        self.history.clear()
        self.path = path
        self.mode = "read" if read_only else "read-write"
        self.opened_at = time.time()
        return self.status()

    def ensure_reader(self) -> DiskReader:
        if self.reader is None:
            raise RuntimeError("Источник не открыт")
        return self.reader

    def ensure_parser(self):
        if self.parser is None:
            raise RuntimeError("Файловая система не распознана")
        return self.parser

    def status(self) -> dict[str, Any]:
        if self.reader is None:
            return {
                "isOpen": False,
                "path": None,
                "name": None,
                "size": 0,
                "sizeHuman": "0 B",
                "mode": self.mode,
                "isBlockDevice": False,
                "filesystem": None,
                "fsInfo": {},
                "rootInode": None,
                "blockSize": 4096,
                "inodeCount": 0,
                "groupCount": 0,
                "canUndo": False,
                "canRedo": False,
                "history": [],
                "capabilities": self.filesystem_capabilities(),
            }

        fs_info: dict[str, str] = {}
        root_inode = None
        block_size = 4096
        inode_count = 0
        group_count = 0

        if self.parser is not None:
            try:
                fs_info = self.parser.get_fs_info()
            except Exception as exc:
                fs_info = {"Ошибка чтения ФС": str(exc)}
            try:
                sb = self.parser._read_superblock_raw()
                block_size = (
                    sb.get("block_size")
                    or sb.get("sb_blocksize")
                    or sb.get("sectorsize")
                    or 4096
                )
                if self.parser.fs_name() == "XFS":
                    root_inode = sb.get("sb_rootino", 2)
                elif self.parser.fs_name() == "Btrfs":
                    root_inode = 256
                else:
                    root_inode = 2
            except Exception:
                root_inode = 2
            try:
                inode_count = int(self.parser.get_inode_count())
            except Exception:
                inode_count = 0
            try:
                group_count = int(self.parser.get_block_group_count())
            except Exception:
                group_count = 0

        return {
            "isOpen": True,
            "path": self.path,
            "name": os.path.basename(self.path or ""),
            "size": self.reader.size,
            "sizeHuman": format_size(self.reader.size),
            "mode": self.mode,
            "isBlockDevice": self.reader.is_block_device,
            "filesystem": self.parser.fs_name() if self.parser else None,
            "fsInfo": fs_info,
            "rootInode": root_inode,
            "blockSize": block_size,
            "inodeCount": inode_count,
            "groupCount": group_count,
            "canUndo": self.history.can_undo(),
            "canRedo": self.history.can_redo(),
            "history": self.history.get_history(),
            "capabilities": self.filesystem_capabilities(),
        }

    def filesystem_capabilities(self) -> dict[str, Any]:
        fs_name = self.parser.fs_name() if self.parser else None
        raw = {
            "metadata": bool(self.parser),
            "timeline": bool(self.parser),
            "rawSearch": self.reader is not None,
            "deletedRecovery": fs_name == "ext4",
            "directoryArtifacts": fs_name == "ext4",
            "imaging": True,
        }
        notes = []
        if fs_name and fs_name != "ext4":
            notes.append("Глубокое восстановление удалённых файлов пока доступно только для ext4")
        if fs_name in {"NTFS", "exFAT", "FAT", "FAT32", "FAT16", "FAT12"}:
            notes.append("Базовый парсер: доступен поиск по байтам, хронология ограничена")
        return {"filesystem": fs_name, **raw, "notes": notes}

    def read(self, offset: int, length: int) -> dict[str, Any]:
        reader = self.ensure_reader()
        length = max(0, min(length, MAX_READ_LENGTH))
        data = reader.read(offset, length)
        return {
            "offset": offset,
            "length": len(data),
            "hex": data.hex(),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
            "endOffset": offset + len(data),
            "isEnd": offset + len(data) >= reader.size,
        }

    def structure(self, kind: str, index: int | None = None) -> dict[str, Any]:
        parser = self.ensure_parser()
        if kind == "superblock":
            return _structure_to_json(parser.parse_superblock())
        if kind == "inode":
            if index is None:
                raise ValueError("Нужен номер инода")
            return _structure_to_json(parser.get_inode(index))
        if kind == "block_group":
            if index is None:
                raise ValueError("Нужен номер группы")
            return _structure_to_json(parser.get_block_group_info(index))
        if kind == "root":
            root = self.status().get("rootInode") or 2
            return _structure_to_json(parser.get_inode(int(root)))
        raise ValueError(f"Неизвестная структура: {kind}")

    def directory(self, inode: int) -> dict[str, Any]:
        parser = self.ensure_parser()
        entries = parser.list_directory(inode)
        return {"inode": inode, "entries": [_entry_to_json(entry) for entry in entries]}

    def search(self, pattern: bytes, start: int = 0) -> dict[str, Any]:
        reader = self.ensure_reader()
        if not pattern:
            raise ValueError("Пустой шаблон")

        overlap = max(0, len(pattern) - 1)
        offset = max(0, start)
        carry = b""

        while offset < reader.size:
            chunk = reader.read(offset, min(SEARCH_CHUNK_SIZE, reader.size - offset))
            if not chunk:
                break
            haystack = carry + chunk
            found = haystack.find(pattern)
            if found >= 0:
                absolute = offset - len(carry) + found
                if absolute >= start:
                    return {"found": True, "offset": absolute, "length": len(pattern)}
            carry = haystack[-overlap:] if overlap else b""
            offset += len(chunk)

        return {"found": False, "offset": None, "length": len(pattern)}

    def owners(self, offset: int, limit: int = 20) -> dict[str, Any]:
        parser = self.ensure_parser()
        if parser.fs_name() != "ext4":
            raise ValueError("Поиск владельца блока сейчас доступен только для ext4")

        sb = parser._read_superblock_raw()
        block_size = int(sb["block_size"])
        local_offset = offset - parser.partition_offset
        if local_offset < 0:
            raise ValueError("Смещение находится до начала раздела")

        physical_block = local_offset // block_size
        byte_offset_in_block = local_offset % block_size
        inode_count = min(int(parser.get_inode_count()), 200_000)
        candidates: list[dict[str, Any]] = []

        for inode in range(1, inode_count + 1):
            if len(candidates) >= limit:
                break
            try:
                structure = parser.get_inode(inode)
                mode = str(_field_by_name(structure, "i_mode") or "")
                if mode.startswith("0o000000"):
                    continue

                blocks = parser._get_data_blocks(inode)
                if physical_block not in blocks:
                    continue

                block_index = blocks.index(physical_block)
                candidates.append(
                    {
                        "inode": inode,
                        "mode": mode,
                        "size": str(_field_by_name(structure, "i_size_lo") or ""),
                        "links": _field_by_name(structure, "i_links_count"),
                        "atime": str(_field_by_name(structure, "i_atime") or "—"),
                        "ctime": str(_field_by_name(structure, "i_ctime") or "—"),
                        "mtime": str(_field_by_name(structure, "i_mtime") or "—"),
                        "dtime": str(_field_by_name(structure, "i_dtime") or "—"),
                        "crtime": str(_field_by_name(structure, "i_crtime") or "—"),
                        "flags": str(_field_by_name(structure, "i_flags") or ""),
                        "blockIndex": block_index,
                        "physicalBlock": physical_block,
                        "blockStart": parser.partition_offset + physical_block * block_size,
                        "byteOffsetInBlock": byte_offset_in_block,
                        "deleted": str(_field_by_name(structure, "i_dtime") or "—") != "—"
                        or _field_by_name(structure, "i_links_count") == 0,
                    }
                )
            except Exception:
                continue

        return {
            "offset": offset,
            "blockSize": block_size,
            "physicalBlock": physical_block,
            "byteOffsetInBlock": byte_offset_in_block,
            "scannedInodes": inode_count,
            "truncated": int(parser.get_inode_count()) > inode_count,
            "candidates": candidates,
        }

    def _ensure_ext4_forensics(self):
        parser = self.ensure_parser()
        if parser.fs_name() != "ext4":
            raise ValueError("Поиск следов доступен только для ext4")
        return parser

    def deleted_files(self, limit: int = 100, cursor: int = 1,
                      min_size: int = 1, name_hint: str | None = None) -> dict[str, Any]:
        parser = self._ensure_ext4_forensics()
        return parser.scan_deleted_files(limit, cursor, min_size, name_hint)

    def deleted_file(self, inode: int) -> dict[str, Any]:
        parser = self._ensure_ext4_forensics()
        return parser.get_deleted_file(inode)

    def deleted_file_preview(self, inode: int, length: int = 4096) -> dict[str, Any]:
        parser = self._ensure_ext4_forensics()
        return parser.read_file_preview(inode, length)

    def recover_deleted_file(self, inode: int) -> dict[str, Any]:
        parser = self._ensure_ext4_forensics()
        return parser.recover_file(inode)

    def deleted_file_report(self, inode: int) -> str:
        record = self.deleted_file(inode)
        warnings = record.get("warnings") or []
        extent_lines = [
            (
                f"| {extent['logical']} | {extent['physical']} | {extent['length']} | "
                f"{extent['blockStart']} | {'yes' if extent.get('uninitialized') else 'no'} |"
            )
            for extent in record.get("extents", [])
        ]
        warning_lines = [f"- {warning}" for warning in warnings] or ["- нет"]
        return "\n".join([
            f"# Отчёт HexCorruptor по удалённому файлу: inode #{inode}",
            "",
            "Восстановление best-effort; имя и исходный путь не доказаны без directory/journal анализа.",
            "",
            "## Данные",
            f"- Источник: `{self.path or 'неизвестно'}`",
            f"- Файловая система: `{self.parser.fs_name() if self.parser else 'неизвестно'}`",
            f"- Имя файла: `{record.get('filename', 'неизвестно')}`",
            f"- Размер: {record['size']} байт ({record['sizeHuman']})",
            f"- Режим: {record['mode']}",
            f"- UID/GID: {record['uid']}/{record['gid']}",
            f"- Ссылки: {record['links']}",
            f"- Удалён: {record['deleted']}",
            f"- Уверенность: {record['confidence']}",
            f"- Восстановление: {record['recoverability']} ({record['recoverableBytes']} байт)",
            "",
            "## Хронология",
            f"- Создан (crtime): {record.get('crtime') or 'неизвестно'}",
            f"- Изменён (mtime): {record.get('mtime') or 'неизвестно'}",
            f"- Метаданные изменены (ctime): {record.get('ctime') or 'неизвестно'}",
            f"- Доступ (atime): {record.get('atime') or 'неизвестно'}",
            f"- Удалён (dtime): {record.get('dtime') or 'неизвестно'}",
            "",
            "## Extents / карта блоков",
            "| logical | physical | length | byte offset | uninitialized |",
            "|---:|---:|---:|---:|:---:|",
            *(extent_lines or ["| - | - | - | - | - |"]),
            "",
            "## Предупреждения",
            *warning_lines,
            "",
        ])

    def _raw_artifact_search(self, query: str, limit: int = 50,
                             cancel_event: threading.Event | None = None) -> dict[str, Any]:
        reader = self.ensure_reader()
        _check_cancel(cancel_event)
        text = query.strip()
        if text.lower().startswith("0x"):
            try:
                pattern = _decode_bytes(text, "hex")
            except ValueError:
                pattern = text.encode("utf-8", errors="ignore")
        else:
            pattern = text.encode("utf-8", errors="ignore")
        if not pattern:
            return {"items": [], "candidateBlocks": [], "scannedBytes": 0, "truncated": False}

        limit = max(1, min(limit, 200))
        overlap = max(0, len(pattern) - 1)
        cursor = 0
        carry = b""
        items: list[dict[str, Any]] = []
        candidate_blocks: set[int] = set()
        hit_limit = False
        block_size = 4096
        if self.parser is not None:
            try:
                block_size = int(self.parser._read_superblock_raw().get("block_size", 4096))
            except Exception:
                block_size = 4096

        def add_match(absolute: int) -> None:
            candidate_blocks.add(absolute // block_size)
            preview_start = max(0, absolute - 48)
            preview = reader.read(preview_start, min(160, reader.size - preview_start))
            items.append({
                "offset": absolute,
                "length": len(pattern),
                "previewOffset": preview_start,
                "previewAscii": "".join(chr(b) if 32 <= b < 127 else "." for b in preview),
                "previewHex": preview.hex(" "),
            })

        file_obj = getattr(reader, "_file", None)
        if file_obj is not None and not getattr(reader, "is_block_device", False):
            try:
                with mmap.mmap(file_obj.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    while cursor < reader.size:
                        _check_cancel(cancel_event)
                        window_end = min(reader.size, cursor + RAW_SEARCH_MMAP_WINDOW_SIZE + overlap)
                        found = mapped.find(pattern, cursor, window_end)
                        while found >= 0 and len(items) < limit:
                            _check_cancel(cancel_event)
                            if found >= cursor:
                                add_match(found)
                            found = mapped.find(pattern, found + 1, window_end)
                        cursor = min(reader.size, cursor + RAW_SEARCH_MMAP_WINDOW_SIZE)
                        if len(items) >= limit:
                            hit_limit = True
                            break
                return {
                    "items": items,
                    "candidateBlocks": sorted(candidate_blocks),
                    "scannedBytes": min(cursor, reader.size),
                    "truncated": hit_limit or cursor < reader.size,
                }
            except (BufferError, OSError, ValueError):
                cursor = 0

        while cursor < reader.size:
            _check_cancel(cancel_event)
            length = min(RAW_SEARCH_CHUNK_SIZE, reader.size - cursor)
            if getattr(reader, "_file", None) is not None:
                reader._file.seek(cursor)
                chunk = reader._file.read(length)
            else:
                chunk = reader.read(cursor, length)
            if not chunk:
                break
            haystack = carry + chunk
            base = cursor - len(carry)
            start = 0
            while len(items) < limit:
                _check_cancel(cancel_event)
                found = haystack.find(pattern, start)
                if found < 0:
                    break
                absolute = base + found
                add_match(absolute)
                start = found + 1
            if len(items) >= limit:
                hit_limit = True
                cursor += len(chunk)
                break
            carry = haystack[-overlap:] if overlap else b""
            cursor += len(chunk)

        return {
            "items": items,
            "candidateBlocks": sorted(candidate_blocks),
            "scannedBytes": min(cursor, reader.size),
            "truncated": hit_limit or cursor < reader.size,
        }

    def forensic_artifacts(self, query: str = "", limit: int = 100,
                           cursor_block: int = 0, include_raw: bool = True,
                           raw_limit: int = 50,
                           cancel_token: str | None = None) -> dict[str, Any]:
        self.ensure_reader()
        cancel_event = _cancel_event(cancel_token)
        _check_cancel(cancel_event)
        parser = self.parser
        fs_name = parser.fs_name() if parser else None
        raw_matches = self._raw_artifact_search(query, limit=raw_limit, cancel_event=cancel_event) if query.strip() and include_raw else {
            "items": [],
            "candidateBlocks": [],
            "scannedBytes": 0,
            "truncated": False,
        }
        if parser and fs_name == "ext4":
            _check_cancel(cancel_event)
            block_numbers = raw_matches.get("candidateBlocks", []) if query.strip() else None
            if block_numbers:
                neighborhood = set()
                for block in block_numbers:
                    for delta in range(-2, 3):
                        if int(block) + delta >= 0:
                            neighborhood.add(int(block) + delta)
                block_numbers = sorted(neighborhood)
            if query.strip() and block_numbers:
                directory_entries = parser.scan_directory_artifacts(
                    limit=limit,
                    cursor_block=cursor_block,
                    name_hint=query,
                    block_numbers=block_numbers,
                    cancel_check=lambda: _check_cancel(cancel_event),
                )
            elif query.strip():
                directory_entries = parser.scan_directory_inode_artifacts(
                    limit=limit,
                    name_hint=query,
                    cancel_check=lambda: _check_cancel(cancel_event),
                )
            else:
                _check_cancel(cancel_event)
                directory_entries = parser.scan_directory_artifacts(
                    limit=limit,
                    cursor_block=cursor_block,
                    name_hint=None,
                    max_blocks=50_000,
                    cancel_check=lambda: _check_cancel(cancel_event),
                )
            if query.strip() and not directory_entries.get("items") and block_numbers:
                directory_entries = parser.scan_directory_artifacts(
                    limit=limit,
                    cursor_block=cursor_block,
                    name_hint=query,
                    block_numbers=block_numbers,
                    cancel_check=lambda: _check_cancel(cancel_event),
                )
            if query.strip() and not any("/" in str(item.get("pathHint") or "") for item in directory_entries.get("items", [])):
                seen_offsets = {
                    int(item.get("diskOffset", -1))
                    for item in directory_entries.get("items", [])
                }
                for variant in _name_variants(query):
                    _check_cancel(cancel_event)
                    variant_raw = self._raw_artifact_search(
                        variant,
                        limit=1,
                        cancel_event=cancel_event,
                    )
                    variant_blocks = variant_raw.get("candidateBlocks", [])
                    if not variant_blocks:
                        continue
                    neighborhood = set()
                    for block in variant_blocks:
                        for delta in range(-2, 3):
                            if int(block) + delta >= 0:
                                neighborhood.add(int(block) + delta)
                    variant_entries = parser.scan_directory_artifacts(
                        limit=limit,
                        cursor_block=cursor_block,
                        name_hint=query,
                        block_numbers=sorted(neighborhood),
                        cancel_check=lambda: _check_cancel(cancel_event),
                    )
                    for item in variant_entries.get("items", []):
                        offset = int(item.get("diskOffset", -1))
                        if offset not in seen_offsets:
                            directory_entries["items"].append(item)
                            seen_offsets.add(offset)
                    if any("/" in str(item.get("pathHint") or "") for item in directory_entries.get("items", [])):
                        break
                directory_entries["items"].sort(key=lambda item: int(item.get("diskOffset", 0)))
            query_leaf = query.strip().rsplit("/", 1)[-1]
            query_stem = query_leaf.split(".", 1)[0]
            has_parent_hint = any(
                "/" in str(item.get("pathHint") or "")
                for item in directory_entries.get("items", [])
            )
            if query_stem and query_stem.lower() != query.strip().lower() and not has_parent_hint:
                _check_cancel(cancel_event)
                expanded = parser.scan_directory_inode_artifacts(
                    limit=limit,
                    name_hint=query_stem,
                    cancel_check=lambda: _check_cancel(cancel_event),
                )
                if not expanded.get("items") and block_numbers:
                    expanded = parser.scan_directory_artifacts(
                        limit=limit,
                        cursor_block=cursor_block,
                        name_hint=query_stem,
                        block_numbers=block_numbers,
                        cancel_check=lambda: _check_cancel(cancel_event),
                    )
                seen_offsets = {
                    int(item.get("diskOffset", -1))
                    for item in directory_entries.get("items", [])
                }
                for item in expanded.get("items", []):
                    offset = int(item.get("diskOffset", -1))
                    if offset not in seen_offsets:
                        directory_entries["items"].append(item)
                        seen_offsets.add(offset)
                    else:
                        for existing in directory_entries["items"]:
                            if int(existing.get("diskOffset", -1)) == offset:
                                existing.update(item)
                                break
                directory_entries["items"].sort(key=lambda item: int(item.get("diskOffset", 0)))
        else:
            directory_entries = {
                "items": [],
                "cursorBlock": cursor_block,
                "nextCursorBlock": None,
                "scannedBlocks": 0,
                "totalBlocks": 0,
                "truncated": False,
                "nameHint": query or "",
            }
        return {
            "query": query,
            "directoryEntries": directory_entries,
            "rawMatches": raw_matches,
        }

    def _record_timeline_events(self, record: dict[str, Any], evidence_type: str,
                                source_fs: str | None = None) -> list[dict[str, Any]]:
        source_fs = source_fs or (self.parser.fs_name() if self.parser else None)
        fields = [
            ("crtime", "created"),
            ("mtime", "modified"),
            ("ctime", "metadata_changed"),
            ("atime", "accessed"),
            ("dtime", "deleted"),
        ]
        events = []
        for field, event_type in fields:
            epoch = _iso_to_epoch(record.get(field))
            if epoch is None:
                continue
            events.append(_event(
                event_type,
                epoch,
                source_fs,
                evidence_type,
                inode=record.get("inode"),
                name=record.get("filename") or record.get("name"),
                pathHint=record.get("pathHint"),
                offset=record.get("diskOffset"),
                confidence=record.get("confidence", "medium"),
                warnings=record.get("warnings", []),
                details={
                    "size": record.get("size"),
                    "sizeHuman": record.get("sizeHuman"),
                    "mode": record.get("mode"),
                    "links": record.get("links"),
                    "field": field,
                },
            ))
        return events

    def _ext4_inode_timeline_records(self, query: str = "", limit: int = 5000,
                                     cancel_event: threading.Event | None = None) -> list[dict[str, Any]]:
        parser = self.ensure_parser()
        if parser.fs_name() != "ext4":
            return []
        inode_count = int(parser.get_inode_count())
        max_inodes = min(inode_count, 500_000)
        query_text = query.strip().lower()
        query_inode = int(query_text) if query_text.isdigit() else None
        if query_text and query_inode is None:
            # ext4 inode records do not store names. Text/path searches get
            # their timeline evidence from directory artifacts and raw matches.
            return []
        records: list[dict[str, Any]] = []
        for inode in range(1, max_inodes + 1):
            if inode % 512 == 0:
                _check_cancel(cancel_event)
            if len(records) >= limit:
                break
            if query_inode is not None and inode != query_inode:
                continue
            try:
                raw, ps = parser._read_inode_raw(inode)
            except Exception:
                continue
            if raw.get("i_mode", 0) == 0 and raw.get("i_dtime", 0) == 0:
                continue
            records.append({
                "inode": inode,
                "filename": "unknown",
                "diskOffset": ps.disk_offset,
                "size": raw.get("i_size", 0),
                "sizeHuman": format_size(raw.get("i_size", 0)),
                "mode": f"0o{raw.get('i_mode', 0):06o} ({format_mode(raw.get('i_mode', 0))})",
                "links": raw.get("i_links_count", 0),
                "crtime": parser._timestamp_value(raw, "i_crtime"),
                "mtime": parser._timestamp_value(raw, "i_mtime"),
                "ctime": parser._timestamp_value(raw, "i_ctime"),
                "atime": parser._timestamp_value(raw, "i_atime"),
                "dtime": parser._timestamp_value(raw, "i_dtime"),
                "confidence": "medium",
                "warnings": [],
            })
        return records

    def _metadata_timeline_records(self, query: str = "", limit: int = 200,
                                   cancel_event: threading.Event | None = None) -> list[dict[str, Any]]:
        parser = self.parser
        if parser is None:
            return []
        if parser.fs_name() == "ext4":
            return self._ext4_inode_timeline_records(query, limit, cancel_event)

        candidates: list[int] = []
        status = self.status()
        if isinstance(status.get("rootInode"), int):
            candidates.append(int(status["rootInode"]))
        if query.strip().isdigit():
            candidates.insert(0, int(query.strip()))

        records = []
        seen: set[int] = set()
        for inode in candidates:
            _check_cancel(cancel_event)
            if inode in seen or len(records) >= limit:
                continue
            seen.add(inode)
            try:
                meta = parser.get_inode_meta(inode)
            except Exception:
                continue
            records.append({
                "inode": inode,
                "filename": "unknown",
                "diskOffset": meta.disk_offset,
                "size": meta.size,
                "sizeHuman": format_size(meta.size),
                "mode": f"0o{meta.mode:06o} ({format_mode(meta.mode)})",
                "links": meta.links,
                "crtime": None,
                "mtime": meta.mtime.isoformat() if meta.mtime else None,
                "ctime": meta.ctime.isoformat() if meta.ctime else None,
                "atime": meta.atime.isoformat() if meta.atime else None,
                "dtime": None,
                "confidence": "low",
                "warnings": ["Metadata timeline is limited for this filesystem"],
            })
        return records

    def forensic_timeline(self, query: str = "", from_value: str | None = None,
                          to_value: str | None = None,
                          event_types: str = "", limit: int = 1000,
                          artifacts: dict[str, Any] | None = None,
                          cancel_token: str | None = None) -> dict[str, Any]:
        self.ensure_reader()
        cancel_event = _cancel_event(cancel_token)
        _check_cancel(cancel_event)
        parser = self.parser
        source_fs = parser.fs_name() if parser else None
        start_epoch = _parse_optional_epoch(from_value)
        end_epoch = _parse_optional_epoch(to_value)
        if to_value and len(to_value.strip()) == 10 and end_epoch is not None:
            end_epoch += 86399
        type_filter = {item.strip() for item in event_types.split(",") if item.strip()}

        events: list[dict[str, Any]] = []
        for record in self._metadata_timeline_records(query, limit=limit, cancel_event=cancel_event):
            events.extend(self._record_timeline_events(record, "inode_metadata", source_fs))

        _check_cancel(cancel_event)
        artifacts = artifacts if artifacts is not None else (self.forensic_artifacts(query, limit=200, cancel_token=cancel_token) if query.strip() else {
            "directoryEntries": {"items": []},
            "rawMatches": {"items": []},
        })
        for item in artifacts.get("directoryEntries", {}).get("items", []):
            state = item.get("inodeState", {})
            epoch = _iso_to_epoch(state.get("dtime"))
            events.append(_event(
                "name_trace",
                epoch,
                source_fs,
                "directory_entry",
                inode=item.get("inode"),
                name=item.get("name"),
                pathHint=item.get("pathHint"),
                offset=item.get("diskOffset"),
                confidence=item.get("confidence", "medium"),
                warnings=state.get("warnings", []),
                details={
                    "fileType": item.get("fileType"),
                    "inodeState": state.get("state"),
                    "containerInode": item.get("containerInode"),
                    "parentInode": item.get("parentInode"),
                },
            ))
        for item in artifacts.get("rawMatches", {}).get("items", []):
            events.append(_event(
                "content_match",
                None,
                source_fs,
                "raw_match",
                name=query or None,
                offset=item.get("offset"),
                confidence="low",
                details={
                    "length": item.get("length"),
                    "previewAscii": item.get("previewAscii"),
                    "previewOffset": item.get("previewOffset"),
                },
            ))

        def keep(event: dict[str, Any]) -> bool:
            epoch = event.get("timestampEpoch")
            if type_filter and event.get("eventType") not in type_filter:
                return False
            if epoch is not None and start_epoch is not None and epoch < start_epoch:
                return False
            if epoch is not None and end_epoch is not None and epoch > end_epoch:
                return False
            return True

        filtered = [event for event in events if keep(event)]
        filtered.sort(key=lambda item: (
            item["timestampEpoch"] is None,
            item["timestampEpoch"] if item["timestampEpoch"] is not None else float("inf"),
        ))
        return {
            "query": query,
            "from": from_value,
            "to": to_value,
            "events": filtered[:max(1, min(limit, 5000))],
            "total": len(filtered),
            "undated": sum(1 for event in filtered if event.get("timestampEpoch") is None),
            "capabilities": self.filesystem_capabilities(),
        }

    def forensic_search(self, query: str = "", from_value: str | None = None,
                        to_value: str | None = None, types: str = "",
                        limit: int = 100,
                        cancel_token: str | None = None) -> dict[str, Any]:
        cancel_event = _cancel_event(cancel_token)
        _check_cancel(cancel_event)
        query_text = query.strip()
        query_inode = query_text.isdigit()
        reader = self.ensure_reader()
        artifacts = self.forensic_artifacts(
            query,
            limit=limit,
            include_raw=False,
            cancel_token=cancel_token,
        )
        has_names = bool(artifacts.get("directoryEntries", {}).get("items"))
        eager_raw = reader.size <= RAW_SEARCH_EAGER_MAX_SIZE
        if query_text and (not has_names or eager_raw):
            artifacts = self.forensic_artifacts(
                query,
                limit=limit,
                include_raw=True,
                raw_limit=50 if eager_raw else 1,
                cancel_token=cancel_token,
            )
        _check_cancel(cancel_event)
        timeline = self.forensic_timeline(
            query,
            from_value,
            to_value,
            types,
            limit=limit,
            artifacts=artifacts,
            cancel_token=cancel_token,
        )
        recoverable = []
        if self.parser and self.parser.fs_name() == "ext4" and (not query_text or query_inode):
            _check_cancel(cancel_event)
            scan = self.deleted_files(limit=min(limit, 200), cursor=1, min_size=1, name_hint=query or None)
            recoverable = scan.get("items", [])
        return {
            "query": query,
            "names": artifacts.get("directoryEntries", {}).get("items", []),
            "content": artifacts.get("rawMatches", {}).get("items", []),
            "timelineEvents": timeline.get("events", []),
            "recoverableInodes": recoverable,
            "capabilities": self.filesystem_capabilities(),
        }

    def file_dossier(self, inode: int | None = None, name: str = "",
                     offset: int | None = None,
                     cancel_token: str | None = None) -> dict[str, Any]:
        self.ensure_reader()
        cancel_event = _cancel_event(cancel_token)
        _check_cancel(cancel_event)
        parser = self.parser
        source_fs = parser.fs_name() if parser else None
        include_raw_for_name = bool(name and inode is None and offset is None)
        artifacts = self.forensic_artifacts(
            name,
            limit=200,
            include_raw=include_raw_for_name,
            cancel_token=cancel_token,
        ) if name else {
            "directoryEntries": {"items": []},
            "rawMatches": {"items": []},
        }
        names = artifacts.get("directoryEntries", {}).get("items", [])
        if name:
            query_leaf = name.strip().rsplit("/", 1)[-1].lower()
            names.sort(key=lambda item: (
                0 if str(item.get("name", "")).lower() == query_leaf else 1,
                int(item.get("diskOffset", 0)),
            ))
        raw_matches = artifacts.get("rawMatches", {}).get("items", [])
        selected_inode = inode
        if selected_inode is None and names:
            selected_inode = int(names[0].get("inode", 0))

        inode_record = None
        recoverable = None
        if selected_inode and parser:
            _check_cancel(cancel_event)
            if parser.fs_name() == "ext4":
                try:
                    recoverable = parser.get_deleted_file(selected_inode)
                except Exception:
                    try:
                        raw, ps = parser._read_inode_raw(selected_inode)
                        extents, warnings = parser._file_extents(raw)
                        inode_record = {
                            "inode": selected_inode,
                            "diskOffset": ps.disk_offset,
                            "state": "wiped" if raw.get("i_mode", 0) == 0 else (
                                "deleted" if raw.get("i_dtime") or raw.get("i_links_count") == 0 else "active"
                            ),
                            "size": raw.get("i_size", 0),
                            "sizeHuman": format_size(raw.get("i_size", 0)),
                            "mode": f"0o{raw.get('i_mode', 0):06o} ({format_mode(raw.get('i_mode', 0))})",
                            "links": raw.get("i_links_count", 0),
                            "uid": raw.get("i_uid", 0),
                            "gid": raw.get("i_gid", 0),
                            "crtime": parser._timestamp_value(raw, "i_crtime"),
                            "mtime": parser._timestamp_value(raw, "i_mtime"),
                            "ctime": parser._timestamp_value(raw, "i_ctime"),
                            "atime": parser._timestamp_value(raw, "i_atime"),
                            "dtime": parser._timestamp_value(raw, "i_dtime"),
                            "extents": extents,
                            "warnings": warnings,
                        }
                    except Exception as exc:
                        inode_record = {"inode": selected_inode, "state": "unreadable", "warnings": [str(exc)]}
            else:
                try:
                    meta = parser.get_inode_meta(selected_inode)
                    inode_record = {
                        "inode": selected_inode,
                        "diskOffset": meta.disk_offset,
                        "state": "active" if meta.mode else "unreadable",
                        "size": meta.size,
                        "sizeHuman": format_size(meta.size),
                        "mode": f"0o{meta.mode:06o} ({format_mode(meta.mode)})",
                        "links": meta.links,
                        "crtime": None,
                        "mtime": meta.mtime.isoformat() if meta.mtime else None,
                        "ctime": meta.ctime.isoformat() if meta.ctime else None,
                        "atime": meta.atime.isoformat() if meta.atime else None,
                        "dtime": None,
                        "extents": [],
                        "warnings": ["Deep file metadata is limited for this filesystem"],
                    }
                except Exception as exc:
                    inode_record = {"inode": selected_inode, "state": "unreadable", "warnings": [str(exc)]}

        if name and not names and (selected_inode is not None or offset is not None):
            leaf = name.strip().rsplit("/", 1)[-1] or name
            state = "unknown"
            if recoverable:
                state = "deleted" if recoverable.get("deleted") else "active"
            elif isinstance(inode_record, dict):
                state = str(inode_record.get("state") or "unknown")
            names = [{
                "name": leaf,
                "pathHint": name,
                "inode": selected_inode or 0,
                "fileType": "unknown",
                "recordLength": 0,
                "nameLength": len(leaf.encode("utf-8", errors="ignore")),
                "diskOffset": offset or 0,
                "block": None,
                "blockOffset": None,
                "containerInode": None,
                "parentInode": None,
                "evidence": "selected_result",
                "confidence": "medium",
                "inodeState": {
                    "state": state,
                    "mode": inode_record.get("mode") if isinstance(inode_record, dict) else recoverable.get("mode") if recoverable else None,
                    "size": inode_record.get("size", 0) if isinstance(inode_record, dict) else recoverable.get("size", 0) if recoverable else 0,
                    "sizeHuman": inode_record.get("sizeHuman", "unknown") if isinstance(inode_record, dict) else recoverable.get("sizeHuman", "unknown") if recoverable else "unknown",
                    "links": inode_record.get("links", 0) if isinstance(inode_record, dict) else recoverable.get("links", 0) if recoverable else 0,
                    "dtime": inode_record.get("dtime") if isinstance(inode_record, dict) else recoverable.get("dtime") if recoverable else None,
                    "crtime": inode_record.get("crtime") if isinstance(inode_record, dict) else recoverable.get("crtime") if recoverable else None,
                    "mtime": inode_record.get("mtime") if isinstance(inode_record, dict) else recoverable.get("mtime") if recoverable else None,
                    "recoverable": bool(recoverable),
                    "extentCount": len(recoverable.get("extents", [])) if recoverable else 0,
                    "warnings": ["Path hint comes from selected search result"],
                },
            }]

        offset_preview = None
        if offset is not None:
            _check_cancel(cancel_event)
            data = self.ensure_reader().read(max(0, offset - 48), 160)
            offset_preview = {
                "offset": offset,
                "previewOffset": max(0, offset - 48),
                "previewAscii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
                "previewHex": data.hex(" "),
            }

        timeline_query = str(selected_inode) if selected_inode else ""
        timeline = self.forensic_timeline(
            timeline_query,
            limit=500,
            artifacts=artifacts,
            cancel_token=cancel_token,
        )
        return {
            "sourceFs": source_fs,
            "query": name,
            "inode": selected_inode,
            "names": names,
            "rawMatches": raw_matches,
            "inodeRecord": inode_record,
            "recoverableFile": recoverable,
            "offsetPreview": offset_preview,
            "timeline": timeline.get("events", []),
            "capabilities": self.filesystem_capabilities(),
        }

    def forensic_report(self, output_format: str = "markdown", query: str = "",
                        from_value: str | None = None, to_value: str | None = None) -> tuple[bytes, str, str]:
        search = self.forensic_search(query, from_value, to_value, limit=200)
        timeline = self.forensic_timeline(query, from_value, to_value, limit=500)
        payload = {
            "source": self.path,
            "createdAt": _format_local(time.time()),
            "query": query,
            "search": search,
            "timeline": timeline,
        }
        if output_format == "json":
            return (
                json.dumps(payload, ensure_ascii=False, default=_json_default, indent=2).encode("utf-8"),
                "application/json; charset=utf-8",
                "hexcorruptor-forensics.json",
            )

        lines = [
            "# Отчёт HexCorruptor",
            "",
            f"- Источник: `{self.path or 'неизвестно'}`",
            f"- Файловая система: `{self.parser.fs_name() if self.parser else 'неизвестно'}`",
            f"- Запрос: `{query or '—'}`",
            f"- Создан: {payload['createdAt']}",
            "",
            "## Сводка",
            f"- Имена: {len(search['names'])}",
            f"- Совпадения в содержимом: {len(search['content'])}",
            f"- События: {len(timeline['events'])}",
            f"- Восстановимые inode: {len(search['recoverableInodes'])}",
            "",
            "## Имена",
        ]
        for item in search["names"][:100]:
            lines.append(
                f"- `{item.get('pathHint') or item.get('name')}` inode #{item.get('inode')} "
                f"состояние={item.get('inodeState', {}).get('state')} смещение=0x{int(item.get('diskOffset', 0)):X}"
            )
        lines.extend(["", "## Хронология"])
        for event in timeline["events"][:200]:
            ts = event.get("timestampLocal") or "без даты"
            target = event.get("pathHint") or event.get("name") or f"inode #{event.get('inode')}"
            lines.append(f"- {ts} `{event.get('eventType')}` {target} источник={event.get('evidenceType')}")
        lines.append("")
        return "\n".join(lines).encode("utf-8"), "text/markdown; charset=utf-8", "hexcorruptor-forensics.md"

    def list_devices(self) -> dict[str, Any]:
        if platform.system() == "Darwin":
            return {"platform": "Darwin", "devices": self._list_macos_devices()}
        if platform.system() == "Linux":
            return {"platform": "Linux", "devices": self._list_linux_devices()}
        return {"platform": platform.system(), "devices": []}

    def _list_macos_devices(self) -> list[dict[str, Any]]:
        try:
            raw = subprocess.check_output(["diskutil", "list", "-plist"], timeout=10)
            plist = plistlib.loads(raw)
        except Exception:
            return []
        devices = []
        for disk in plist.get("AllDisksAndPartitions", []):
            identifier = disk.get("DeviceIdentifier")
            if not identifier:
                continue
            info = {}
            try:
                info_raw = subprocess.check_output(["diskutil", "info", "-plist", identifier], timeout=10)
                info = plistlib.loads(info_raw)
            except Exception:
                pass
            size = int(disk.get("Size") or info.get("TotalSize") or 0)
            mountpoints = [
                part.get("MountPoint")
                for part in disk.get("Partitions", [])
                if part.get("MountPoint")
            ]
            filesystem = ", ".join(
                sorted({
                    str(part.get("Content") or part.get("FilesystemName") or "")
                    for part in disk.get("Partitions", [])
                    if part.get("Content") or part.get("FilesystemName")
                })
            )
            devices.append({
                "id": identifier,
                "path": f"/dev/r{identifier}",
                "displayName": info.get("MediaName") or disk.get("Content") or identifier,
                "size": size,
                "sizeHuman": format_size(size),
                "model": info.get("DeviceNode") or identifier,
                "filesystem": filesystem or str(disk.get("Content") or "unknown"),
                "mountpoints": mountpoints,
                "removable": bool(info.get("Removable") or info.get("Ejectable")),
                "readOnly": bool(info.get("ReadOnly")),
                "wholeDisk": True,
            })
        return devices

    def _list_linux_devices(self) -> list[dict[str, Any]]:
        if not shutil.which("lsblk"):
            return []
        try:
            raw = subprocess.check_output([
                "lsblk", "-J", "-b",
                "-o", "NAME,PATH,SIZE,MODEL,TRAN,RM,MOUNTPOINTS,FSTYPE,TYPE,RO",
            ], timeout=10)
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            return []
        devices = []
        for block in payload.get("blockdevices", []):
            if block.get("type") != "disk":
                continue
            mountpoints: list[str] = []
            fstypes: set[str] = set()
            for child in block.get("children") or []:
                for mount in child.get("mountpoints") or []:
                    if mount:
                        mountpoints.append(mount)
                if child.get("fstype"):
                    fstypes.add(str(child["fstype"]))
            size = int(block.get("size") or 0)
            devices.append({
                "id": block.get("name"),
                "path": block.get("path"),
                "displayName": block.get("model") or block.get("name"),
                "size": size,
                "sizeHuman": format_size(size),
                "model": block.get("model") or "",
                "filesystem": ", ".join(sorted(fstypes)) or "unknown",
                "mountpoints": mountpoints,
                "removable": bool(int(block.get("rm") or 0)),
                "readOnly": bool(int(block.get("ro") or 0)),
                "wholeDisk": True,
            })
        return devices

    def start_capture(self, source: str, destination: str, unmount: bool = False) -> dict[str, Any]:
        source_path = os.path.realpath(source)
        destination_path = os.path.realpath(destination)
        if not source_path:
            raise ValueError("Нужен путь к исходному устройству")
        if not destination_path:
            raise ValueError("Нужен путь для нового образа")
        if source_path == destination_path:
            raise ValueError("Новый образ не может совпадать с исходным устройством")
        if os.path.exists(destination_path):
            raise ValueError("Файл нового образа уже существует")
        if source_path.startswith("/dev/") and destination_path.startswith("/dev/"):
            raise ValueError("Новый образ должен быть файлом, а не устройством")

        size = 0
        try:
            size = os.stat(source_path).st_size
        except OSError:
            size = 0
        job_id = uuid.uuid4().hex
        job = {
            "jobId": job_id,
            "status": "queued",
            "source": source_path,
            "destination": destination_path,
            "unmount": bool(unmount),
            "bytesCopied": 0,
            "totalBytes": size,
            "progress": 0,
            "speedBytesPerSec": 0,
            "etaSeconds": None,
            "sha256": None,
            "error": None,
            "startedAt": time.time(),
            "completedAt": None,
            "cancelRequested": False,
        }
        with CAPTURE_LOCK:
            CAPTURE_JOBS[job_id] = job
        thread = threading.Thread(target=self._run_capture_job, args=(job_id,), daemon=True)
        thread.start()
        return job

    def _run_capture_job(self, job_id: str) -> None:
        with CAPTURE_LOCK:
            job = CAPTURE_JOBS[job_id]
            job["status"] = "running"
        source = job["source"]
        destination = job["destination"]
        started = time.time()
        digest = hashlib.sha256()
        try:
            if job.get("unmount") and source.startswith("/dev/"):
                self._unmount_device(source)
            copied = 0
            with open(source, "rb", buffering=0) as src, open(destination, "xb", buffering=0) as dst:
                while True:
                    with CAPTURE_LOCK:
                        if CAPTURE_JOBS[job_id].get("cancelRequested"):
                            CAPTURE_JOBS[job_id]["status"] = "cancelled"
                            break
                    chunk = src.read(CAPTURE_CHUNK_SIZE)
                    if not chunk:
                        with CAPTURE_LOCK:
                            CAPTURE_JOBS[job_id]["status"] = "complete"
                        break
                    dst.write(chunk)
                    digest.update(chunk)
                    copied += len(chunk)
                    elapsed = max(0.001, time.time() - started)
                    speed = copied / elapsed
                    with CAPTURE_LOCK:
                        job = CAPTURE_JOBS[job_id]
                        job["bytesCopied"] = copied
                        if job["totalBytes"]:
                            job["progress"] = min(1, copied / job["totalBytes"])
                            remaining = max(0, job["totalBytes"] - copied)
                            job["etaSeconds"] = remaining / speed if speed else None
                        job["speedBytesPerSec"] = speed
            with CAPTURE_LOCK:
                job = CAPTURE_JOBS[job_id]
                if job["status"] == "complete":
                    job["sha256"] = digest.hexdigest()
                    job["completedAt"] = time.time()
                    self._write_capture_logs(job)
                elif job["status"] == "cancelled" and os.path.exists(destination):
                    os.remove(destination)
        except PermissionError as exc:
            if platform.system() == "Darwin":
                message = (
                    f"Недостаточно прав для чтения {source}. "
                    "macOS обычно требует запуск HexCorruptor с правами администратора "
                    "или отдельный privileged helper. Source не изменён."
                )
            elif platform.system() == "Linux":
                message = (
                    f"Недостаточно прав для чтения {source}. "
                    "Запустите capture через sudo/pkexec flow или выдайте пользователю доступ к block device. "
                    "Source не изменён."
                )
            else:
                message = f"Недостаточно прав для чтения {source}: {exc}"
            with CAPTURE_LOCK:
                job = CAPTURE_JOBS[job_id]
                job["status"] = "error"
                job["error"] = message
                job["completedAt"] = time.time()
        except Exception as exc:
            with CAPTURE_LOCK:
                job = CAPTURE_JOBS[job_id]
                job["status"] = "error"
                job["error"] = str(exc)
                job["completedAt"] = time.time()

    def _unmount_device(self, source: str) -> None:
        if platform.system() == "Darwin" and shutil.which("diskutil"):
            subprocess.run(["diskutil", "unmountDisk", source], check=False, timeout=60)
        elif platform.system() == "Linux":
            if shutil.which("udisksctl"):
                subprocess.run(["udisksctl", "unmount", "-b", source], check=False, timeout=60)
            elif shutil.which("umount"):
                subprocess.run(["umount", source], check=False, timeout=60)

    def _write_capture_logs(self, job: dict[str, Any]) -> None:
        log = {
            "jobId": job["jobId"],
            "source": job["source"],
            "destination": job["destination"],
            "bytesCopied": job["bytesCopied"],
            "sha256": job["sha256"],
            "startedAt": _format_local(job["startedAt"]),
            "completedAt": _format_local(job["completedAt"]),
            "readOnly": True,
        }
        json_path = f"{job['destination']}.capture.json"
        md_path = f"{job['destination']}.capture.md"
        Path(json_path).write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
        Path(md_path).write_text(
            "\n".join([
                "# Снятие образа HexCorruptor",
                "",
                f"- Исходное устройство: `{log['source']}`",
                f"- Новый образ: `{log['destination']}`",
                f"- Байт скопировано: {log['bytesCopied']}",
                f"- SHA256: `{log['sha256']}`",
                f"- Начато: {log['startedAt']}",
                f"- Завершено: {log['completedAt']}",
                "- Режим: только чтение",
                "",
            ]),
            encoding="utf-8",
        )

    def get_capture_job(self, job_id: str) -> dict[str, Any]:
        with CAPTURE_LOCK:
            if job_id not in CAPTURE_JOBS:
                raise ValueError("Capture job не найден")
            return dict(CAPTURE_JOBS[job_id])

    def cancel_capture_job(self, job_id: str) -> dict[str, Any]:
        with CAPTURE_LOCK:
            if job_id not in CAPTURE_JOBS:
                raise ValueError("Capture job не найден")
            CAPTURE_JOBS[job_id]["cancelRequested"] = True
            return dict(CAPTURE_JOBS[job_id])

    def write(self, offset: int, data: bytes) -> dict[str, Any]:
        reader = self.ensure_reader()
        old = reader.read(offset, len(data))
        if len(old) != len(data):
            raise ValueError("Невозможно записать за пределами источника")
        self.history.execute(ReplaceCommand(reader, offset, old, data))
        return {
            "offset": offset,
            "oldHex": old.hex(),
            "newHex": data.hex(),
            "history": self.history.get_history(),
            "status": self.status(),
        }

    def replace(self, old: bytes, new: bytes, start: int, all_matches: bool) -> dict[str, Any]:
        if not old:
            raise ValueError("Пустой шаблон")
        if len(old) != len(new):
            raise ValueError("Замена пока работает как overwrite: длины должны совпадать")

        reader = self.ensure_reader()
        replaced: list[int] = []
        cursor = max(0, start)

        while cursor < reader.size:
            result = self.search(old, cursor)
            if not result["found"]:
                break
            offset = int(result["offset"])
            self.history.execute(ReplaceCommand(reader, offset, old, new))
            replaced.append(offset)
            cursor = offset + max(1, len(new))
            if not all_matches:
                break

        return {
            "count": len(replaced),
            "offsets": replaced,
            "history": self.history.get_history(),
            "status": self.status(),
        }

    def undo(self) -> dict[str, Any]:
        command = self.history.undo()
        return {
            "changed": command is not None,
            "description": command.description if command else None,
            "history": self.history.get_history(),
            "status": self.status(),
        }

    def redo(self) -> dict[str, Any]:
        command = self.history.redo()
        return {
            "changed": command is not None,
            "description": command.description if command else None,
            "history": self.history.get_history(),
            "status": self.status(),
        }


SESSION = HexCorruptorSession()


def _create_demo_image() -> str:
    """Create a small synthetic ext-style image for UI smoke checks."""
    path = Path(tempfile.gettempdir()) / f"hexcorruptor-demo-{uuid.uuid4().hex}.img"
    data = bytearray(256 * 1024)
    sb = bytearray(1024)
    sb[0:4] = (1280).to_bytes(4, "little")
    sb[4:8] = (65536).to_bytes(4, "little")
    sb[12:16] = (60000).to_bytes(4, "little")
    sb[16:20] = (1200).to_bytes(4, "little")
    sb[20:24] = (1).to_bytes(4, "little")
    sb[24:28] = (0).to_bytes(4, "little")
    sb[28:32] = (0).to_bytes(4, "little")
    sb[32:36] = (32768).to_bytes(4, "little")
    sb[36:40] = (32768).to_bytes(4, "little")
    sb[40:44] = (1600).to_bytes(4, "little")
    sb[44:48] = (1609459200).to_bytes(4, "little")
    sb[48:52] = (1609459200).to_bytes(4, "little")
    sb[52:54] = (1).to_bytes(2, "little")
    sb[54:56] = (20).to_bytes(2, "little")
    sb[56:58] = (0xEF53).to_bytes(2, "little")
    sb[58:60] = (1).to_bytes(2, "little")
    sb[60:62] = (1).to_bytes(2, "little")
    sb[76:80] = (1).to_bytes(4, "little")
    sb[84:88] = (11).to_bytes(4, "little")
    sb[88:90] = (256).to_bytes(2, "little")
    sb[92:96] = (0).to_bytes(4, "little")
    sb[96:100] = (6).to_bytes(4, "little")
    sb[100:104] = (1).to_bytes(4, "little")
    sb[104:120] = uuid.UUID("12345678-1234-1234-1234-123456789abc").bytes
    sb[120:136] = b"demo_ext4".ljust(16, b"\0")
    sb[136:200] = b"/demo".ljust(64, b"\0")
    sb[254:256] = (32).to_bytes(2, "little")
    sb[264:268] = (1609459200).to_bytes(4, "little")
    data[1024:2048] = sb

    block_size = 1024
    inode_size = 256
    inode_table_block = 5
    group_desc = bytearray(32)
    group_desc[8:12] = inode_table_block.to_bytes(4, "little")
    data[2048:2080] = group_desc

    def put_inode(inode: int, mode: int, content: bytes, *, links: int, dtime: int = 0) -> None:
        inode_data = bytearray(inode_size)
        data_block = 80 + inode
        now = 1772323200 + inode
        inode_data[0:2] = mode.to_bytes(2, "little")
        inode_data[4:8] = len(content).to_bytes(4, "little")
        inode_data[8:12] = now.to_bytes(4, "little")
        inode_data[12:16] = now.to_bytes(4, "little")
        inode_data[16:20] = now.to_bytes(4, "little")
        inode_data[20:24] = dtime.to_bytes(4, "little")
        inode_data[26:28] = links.to_bytes(2, "little")
        inode_data[28:32] = ((block_size // 512)).to_bytes(4, "little")
        inode_data[32:36] = (0x00080000).to_bytes(4, "little")
        i_block = bytearray(60)
        i_block[0:2] = (0xF30A).to_bytes(2, "little")
        i_block[2:4] = (1).to_bytes(2, "little")
        i_block[4:6] = (4).to_bytes(2, "little")
        i_block[6:8] = (0).to_bytes(2, "little")
        i_block[12:16] = (0).to_bytes(4, "little")
        i_block[16:18] = (1).to_bytes(2, "little")
        i_block[18:20] = (0).to_bytes(2, "little")
        i_block[20:24] = data_block.to_bytes(4, "little")
        inode_data[40:100] = i_block
        inode_data[144:148] = (now - 3600).to_bytes(4, "little")
        offset = inode_table_block * block_size + (inode - 1) * inode_size
        data[offset:offset + inode_size] = inode_data
        block_offset = data_block * block_size
        data[block_offset:block_offset + len(content)] = content

    def put_dir_block(block_number: int, self_inode: int, parent_inode: int,
                      entries: list[tuple[int, str, int]]) -> None:
        block = bytearray(block_size)
        pos = 0
        all_entries = [(self_inode, ".", 2), (parent_inode, "..", 2), *entries]
        for index, (inode, name, file_type) in enumerate(all_entries):
            name_bytes = name.encode("utf-8")
            rec_len = 8 + ((len(name_bytes) + 3) & ~3)
            if index == len(all_entries) - 1:
                rec_len = block_size - pos
            block[pos:pos + 4] = inode.to_bytes(4, "little")
            block[pos + 4:pos + 6] = rec_len.to_bytes(2, "little")
            block[pos + 6] = len(name_bytes)
            block[pos + 7] = file_type
            block[pos + 8:pos + 8 + len(name_bytes)] = name_bytes
            pos += rec_len
        start = block_number * block_size
        data[start:start + block_size] = block

    put_inode(12, 0o100644, b"ACTIVE_DEMO_FILE", links=1)
    put_inode(
        13,
        0o100600,
        b"HC_SECRET_DELETED_DEMO_2026_ALPHA\n" + b"X" * 96,
        links=0,
        dtime=1772326800,
    )
    put_inode(14, 0o040755, b"", links=2)
    put_dir_block(96, 2, 2, [(18, "secret_folder", 2)])
    put_dir_block(97, 18, 2, [(19, "secret.txt", 1)])
    data[98 * block_size:98 * block_size + len(b"secret_text\n")] = b"secret_text\n"
    path.write_bytes(data)
    return str(path)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "HexCorruptorWeb/0.1"

    def do_OPTIONS(self) -> None:
        self._send_json({"ok": True})

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[api] {self.address_string()} {fmt % args}")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        cancel_token = query.get("cancel_token", [None])[0]
        try:
            if method == "GET" and parsed.path == "/api/status":
                self._send_json(SESSION.status())
            elif method == "GET" and parsed.path == "/api/read":
                self._send_json(
                    SESSION.read(
                        _parse_int(query.get("offset", ["0"])[0]),
                        _parse_int(query.get("length", ["4096"])[0], 4096),
                    )
                )
            elif method == "GET" and parsed.path == "/api/structure":
                kind = query.get("kind", [""])[0]
                index_value = query.get("index", [None])[0]
                index = _parse_int(index_value) if index_value is not None else None
                self._send_json(SESSION.structure(kind, index))
            elif method == "GET" and parsed.path == "/api/directory":
                self._send_json(SESSION.directory(_parse_int(query.get("inode", ["2"])[0], 2)))
            elif method == "GET" and parsed.path == "/api/search":
                pattern = _decode_bytes(
                    query.get("pattern", [""])[0],
                    query.get("encoding", ["auto"])[0],
                )
                start = _parse_int(query.get("start", ["0"])[0])
                self._send_json(SESSION.search(pattern, start))
            elif method == "GET" and parsed.path == "/api/owners":
                self._send_json(
                    SESSION.owners(
                        _parse_int(query.get("offset", ["0"])[0]),
                        _parse_int(query.get("limit", ["20"])[0], 20),
                    )
                )
            elif method == "GET" and parsed.path == "/api/forensics/deleted-files":
                self._send_json(
                    SESSION.deleted_files(
                        _parse_int(query.get("limit", ["100"])[0], 100),
                        _parse_int(query.get("cursor", ["1"])[0], 1),
                        _parse_int(query.get("min_size", ["1"])[0], 1),
                        query.get("name_hint", [None])[0],
                    )
                )
            elif method == "GET" and parsed.path == "/api/forensics/artifacts":
                self._send_json(
                    SESSION.forensic_artifacts(
                        query=query.get("query", [""])[0],
                        limit=_parse_int(query.get("limit", ["100"])[0], 100),
                        cursor_block=_parse_int(query.get("cursor_block", ["0"])[0], 0),
                        include_raw=True,
                        cancel_token=cancel_token,
                    )
                )
            elif method == "GET" and parsed.path == "/api/forensics/search":
                self._send_json(
                    SESSION.forensic_search(
                        query.get("query", [""])[0],
                        query.get("from", [None])[0],
                        query.get("to", [None])[0],
                        query.get("types", [""])[0],
                        _parse_int(query.get("limit", ["100"])[0], 100),
                        cancel_token,
                    )
                )
            elif method == "GET" and parsed.path == "/api/forensics/timeline":
                self._send_json(
                    SESSION.forensic_timeline(
                        query.get("query", [""])[0],
                        query.get("from", [None])[0],
                        query.get("to", [None])[0],
                        query.get("event_types", query.get("types", [""]))[0],
                        _parse_int(query.get("limit", ["1000"])[0], 1000),
                        cancel_token=cancel_token,
                    )
                )
            elif method == "GET" and parsed.path == "/api/forensics/file-dossier":
                inode_value = query.get("inode", [None])[0]
                offset_value = query.get("offset", [None])[0]
                self._send_json(
                    SESSION.file_dossier(
                        _parse_int(inode_value) if inode_value not in (None, "") else None,
                        query.get("name", [""])[0],
                        _parse_int(offset_value) if offset_value not in (None, "") else None,
                        cancel_token,
                    )
                )
            elif method == "GET" and parsed.path == "/api/forensics/report":
                body, content_type, filename = SESSION.forensic_report(
                    query.get("format", ["markdown"])[0],
                    query.get("query", [""])[0],
                    query.get("from", [None])[0],
                    query.get("to", [None])[0],
                )
                self._send_bytes(body, content_type, filename)
            elif method == "GET" and parsed.path == "/api/devices":
                self._send_json(SESSION.list_devices())
            elif method == "GET" and parsed.path.startswith("/api/images/capture/"):
                parts = parsed.path.strip("/").split("/")
                if len(parts) != 4:
                    raise ValueError("Нужен capture jobId")
                self._send_json(SESSION.get_capture_job(parts[3]))
            elif method == "GET" and parsed.path.startswith("/api/forensics/deleted-files/"):
                parts = parsed.path.strip("/").split("/")
                if len(parts) < 4:
                    raise ValueError("Нужен номер inode")
                inode = _parse_int(parts[3])
                action = parts[4] if len(parts) > 4 else "detail"
                if action == "detail":
                    self._send_json(SESSION.deleted_file(inode))
                elif action == "preview":
                    self._send_json(
                        SESSION.deleted_file_preview(
                            inode,
                            _parse_int(query.get("length", ["4096"])[0], 4096),
                        )
                    )
                elif action == "recover":
                    recovery = SESSION.recover_deleted_file(inode)
                    self._send_bytes(
                        recovery["data"],
                        "application/octet-stream",
                        recovery["filename"],
                    )
                elif action == "report":
                    body = SESSION.deleted_file_report(inode).encode("utf-8")
                    self._send_bytes(
                        body,
                        "text/markdown; charset=utf-8",
                        f"forensics_inode_{inode}.md",
                    )
                else:
                    raise ValueError(f"Неизвестное forensic действие: {action}")
            elif method == "POST" and parsed.path == "/api/open":
                body = self._read_body()
                self._send_json(
                    SESSION.open_source(
                        str(body.get("path", "")),
                        bool(body.get("writable", False)),
                    )
                )
            elif method == "POST" and parsed.path == "/api/demo":
                path = _create_demo_image()
                self._send_json(SESSION.open_source(path, writable=True))
            elif method == "POST" and parsed.path == "/api/close":
                SESSION.close()
                self._send_json(SESSION.status())
            elif method == "POST" and parsed.path == "/api/write":
                body = self._read_body()
                data = _decode_bytes(str(body.get("data", "")), str(body.get("encoding", "hex")))
                self._send_json(SESSION.write(int(body.get("offset", 0)), data))
            elif method == "POST" and parsed.path == "/api/replace":
                body = self._read_body()
                encoding = str(body.get("encoding", "auto"))
                old = _decode_bytes(str(body.get("old", "")), encoding)
                new = _decode_bytes(str(body.get("new", "")), encoding)
                self._send_json(
                    SESSION.replace(
                        old,
                        new,
                        int(body.get("start", 0)),
                        bool(body.get("all", False)),
                    )
                )
            elif method == "POST" and parsed.path == "/api/undo":
                self._send_json(SESSION.undo())
            elif method == "POST" and parsed.path == "/api/redo":
                self._send_json(SESSION.redo())
            elif method == "POST" and parsed.path == "/api/forensics/cancel":
                body = self._read_body()
                token = str(body.get("token") or cancel_token or "")
                self._send_json({"cancelled": _request_forensic_cancel(token), "token": token})
            elif method == "POST" and parsed.path == "/api/images/capture":
                body = self._read_body()
                self._send_json(
                    SESSION.start_capture(
                        str(body.get("source", "")),
                        str(body.get("destination", "")),
                        bool(body.get("unmount", False)),
                    )
                )
            elif method == "POST" and parsed.path.startswith("/api/images/capture/") and parsed.path.endswith("/cancel"):
                parts = parsed.path.strip("/").split("/")
                if len(parts) != 5:
                    raise ValueError("Нужен capture jobId")
                self._send_json(SESSION.cancel_capture_job(parts[3]))
            else:
                self._send_json({"error": f"Неизвестный endpoint: {parsed.path}"}, status=404)
        except ForensicCancelled as exc:
            self._send_json({"error": str(exc), "cancelled": True}, status=499)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=400)
        finally:
            if parsed.path != "/api/forensics/cancel":
                _clear_cancel_event(cancel_token)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, filename: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="HexCorruptor web API bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), ApiHandler)
    print(f"HexCorruptor API listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        SESSION.close()
        server.server_close()


if __name__ == "__main__":
    main()
