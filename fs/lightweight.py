"""
Lightweight parsers for common filesystems.

These parsers intentionally expose boot/superblock metadata and raw-search
capability only. Deep directory traversal and deleted-file recovery stay in the
dedicated filesystem parsers.
"""

from __future__ import annotations

import datetime
import struct
from typing import Any

from core.disk import DiskReader
from fs.base import (
    DirEntry,
    FSParser,
    FileType,
    InodeMeta,
    ParsedStructure,
    format_size,
)


def _dos_label(raw: bytes) -> str:
    return raw.decode("ascii", errors="replace").strip() or "—"


def _empty_inode_meta(number: int = 0) -> InodeMeta:
    return InodeMeta(
        number=number,
        mode=0,
        uid=0,
        gid=0,
        size=0,
        links=0,
        atime=None,
        mtime=None,
        ctime=None,
        flags=0,
        file_type=FileType.UNKNOWN,
        disk_offset=0,
    )


class _BootSectorParser(FSParser):
    _name = "unknown"
    _boot_size = 512

    def __init__(self, reader: DiskReader, partition_offset: int = 0):
        super().__init__(reader, partition_offset)
        self._boot: dict[str, Any] | None = None

    @staticmethod
    def fs_name() -> str:
        return "unknown"

    def _read_boot(self) -> bytes:
        data = self._read(0, self._boot_size)
        if len(data) < 90:
            raise ValueError("Недостаточно данных для boot sector")
        return data

    def parse_superblock(self) -> ParsedStructure:
        boot = self._read_boot()
        ps = ParsedStructure(
            name=f"Boot sector {self.fs_name()}",
            disk_offset=self._partition_offset,
            size=min(len(boot), self._boot_size),
        )
        ps.add("jump", 0, 3, boot[0:3], boot[0:3].hex(" "), "Boot jump")
        ps.add("oem", 3, 8, boot[3:11], _dos_label(boot[3:11]), "OEM / FS marker")
        ps.add("signature", 510, 2, boot[510:512] if len(boot) >= 512 else b"",
               boot[510:512].hex(" ") if len(boot) >= 512 else "—",
               "Boot sector signature")
        return ps

    def get_inode(self, inode_number: int) -> ParsedStructure:
        ps = ParsedStructure(
            name=f"{self.fs_name()} inode/object #{inode_number} (not supported)",
            disk_offset=0,
            size=0,
        )
        ps.add("info", 0, 0, b"", "Metadata object parsing is not implemented", "")
        return ps

    def get_inode_meta(self, inode_number: int) -> InodeMeta:
        return _empty_inode_meta(inode_number)

    def list_directory(self, inode_number: int) -> list[DirEntry]:
        return []

    def get_block_group_count(self) -> int:
        return 0

    def get_block_group_info(self, group_index: int) -> ParsedStructure:
        ps = ParsedStructure(
            name=f"{self.fs_name()} allocation group #{group_index} (not supported)",
            disk_offset=0,
            size=0,
        )
        ps.add("info", 0, 0, b"", "No block group view for lightweight parser", "")
        return ps

    def get_inode_count(self) -> int:
        return 0


class NTFSParser(_BootSectorParser):
    @staticmethod
    def fs_name() -> str:
        return "NTFS"

    def _read_superblock_raw(self) -> dict[str, Any]:
        if self._boot is not None:
            return self._boot
        data = self._read_boot()
        if data[3:11] != b"NTFS    ":
            raise ValueError("Неверная сигнатура NTFS")
        bytes_per_sector = struct.unpack_from("<H", data, 11)[0]
        sectors_per_cluster = data[13]
        total_sectors = struct.unpack_from("<Q", data, 40)[0]
        mft_cluster = struct.unpack_from("<Q", data, 48)[0]
        mft_mirror_cluster = struct.unpack_from("<Q", data, 56)[0]
        clusters_per_mft_record = struct.unpack_from("<b", data, 64)[0]
        if clusters_per_mft_record < 0:
            mft_record_size = 1 << abs(clusters_per_mft_record)
        else:
            mft_record_size = clusters_per_mft_record * bytes_per_sector * sectors_per_cluster
        self._boot = {
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "cluster_size": bytes_per_sector * sectors_per_cluster,
            "total_sectors": total_sectors,
            "mft_cluster": mft_cluster,
            "mft_mirror_cluster": mft_mirror_cluster,
            "mft_record_size": mft_record_size,
        }
        return self._boot

    def parse_superblock(self) -> ParsedStructure:
        raw = self._read_superblock_raw()
        data = self._read_boot()
        ps = super().parse_superblock()
        ps.name = "Boot sector NTFS"
        ps.add("bytes_per_sector", 11, 2, data[11:13], raw["bytes_per_sector"], "")
        ps.add("sectors_per_cluster", 13, 1, data[13:14], raw["sectors_per_cluster"], "")
        ps.add("cluster_size", -1, 0, b"", f"{raw['cluster_size']} байт", "")
        ps.add("total_sectors", 40, 8, data[40:48], raw["total_sectors"], "")
        ps.add("$MFT cluster", 48, 8, data[48:56], raw["mft_cluster"], "")
        ps.add("$MFTMirr cluster", 56, 8, data[56:64], raw["mft_mirror_cluster"], "")
        ps.add("mft_record_size", -1, 0, b"", raw["mft_record_size"], "")
        return ps

    def get_fs_info(self) -> dict[str, str]:
        raw = self._read_superblock_raw()
        return {
            "Файловая система": "NTFS",
            "Размер сектора": f"{raw['bytes_per_sector']} байт",
            "Размер кластера": f"{raw['cluster_size']} байт",
            "Объём": format_size(raw["total_sectors"] * raw["bytes_per_sector"]),
            "$MFT cluster": str(raw["mft_cluster"]),
            "MFT record": f"{raw['mft_record_size']} байт",
        }


class ExFATParser(_BootSectorParser):
    @staticmethod
    def fs_name() -> str:
        return "exFAT"

    def _read_superblock_raw(self) -> dict[str, Any]:
        if self._boot is not None:
            return self._boot
        data = self._read_boot()
        if data[3:11] != b"EXFAT   ":
            raise ValueError("Неверная сигнатура exFAT")
        partition_offset = struct.unpack_from("<Q", data, 64)[0]
        volume_length = struct.unpack_from("<Q", data, 72)[0]
        fat_offset = struct.unpack_from("<I", data, 80)[0]
        fat_length = struct.unpack_from("<I", data, 84)[0]
        cluster_heap_offset = struct.unpack_from("<I", data, 88)[0]
        cluster_count = struct.unpack_from("<I", data, 92)[0]
        root_cluster = struct.unpack_from("<I", data, 96)[0]
        sector_shift = data[108]
        cluster_shift = data[109]
        bytes_per_sector = 1 << sector_shift
        sectors_per_cluster = 1 << cluster_shift
        self._boot = {
            "partition_offset": partition_offset,
            "volume_length": volume_length,
            "fat_offset": fat_offset,
            "fat_length": fat_length,
            "cluster_heap_offset": cluster_heap_offset,
            "cluster_count": cluster_count,
            "root_cluster": root_cluster,
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "cluster_size": bytes_per_sector * sectors_per_cluster,
        }
        return self._boot

    def parse_superblock(self) -> ParsedStructure:
        raw = self._read_superblock_raw()
        data = self._read_boot()
        ps = super().parse_superblock()
        ps.name = "Boot sector exFAT"
        ps.add("volume_length", 72, 8, data[72:80], raw["volume_length"], "")
        ps.add("fat_offset", 80, 4, data[80:84], raw["fat_offset"], "")
        ps.add("fat_length", 84, 4, data[84:88], raw["fat_length"], "")
        ps.add("cluster_heap_offset", 88, 4, data[88:92], raw["cluster_heap_offset"], "")
        ps.add("cluster_count", 92, 4, data[92:96], raw["cluster_count"], "")
        ps.add("root_cluster", 96, 4, data[96:100], raw["root_cluster"], "")
        ps.add("cluster_size", -1, 0, b"", f"{raw['cluster_size']} байт", "")
        return ps

    def get_fs_info(self) -> dict[str, str]:
        raw = self._read_superblock_raw()
        return {
            "Файловая система": "exFAT",
            "Размер сектора": f"{raw['bytes_per_sector']} байт",
            "Размер кластера": f"{raw['cluster_size']} байт",
            "Кластеров": str(raw["cluster_count"]),
            "Root cluster": str(raw["root_cluster"]),
            "Объём": format_size(raw["volume_length"] * raw["bytes_per_sector"]),
        }


class FATParser(_BootSectorParser):
    def __init__(self, reader: DiskReader, partition_offset: int = 0):
        super().__init__(reader, partition_offset)
        self._fat_name = "FAT"

    @staticmethod
    def fs_name() -> str:
        return "FAT"

    def _read_superblock_raw(self) -> dict[str, Any]:
        if self._boot is not None:
            return self._boot
        data = self._read_boot()
        if len(data) < 90 or data[510:512] != b"\x55\xaa":
            raise ValueError("Неверная сигнатура FAT")
        bytes_per_sector = struct.unpack_from("<H", data, 11)[0]
        sectors_per_cluster = data[13]
        reserved = struct.unpack_from("<H", data, 14)[0]
        fats = data[16]
        root_entries = struct.unpack_from("<H", data, 17)[0]
        total16 = struct.unpack_from("<H", data, 19)[0]
        total32 = struct.unpack_from("<I", data, 32)[0]
        fat16 = struct.unpack_from("<H", data, 22)[0]
        fat32 = struct.unpack_from("<I", data, 36)[0] if len(data) >= 90 else 0
        total_sectors = total16 or total32
        fat_size = fat16 or fat32
        root_cluster = struct.unpack_from("<I", data, 44)[0] if fat32 else 0
        marker = data[82:90] if fat32 else data[54:62]
        self._fat_name = "FAT32" if fat32 else _dos_label(marker) or "FAT"
        self._boot = {
            "fat_name": self._fat_name,
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "cluster_size": bytes_per_sector * sectors_per_cluster,
            "reserved_sectors": reserved,
            "fats": fats,
            "root_entries": root_entries,
            "total_sectors": total_sectors,
            "fat_size": fat_size,
            "root_cluster": root_cluster,
            "volume_label": _dos_label(data[71:82] if fat32 else data[43:54]),
        }
        return self._boot

    def fs_name(self) -> str:  # type: ignore[override]
        try:
            return self._read_superblock_raw().get("fat_name", "FAT")
        except Exception:
            return "FAT"

    def parse_superblock(self) -> ParsedStructure:
        raw = self._read_superblock_raw()
        data = self._read_boot()
        ps = super().parse_superblock()
        ps.name = f"Boot sector {raw['fat_name']}"
        ps.add("bytes_per_sector", 11, 2, data[11:13], raw["bytes_per_sector"], "")
        ps.add("sectors_per_cluster", 13, 1, data[13:14], raw["sectors_per_cluster"], "")
        ps.add("reserved_sectors", 14, 2, data[14:16], raw["reserved_sectors"], "")
        ps.add("number_of_fats", 16, 1, data[16:17], raw["fats"], "")
        ps.add("root_entries", 17, 2, data[17:19], raw["root_entries"], "")
        ps.add("total_sectors", -1, 0, b"", raw["total_sectors"], "")
        ps.add("fat_size", -1, 0, b"", raw["fat_size"], "")
        ps.add("root_cluster", 44, 4, data[44:48], raw["root_cluster"], "")
        ps.add("volume_label", -1, 0, b"", raw["volume_label"], "")
        return ps

    def get_fs_info(self) -> dict[str, str]:
        raw = self._read_superblock_raw()
        return {
            "Файловая система": raw["fat_name"],
            "Метка тома": raw["volume_label"],
            "Размер сектора": f"{raw['bytes_per_sector']} байт",
            "Размер кластера": f"{raw['cluster_size']} байт",
            "FAT tables": str(raw["fats"]),
            "Root cluster": str(raw["root_cluster"] or "—"),
            "Объём": format_size(raw["total_sectors"] * raw["bytes_per_sector"]),
        }
