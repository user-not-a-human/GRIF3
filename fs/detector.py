"""
Автоматическое определение типа файловой системы
по сигнатурам (magic numbers) в суперблоке.
"""

import struct
from typing import Optional, Type

from core.disk import DiskReader
from fs.base import FSParser
from fs.ext4 import Ext4Parser
from fs.xfs import XFSParser
from fs.btrfs import BtrfsParser
from fs.lightweight import ExFATParser, FATParser, NTFSParser

# Сигнатуры файловых систем
_SIGNATURES: list[tuple[int, bytes, Type[FSParser]]] = [
    # (смещение от начала раздела, magic bytes, класс парсера)
    (0x438, struct.pack('<H', 0xEF53), Ext4Parser),        # ext2/3/4
    (0,     b'XFSB',                   XFSParser),          # XFS
    (0x10040, b'_BHRfS_M',            BtrfsParser),        # Btrfs
    (3,     b'NTFS    ',              NTFSParser),          # NTFS
    (3,     b'EXFAT   ',              ExFATParser),         # exFAT
    (82,    b'FAT32   ',              FATParser),           # FAT32
    (54,    b'FAT16   ',              FATParser),           # FAT16
    (54,    b'FAT12   ',              FATParser),           # FAT12
]


def detect_filesystem(reader: DiskReader,
                      partition_offset: int = 0) -> Optional[FSParser]:
    """
    Определить тип ФС и вернуть соответствующий парсер.

    Проверяет magic numbers по известным смещениям.
    Возвращает None, если ФС не распознана.
    """
    for sig_offset, magic, parser_class in _SIGNATURES:
        abs_offset = partition_offset + sig_offset
        try:
            data = reader.read(abs_offset, len(magic))
        except (IOError, OSError):
            continue
        if data == magic:
            return parser_class(reader, partition_offset)
    return None


def detect_all_partitions(
        reader: DiskReader) -> list[tuple[int, FSParser]]:
    """
    Просканировать известные смещения на наличие ФС.

    Проверяет начало (offset 0) — полезно для образов разделов.
    Не реализует полный разбор таблицы разделов (MBR/GPT),
    но пытается найти ФС по сигнатурам.

    Возвращает список пар (offset, parser).
    """
    results = []

    # Пробуем offset 0 (образ раздела)
    parser = detect_filesystem(reader, 0)
    if parser is not None:
        results.append((0, parser))

    return results
