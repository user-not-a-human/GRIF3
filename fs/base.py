"""
Базовый интерфейс парсера файловой системы.

Все парсеры (ext4, XFS, Btrfs) наследуются от FSParser
и реализуют общий набор методов для навигации по
метаданным файловой системы.
"""

from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.disk import DiskReader


class FileType(IntEnum):
    UNKNOWN = 0
    REGULAR = 1
    DIRECTORY = 2
    CHARDEV = 3
    BLOCKDEV = 4
    FIFO = 5
    SOCKET = 6
    SYMLINK = 7


@dataclass
class ParsedField:
    """Одно поле разобранной структуры."""
    name: str
    offset: int          # смещение внутри структуры
    size: int            # размер в байтах
    raw: bytes           # сырые байты
    value: object        # интерпретированное значение
    description: str = ""


@dataclass
class ParsedStructure:
    """Набор разобранных полей структуры ФС."""
    name: str            # например, "Superblock", "Inode #2"
    disk_offset: int     # абсолютное смещение на диске
    size: int            # общий размер структуры в байтах
    fields: list[ParsedField] = field(default_factory=list)

    def add(self, name: str, offset: int, size: int,
            raw: bytes, value: object, description: str = "") -> None:
        self.fields.append(ParsedField(
            name=name, offset=offset, size=size,
            raw=raw, value=value, description=description
        ))


@dataclass
class DirEntry:
    """Запись каталога."""
    name: str
    inode: int
    file_type: FileType
    disk_offset: int
    rec_len: int


@dataclass
class InodeMeta:
    """Краткие метаданные инода."""
    number: int
    mode: int
    uid: int
    gid: int
    size: int
    links: int
    atime: Optional[datetime.datetime]
    mtime: Optional[datetime.datetime]
    ctime: Optional[datetime.datetime]
    flags: int
    file_type: FileType
    disk_offset: int


def ts_to_datetime(ts: int) -> Optional[datetime.datetime]:
    """Преобразовать UNIX timestamp в datetime (или None если 0)."""
    if ts == 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def format_mode(mode: int) -> str:
    """Форматировать права доступа в строку типа '-rwxr-xr-x'."""
    ftypes = {
        0o140000: 's', 0o120000: 'l', 0o100000: '-',
        0o060000: 'b', 0o040000: 'd', 0o020000: 'c',
        0o010000: 'p',
    }
    ft = ftypes.get(mode & 0o170000, '?')
    perms = ''
    for shift in (6, 3, 0):
        m = (mode >> shift) & 7
        perms += 'r' if m & 4 else '-'
        perms += 'w' if m & 2 else '-'
        perms += 'x' if m & 1 else '-'
    return ft + perms


def format_size(size: int) -> str:
    """Форматировать размер в человекочитаемый вид."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 ** 2:
        return f"{size / 1024:.1f} KiB"
    elif size < 1024 ** 3:
        return f"{size / 1024 ** 2:.1f} MiB"
    elif size < 1024 ** 4:
        return f"{size / 1024 ** 3:.1f} GiB"
    else:
        return f"{size / 1024 ** 4:.1f} TiB"


class FSParser(ABC):
    """Абстрактный парсер файловой системы."""

    def __init__(self, reader: DiskReader, partition_offset: int = 0):
        self._reader = reader
        self._partition_offset = partition_offset

    @property
    def partition_offset(self) -> int:
        return self._partition_offset

    @staticmethod
    @abstractmethod
    def fs_name() -> str:
        """Человекочитаемое имя ФС."""
        ...

    @abstractmethod
    def parse_superblock(self) -> ParsedStructure:
        """Разобрать суперблок."""
        ...

    @abstractmethod
    def get_inode(self, inode_number: int) -> ParsedStructure:
        """Разобрать инод по номеру."""
        ...

    @abstractmethod
    def get_inode_meta(self, inode_number: int) -> InodeMeta:
        """Получить краткие метаданные инода."""
        ...

    @abstractmethod
    def list_directory(self, inode_number: int) -> list[DirEntry]:
        """Прочитать записи каталога по номеру инода каталога."""
        ...

    @abstractmethod
    def get_block_group_count(self) -> int:
        """Количество групп блоков (или аналогичных единиц)."""
        ...

    @abstractmethod
    def get_block_group_info(self, group_index: int) -> ParsedStructure:
        """Информация о группе блоков."""
        ...

    @abstractmethod
    def get_fs_info(self) -> dict[str, str]:
        """Получить основную информацию о ФС в виде словаря."""
        ...

    def _read(self, offset: int, length: int) -> bytes:
        """Чтение с учётом смещения раздела."""
        return self._reader.read(self._partition_offset + offset, length)
