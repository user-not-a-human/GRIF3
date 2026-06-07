"""
Модуль доступа к блочным устройствам и образам дисков.

Предоставляет унифицированный интерфейс для чтения/записи
произвольных областей диска с поддержкой кэширования и
автоматическим определением размера устройства.
"""

import os
import fcntl
import struct
import stat
from typing import Optional

# Linux ioctl для получения размера блочного устройства
BLKGETSIZE64 = 0x80081272


class DiskReader:
    """Унифицированный доступ к блочным устройствам и файлам-образам."""

    def __init__(self, path: str, read_only: bool = True):
        self._path = path
        self._read_only = read_only
        self._fd: Optional[int] = None
        self._file = None
        self._size: int = 0
        self._is_block_device = False
        self._cache: dict[tuple[int, int], bytes] = {}
        self._cache_max = 256

    @property
    def path(self) -> str:
        return self._path

    @property
    def size(self) -> int:
        return self._size

    @property
    def is_block_device(self) -> bool:
        return self._is_block_device

    @property
    def is_open(self) -> bool:
        return self._file is not None

    def open(self) -> None:
        """Открыть устройство или файл-образ."""
        if self._file is not None:
            raise RuntimeError("Устройство уже открыто")

        mode = os.O_RDONLY if self._read_only else os.O_RDWR
        try:
            st = os.stat(self._path)
        except OSError as e:
            raise IOError(f"Не удалось получить информацию о '{self._path}': {e}")

        self._is_block_device = stat.S_ISBLK(st.st_mode)

        if self._is_block_device:
            # Блочное устройство — открываем через os.open для ioctl
            try:
                self._fd = os.open(self._path, mode)
            except PermissionError:
                raise PermissionError(
                    f"Нет прав на чтение '{self._path}'. "
                    f"Запустите программу с sudo."
                )
            self._file = os.fdopen(self._fd, 'rb' if self._read_only else 'r+b')
            self._size = self._get_block_device_size()
        else:
            # Обычный файл (образ диска)
            try:
                self._file = open(
                    self._path, 'rb' if self._read_only else 'r+b'
                )
            except PermissionError:
                raise PermissionError(
                    f"Нет прав на чтение '{self._path}'."
                )
            self._file.seek(0, os.SEEK_END)
            self._size = self._file.tell()
            self._file.seek(0)

    def _get_block_device_size(self) -> int:
        """Получить размер блочного устройства через ioctl."""
        buf = bytearray(8)
        try:
            fcntl.ioctl(self._fd, BLKGETSIZE64, buf)
            return struct.unpack('<Q', buf)[0]
        except OSError:
            # Фоллбэк: seek до конца
            self._file.seek(0, os.SEEK_END)
            size = self._file.tell()
            self._file.seek(0)
            return size

    def read(self, offset: int, length: int) -> bytes:
        """
        Прочитать данные с указанного смещения.

        Возвращает bytes длиной до `length` (может быть меньше,
        если достигнут конец устройства).
        """
        if self._file is None:
            raise RuntimeError("Устройство не открыто")
        if offset < 0:
            raise ValueError("Смещение не может быть отрицательным")
        if length <= 0:
            return b''
        if offset >= self._size:
            return b''

        # Обрезаем если выходим за границу
        length = min(length, self._size - offset)

        # Проверяем кэш
        cache_key = (offset, length)
        if cache_key in self._cache:
            return self._cache[cache_key]

        self._file.seek(offset)
        data = self._file.read(length)

        # Кэшируем
        if len(self._cache) >= self._cache_max:
            # Удаляем самый старый элемент
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[cache_key] = data

        return data

    def write(self, offset: int, data: bytes) -> int:
        """
        Записать данные по указанному смещению.

        Возвращает количество записанных байт.
        """
        if self._file is None:
            raise RuntimeError("Устройство не открыто")
        if self._read_only:
            raise RuntimeError("Устройство открыто только для чтения")
        if offset < 0:
            raise ValueError("Смещение не может быть отрицательным")
        if offset >= self._size:
            raise ValueError("Смещение за пределами устройства")

        self._file.seek(offset)
        written = self._file.write(data)
        self._file.flush()

        # Инвалидируем кэш для затронутой области
        keys_to_remove = []
        for (co, cl) in self._cache:
            if co < offset + len(data) and co + cl > offset:
                keys_to_remove.append((co, cl))
        for key in keys_to_remove:
            del self._cache[key]

        return written

    def invalidate_cache(self) -> None:
        """Очистить кэш чтения."""
        self._cache.clear()

    def close(self) -> None:
        """Закрыть устройство."""
        if self._file is not None:
            self._file.close()
            self._file = None
            self._fd = None
            self._cache.clear()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __repr__(self):
        status = "open" if self.is_open else "closed"
        kind = "block device" if self._is_block_device else "image"
        return f"<DiskReader '{self._path}' ({kind}, {status})>"
