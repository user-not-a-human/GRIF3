"""
Парсер файловой системы Btrfs.

Разбирает суперблок и базовые структуры.
Btrfs использует little-endian и архитектуру Copy-on-Write
с B-деревьями для хранения метаданных.

Ссылки:
  - https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html
  - ctree.h в исходниках ядра Linux
"""

import struct
import uuid as _uuid
from typing import Optional

from core.disk import DiskReader
from fs.base import (
    FSParser, ParsedStructure, DirEntry, InodeMeta,
    FileType, ts_to_datetime, format_size, format_mode,
)

# ── Константы ──────────────────────────────────────────────

BTRFS_SUPER_OFFSET = 0x10000  # 64 KiB
BTRFS_MAGIC = b'_BHRfS_M'

BTRFS_ROOT_TREE_OBJECTID = 1
BTRFS_EXTENT_TREE_OBJECTID = 2
BTRFS_CHUNK_TREE_OBJECTID = 3
BTRFS_DEV_TREE_OBJECTID = 4
BTRFS_FS_TREE_OBJECTID = 5
BTRFS_ROOT_TREE_DIR_OBJECTID = 6
BTRFS_CSUM_TREE_OBJECTID = 7

BTRFS_FIRST_FREE_OBJECTID = 256

# Item types
BTRFS_INODE_ITEM_KEY = 1
BTRFS_INODE_REF_KEY = 12
BTRFS_DIR_ITEM_KEY = 84
BTRFS_DIR_INDEX_KEY = 96
BTRFS_EXTENT_DATA_KEY = 108
BTRFS_ROOT_ITEM_KEY = 132
BTRFS_ROOT_REF_KEY = 156

# Dir item types
BTRFS_FT_UNKNOWN  = 0
BTRFS_FT_REG_FILE = 1
BTRFS_FT_DIR      = 2
BTRFS_FT_CHRDEV   = 3
BTRFS_FT_BLKDEV   = 4
BTRFS_FT_FIFO     = 5
BTRFS_FT_SOCK     = 6
BTRFS_FT_SYMLINK  = 7

_FILE_TYPES = {
    BTRFS_FT_UNKNOWN:  FileType.UNKNOWN,
    BTRFS_FT_REG_FILE: FileType.REGULAR,
    BTRFS_FT_DIR:      FileType.DIRECTORY,
    BTRFS_FT_CHRDEV:   FileType.CHARDEV,
    BTRFS_FT_BLKDEV:   FileType.BLOCKDEV,
    BTRFS_FT_FIFO:     FileType.FIFO,
    BTRFS_FT_SOCK:     FileType.SOCKET,
    BTRFS_FT_SYMLINK:  FileType.SYMLINK,
}


class BtrfsParser(FSParser):
    """Парсер файловой системы Btrfs."""

    def __init__(self, reader: DiskReader, partition_offset: int = 0):
        super().__init__(reader, partition_offset)
        self._sb: Optional[dict] = None
        self._chunk_cache: list[tuple[int, int, int]] = []  # (logical, physical, size)

    @staticmethod
    def fs_name() -> str:
        return "Btrfs"

    # ── Суперблок ──────────────────────────────────────────

    def _read_superblock_raw(self) -> dict:
        if self._sb is not None:
            return self._sb

        data = self._read(BTRFS_SUPER_OFFSET, 4096)
        if len(data) < 512:
            raise ValueError("Недостаточно данных для суперблока Btrfs")

        magic = data[64:72]
        if magic != BTRFS_MAGIC:
            raise ValueError(
                f"Неверная сигнатура Btrfs: {magic!r} "
                f"(ожидалось {BTRFS_MAGIC!r})"
            )

        sb = {}
        sb['csum']              = data[0:32]
        sb['fsid']              = data[32:48]
        sb['bytenr']            = struct.unpack_from('<Q', data, 48)[0]
        sb['flags']             = struct.unpack_from('<Q', data, 56)[0]
        sb['magic']             = magic
        sb['generation']        = struct.unpack_from('<Q', data, 72)[0]
        sb['root']              = struct.unpack_from('<Q', data, 80)[0]
        sb['chunk_root']        = struct.unpack_from('<Q', data, 88)[0]
        sb['log_root']          = struct.unpack_from('<Q', data, 96)[0]
        sb['log_root_transid']  = struct.unpack_from('<Q', data, 104)[0]
        sb['total_bytes']       = struct.unpack_from('<Q', data, 112)[0]
        sb['bytes_used']        = struct.unpack_from('<Q', data, 120)[0]
        sb['root_dir_objectid'] = struct.unpack_from('<Q', data, 128)[0]
        sb['num_devices']       = struct.unpack_from('<Q', data, 136)[0]
        sb['sectorsize']        = struct.unpack_from('<I', data, 144)[0]
        sb['nodesize']          = struct.unpack_from('<I', data, 148)[0]
        sb['leafsize']          = struct.unpack_from('<I', data, 152)[0]
        sb['stripesize']        = struct.unpack_from('<I', data, 156)[0]
        sb['sys_chunk_array_size'] = struct.unpack_from('<I', data, 160)[0]
        sb['chunk_root_generation'] = struct.unpack_from('<Q', data, 164)[0]
        sb['compat_flags']      = struct.unpack_from('<Q', data, 172)[0]
        sb['compat_ro_flags']   = struct.unpack_from('<Q', data, 180)[0]
        sb['incompat_flags']    = struct.unpack_from('<Q', data, 188)[0]
        sb['csum_type']         = struct.unpack_from('<H', data, 196)[0]
        sb['root_level']        = data[198]
        sb['chunk_root_level']  = data[199]
        sb['log_root_level']    = data[200]

        # dev_item: 98 байт начиная с offset 203
        sb['dev_item_devid']    = struct.unpack_from('<Q', data, 203)[0]
        sb['dev_item_total']    = struct.unpack_from('<Q', data, 211)[0]
        sb['dev_item_used']     = struct.unpack_from('<Q', data, 219)[0]

        # Label: 256 байт начиная с offset 299
        sb['label']             = data[299:555].split(b'\x00')[0].decode(
                                      'utf-8', errors='replace')

        # sys_chunk_array: 2048 байт с offset 587
        sb['sys_chunk_array']   = data[587:587 + sb['sys_chunk_array_size']]

        self._sb = sb
        self._parse_sys_chunk_array(sb)
        return sb

    def _parse_sys_chunk_array(self, sb: dict) -> None:
        """Разбор sys_chunk_array для маппинга logical → physical."""
        self._chunk_cache.clear()
        arr = sb['sys_chunk_array']
        pos = 0
        while pos + 48 < len(arr):
            # btrfs_disk_key: objectid(8) + type(1) + offset(8) = 17 bytes
            # chunk: length(8) + owner(8) + stripe_len(8) + type(8) +
            #        io_align(4) + io_width(4) + sector_size(4) + num_stripes(2) +
            #        sub_stripes(2)
            # total key+chunk_header = 17 + 48 = 65
            # Then per stripe: devid(8) + offset(8) + dev_uuid(16) = 32
            logical = struct.unpack_from('<Q', arr, pos + 8)[0]  # key.offset
            pos += 17  # skip key

            if pos + 48 > len(arr):
                break

            length = struct.unpack_from('<Q', arr, pos)[0]
            num_stripes = struct.unpack_from('<H', arr, pos + 44)[0]
            pos += 48  # skip chunk header

            if num_stripes > 0 and pos + 32 <= len(arr):
                # Берём первый stripe
                physical = struct.unpack_from('<Q', arr, pos + 8)[0]
                self._chunk_cache.append((logical, physical, length))

            pos += num_stripes * 32  # skip stripes

    def _logical_to_physical(self, logical: int) -> Optional[int]:
        """Преобразование логического адреса Btrfs в физический."""
        for chunk_log, chunk_phys, chunk_len in self._chunk_cache:
            if chunk_log <= logical < chunk_log + chunk_len:
                return chunk_phys + (logical - chunk_log)
        return None

    def parse_superblock(self) -> ParsedStructure:
        sb = self._read_superblock_raw()
        data = self._read(BTRFS_SUPER_OFFSET, 4096)
        disk_off = self._partition_offset + BTRFS_SUPER_OFFSET

        ps = ParsedStructure(
            name="Суперблок Btrfs",
            disk_offset=disk_off,
            size=4096,
        )

        def a(name, off, sz, val, desc=""):
            ps.add(name, off, sz, data[off:off+sz], val, desc)

        a("csum",          0, 32, sb['csum'].hex(),
          "Контрольная сумма")
        a("fsid",         32, 16,
          str(_uuid.UUID(bytes_le=sb['fsid'])), "UUID файловой системы")
        a("bytenr",       48,  8, sb['bytenr'],
          "Смещение суперблока на диске")
        a("flags",        56,  8, f"0x{sb['flags']:016X}",
          "Флаги")
        a("magic",        64,  8, sb['magic'].decode('ascii'),
          "Сигнатура '_BHRfS_M'")
        a("generation",   72,  8, sb['generation'],
          "Поколение (транзакция)")
        a("root",         80,  8, sb['root'],
          "Логический адрес корня дерева ФС")
        a("chunk_root",   88,  8, sb['chunk_root'],
          "Логический адрес chunk-дерева")
        a("log_root",     96,  8, sb['log_root'],
          "Логический адрес дерева журнала")
        a("total_bytes", 112,  8,
          f"{sb['total_bytes']} ({format_size(sb['total_bytes'])})",
          "Общий объём устройства")
        a("bytes_used",  120,  8,
          f"{sb['bytes_used']} ({format_size(sb['bytes_used'])})",
          "Использовано байт")
        a("num_devices",  136,  8, sb['num_devices'],
          "Число устройств")
        a("sectorsize",   144,  4, sb['sectorsize'],
          "Размер сектора")
        a("nodesize",     148,  4, sb['nodesize'],
          "Размер узла дерева")
        a("leafsize",     152,  4, sb['leafsize'],
          "Размер листа (= nodesize)")
        a("stripesize",   156,  4, sb['stripesize'],
          "Размер stripe")
        a("csum_type",    196,  2, sb['csum_type'],
          "Тип контрольной суммы (0=CRC32C)")
        a("root_level",   198,  1, sb['root_level'],
          "Глубина корневого дерева")
        a("label",        299, 256, sb['label'],
          "Метка тома")
        a("incompat_flags", 188, 8,
          f"0x{sb['incompat_flags']:016X}",
          "Флаги несовместимости")

        return ps

    # ── Чтение узлов дерева ────────────────────────────────

    def _read_tree_node(self, logical_addr: int) -> Optional[bytes]:
        """Прочитать узел B-дерева по логическому адресу."""
        sb = self._read_superblock_raw()
        phys = self._logical_to_physical(logical_addr)
        if phys is None:
            return None
        return self._read(phys, sb['nodesize'])

    def _parse_leaf_items(self, node_data: bytes) -> list[dict]:
        """Разобрать элементы листового узла btrfs."""
        if len(node_data) < 101:
            return []

        # Header: csum(32) + fsid(16) + bytenr(8) + flags(8) +
        #         chunk_tree_uuid(16) + generation(8) + owner(8) +
        #         nritems(4) + level(1) = 101
        nritems = struct.unpack_from('<I', node_data, 96)[0]
        level = node_data[100]

        if level != 0:
            return []  # не лист

        items = []
        for i in range(min(nritems, 200)):
            item_off = 101 + i * 25
            if item_off + 25 > len(node_data):
                break
            # btrfs_item: key(17) + offset(4) + size(4) = 25
            objectid = struct.unpack_from('<Q', node_data, item_off)[0]
            item_type = node_data[item_off + 8]
            key_offset = struct.unpack_from('<Q', node_data, item_off + 9)[0]
            data_offset = struct.unpack_from('<I', node_data, item_off + 17)[0]
            data_size = struct.unpack_from('<I', node_data, item_off + 21)[0]

            # Данные элемента идут от конца заголовка + data_offset
            data_start = 101 + data_offset
            item_data = b''
            if data_start + data_size <= len(node_data):
                item_data = node_data[data_start:data_start + data_size]

            items.append({
                'objectid': objectid,
                'type': item_type,
                'offset': key_offset,
                'data_offset': data_offset,
                'data_size': data_size,
                'data': item_data,
            })

        return items

    # ── Иноды ──────────────────────────────────────────────

    def _find_root_node(self) -> Optional[bytes]:
        """Читаем корень FS tree через root tree."""
        sb = self._read_superblock_raw()
        root_node = self._read_tree_node(sb['root'])
        if root_node is None:
            return None

        level = root_node[100] if len(root_node) > 100 else 255

        if level == 0:
            # Это лист — ищем ROOT_ITEM для FS_TREE_OBJECTID
            items = self._parse_leaf_items(root_node)
            for item in items:
                if (item['objectid'] == BTRFS_FS_TREE_OBJECTID and
                        item['type'] == BTRFS_ROOT_ITEM_KEY):
                    # root_item содержит bytenr(8) корня дерева ФС на offset 0
                    if len(item['data']) >= 8:
                        fs_root_bytenr = struct.unpack_from(
                            '<Q', item['data'], 0)[0]
                        return self._read_tree_node(fs_root_bytenr)
        return None

    def get_inode(self, inode_number: int) -> ParsedStructure:
        sb = self._read_superblock_raw()
        inode_data = self._find_inode_item(inode_number)

        if inode_data is None:
            # Возвращаем пустую структуру
            ps = ParsedStructure(
                name=f"Инод Btrfs #{inode_number} (не найден)",
                disk_offset=0, size=0)
            ps.add("Ошибка", 0, 0, b'',
                   "Инод не найден в дереве ФС",
                   "Возможно, не удалось пройти по B-дереву")
            return ps

        data, disk_offset = inode_data
        return self._parse_inode_struct(data, inode_number, disk_offset)

    def _find_inode_item(
            self, inode_number: int) -> Optional[tuple[bytes, int]]:
        """Найти INODE_ITEM в FS tree."""
        fs_root = self._find_root_node()
        if fs_root is None:
            return None

        items = self._parse_leaf_items(fs_root)
        for item in items:
            if (item['objectid'] == inode_number and
                    item['type'] == BTRFS_INODE_ITEM_KEY and
                    len(item['data']) >= 160):
                sb = self._read_superblock_raw()
                phys = self._logical_to_physical(sb['root'])
                off = phys + 101 + item['data_offset'] if phys else 0
                return item['data'], self._partition_offset + off
        return None

    def _parse_inode_struct(self, data: bytes, inode_number: int,
                            disk_offset: int) -> ParsedStructure:
        """Разобрать btrfs_inode_item (160 байт)."""
        ps = ParsedStructure(
            name=f"Инод Btrfs #{inode_number}",
            disk_offset=disk_offset,
            size=160,
        )

        generation = struct.unpack_from('<Q', data, 0)[0]
        transid    = struct.unpack_from('<Q', data, 8)[0]
        size       = struct.unpack_from('<Q', data, 16)[0]
        nbytes     = struct.unpack_from('<Q', data, 24)[0]
        block_group = struct.unpack_from('<Q', data, 32)[0]
        nlink      = struct.unpack_from('<I', data, 40)[0]
        uid        = struct.unpack_from('<I', data, 44)[0]
        gid        = struct.unpack_from('<I', data, 48)[0]
        mode       = struct.unpack_from('<I', data, 52)[0]
        rdev       = struct.unpack_from('<Q', data, 56)[0]
        flags      = struct.unpack_from('<Q', data, 64)[0]
        sequence   = struct.unpack_from('<Q', data, 72)[0]
        # timespec: sec(8) + nsec(4)
        atime_sec  = struct.unpack_from('<Q', data, 112)[0]
        mtime_sec  = struct.unpack_from('<Q', data, 124)[0]
        ctime_sec  = struct.unpack_from('<Q', data, 136)[0]
        otime_sec  = struct.unpack_from('<Q', data, 148)[0]

        ps.add("generation", 0, 8, data[0:8], generation, "Поколение")
        ps.add("transid",    8, 8, data[8:16], transid, "ID транзакции")
        ps.add("size",      16, 8, data[16:24],
               f"{size} ({format_size(size)})", "Размер")
        ps.add("nbytes",    24, 8, data[24:32], nbytes, "Число байт на диске")
        ps.add("nlink",     40, 4, data[40:44], nlink, "Жёстких ссылок")
        ps.add("uid",       44, 4, data[44:48], uid, "UID")
        ps.add("gid",       48, 4, data[48:52], gid, "GID")
        ps.add("mode",      52, 4, data[52:56],
               f"0o{mode:06o} ({format_mode(mode)})", "Тип и права")
        ps.add("flags",     64, 8, data[64:72],
               f"0x{flags:016X}", "Флаги")
        ps.add("atime",    112, 12, data[112:124],
               str(ts_to_datetime(atime_sec) or "—"), "Время доступа")
        ps.add("mtime",    124, 12, data[124:136],
               str(ts_to_datetime(mtime_sec) or "—"), "Время изменения")
        ps.add("ctime",    136, 12, data[136:148],
               str(ts_to_datetime(ctime_sec) or "—"), "Время метаданных")
        ps.add("otime",    148, 12, data[148:160],
               str(ts_to_datetime(otime_sec) or "—"), "Время создания")

        return ps

    def get_inode_meta(self, inode_number: int) -> InodeMeta:
        result = self._find_inode_item(inode_number)
        if result is None:
            return InodeMeta(
                number=inode_number, mode=0, uid=0, gid=0,
                size=0, links=0, atime=None, mtime=None, ctime=None,
                flags=0, file_type=FileType.UNKNOWN, disk_offset=0,
            )
        data, disk_offset = result
        size   = struct.unpack_from('<Q', data, 16)[0]
        nlink  = struct.unpack_from('<I', data, 40)[0]
        uid    = struct.unpack_from('<I', data, 44)[0]
        gid    = struct.unpack_from('<I', data, 48)[0]
        mode   = struct.unpack_from('<I', data, 52)[0]
        flags  = struct.unpack_from('<Q', data, 64)[0]
        atime  = struct.unpack_from('<Q', data, 112)[0]
        mtime  = struct.unpack_from('<Q', data, 124)[0]
        ctime  = struct.unpack_from('<Q', data, 136)[0]

        mode_type = mode & 0o170000
        ft_map = {
            0o100000: FileType.REGULAR,
            0o040000: FileType.DIRECTORY,
            0o120000: FileType.SYMLINK,
        }

        return InodeMeta(
            number=inode_number,
            mode=mode, uid=uid, gid=gid, size=size, links=nlink,
            atime=ts_to_datetime(atime),
            mtime=ts_to_datetime(mtime),
            ctime=ts_to_datetime(ctime),
            flags=flags,
            file_type=ft_map.get(mode_type, FileType.UNKNOWN),
            disk_offset=disk_offset,
        )

    # ── Каталоги ───────────────────────────────────────────

    def list_directory(self, inode_number: int) -> list[DirEntry]:
        """
        Прочитать записи каталога Btrfs.

        Ищет DIR_ITEM и DIR_INDEX записи в FS tree.
        """
        fs_root = self._find_root_node()
        if fs_root is None:
            return []

        items = self._parse_leaf_items(fs_root)
        entries = []

        for item in items:
            if item['objectid'] != inode_number:
                continue
            if item['type'] not in (BTRFS_DIR_ITEM_KEY, BTRFS_DIR_INDEX_KEY):
                continue

            data = item['data']
            if len(data) < 30:
                continue

            # btrfs_dir_item:
            # location: key(17) + transid(8) + data_len(2) + name_len(2) + type(1) = 30
            child_objectid = struct.unpack_from('<Q', data, 0)[0]
            child_type = data[8]
            data_len = struct.unpack_from('<H', data, 25)[0]
            name_len = struct.unpack_from('<H', data, 27)[0]
            ftype = data[29]

            if name_len > 0 and 30 + name_len <= len(data):
                name = data[30:30 + name_len].decode(
                    'utf-8', errors='replace')
                entries.append(DirEntry(
                    name=name,
                    inode=child_objectid,
                    file_type=_FILE_TYPES.get(ftype, FileType.UNKNOWN),
                    disk_offset=0,
                    rec_len=30 + name_len + data_len,
                ))

        return entries

    # ── Группы ─────────────────────────────────────────────

    def get_block_group_count(self) -> int:
        sb = self._read_superblock_raw()
        if sb['nodesize'] == 0:
            return 0
        return max(1, int(sb['total_bytes'] // (1024 * 1024 * 1024)))

    def get_block_group_info(self, group_index: int) -> ParsedStructure:
        sb = self._read_superblock_raw()
        ps = ParsedStructure(
            name=f"Chunk/Block Group #{group_index}",
            disk_offset=0,
            size=0,
        )
        ps.add("info", 0, 0, b'',
               "Btrfs использует chunk tree вместо групп блоков",
               "Для детального анализа используйте btrfs inspect")
        ps.add("total_bytes", 0, 0, b'',
               format_size(sb['total_bytes']),
               "Общий объём")
        ps.add("bytes_used", 0, 0, b'',
               format_size(sb['bytes_used']),
               "Использовано")
        return ps

    def get_inode_count(self) -> int:
        return 0  # Btrfs не имеет фиксированного счётчика инодов

    # ── Сводка ─────────────────────────────────────────────

    def get_fs_info(self) -> dict[str, str]:
        sb = self._read_superblock_raw()
        csum_names = {0: "CRC32C", 1: "xxhash64", 2: "SHA256", 3: "BLAKE2b"}

        return {
            "Файловая система": "Btrfs",
            "UUID": str(_uuid.UUID(bytes_le=sb['fsid'])),
            "Метка тома": sb['label'] or "—",
            "Объём ФС": format_size(sb['total_bytes']),
            "Использовано": format_size(sb['bytes_used']),
            "Размер сектора": f"{sb['sectorsize']} байт",
            "Размер узла": f"{sb['nodesize']} байт",
            "Число устройств": f"{sb['num_devices']}",
            "Поколение": f"{sb['generation']}",
            "Контрольная сумма": csum_names.get(
                sb['csum_type'], str(sb['csum_type'])),
            "Корень FS tree": f"0x{sb['root']:X}",
            "Корень chunk tree": f"0x{sb['chunk_root']:X}",
            "Флаги несовместимости": f"0x{sb['incompat_flags']:X}",
        }
