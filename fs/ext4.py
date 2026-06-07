"""
Парсер файловой системы ext4 (ext2/ext3/ext4).

Разбирает суперблок, дескрипторы групп блоков, иноды
и записи каталогов по спецификации ядра Linux.

Ссылка: https://www.kernel.org/doc/html/latest/filesystems/ext4/
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

EXT4_SUPER_MAGIC = 0xEF53
EXT4_SUPERBLOCK_OFFSET = 1024
EXT4_SUPERBLOCK_SIZE = 1024

# Флаги совместимости (incompat)
EXT4_FEATURE_INCOMPAT_64BIT = 0x0080
EXT4_FEATURE_INCOMPAT_EXTENTS = 0x0040
EXT4_FEATURE_INCOMPAT_FILETYPE = 0x0002

# Флаги инода
EXT4_EXTENTS_FL = 0x00080000
EXT4_EXTENT_UNWRITTEN = 0x8000

# Типы inode по i_mode
EXT4_S_IFREG = 0o100000
EXT4_S_IFDIR = 0o040000

EXT4_ROOT_INO = 2

# Типы файлов в записях каталогов
_DIR_FILE_TYPES = {
    0: FileType.UNKNOWN,
    1: FileType.REGULAR,
    2: FileType.DIRECTORY,
    3: FileType.CHARDEV,
    4: FileType.BLOCKDEV,
    5: FileType.FIFO,
    6: FileType.SOCKET,
    7: FileType.SYMLINK,
}

_DIR_FILE_TYPE_NAMES = {
    0: "unknown",
    1: "regular",
    2: "directory",
    3: "chardev",
    4: "blockdev",
    5: "fifo",
    6: "socket",
    7: "symlink",
}


class Ext4Parser(FSParser):
    """Парсер ext2/ext3/ext4."""

    def __init__(self, reader: DiskReader, partition_offset: int = 0):
        super().__init__(reader, partition_offset)
        self._sb: Optional[dict] = None  # кэш суперблока

    @staticmethod
    def fs_name() -> str:
        return "ext4"

    # ── Суперблок ──────────────────────────────────────────

    def _read_superblock_raw(self) -> dict:
        """Прочитать и кэшировать ключевые поля суперблока."""
        if self._sb is not None:
            return self._sb

        data = self._read(EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE)
        if len(data) < 264:
            raise ValueError("Невозможно прочитать суперблок ext4: недостаточно данных")

        magic = struct.unpack_from('<H', data, 56)[0]
        if magic != EXT4_SUPER_MAGIC:
            raise ValueError(
                f"Неверная сигнатура суперблока: 0x{magic:04X} "
                f"(ожидалось 0xEF53)"
            )

        sb = {}
        sb['s_inodes_count']        = struct.unpack_from('<I', data, 0)[0]
        sb['s_blocks_count_lo']     = struct.unpack_from('<I', data, 4)[0]
        sb['s_r_blocks_count_lo']   = struct.unpack_from('<I', data, 8)[0]
        sb['s_free_blocks_count_lo'] = struct.unpack_from('<I', data, 12)[0]
        sb['s_free_inodes_count']   = struct.unpack_from('<I', data, 16)[0]
        sb['s_first_data_block']    = struct.unpack_from('<I', data, 20)[0]
        sb['s_log_block_size']      = struct.unpack_from('<I', data, 24)[0]
        sb['s_log_cluster_size']    = struct.unpack_from('<I', data, 28)[0]
        sb['s_blocks_per_group']    = struct.unpack_from('<I', data, 32)[0]
        sb['s_clusters_per_group']  = struct.unpack_from('<I', data, 36)[0]
        sb['s_inodes_per_group']    = struct.unpack_from('<I', data, 40)[0]
        sb['s_mtime']               = struct.unpack_from('<I', data, 44)[0]
        sb['s_wtime']               = struct.unpack_from('<I', data, 48)[0]
        sb['s_mnt_count']           = struct.unpack_from('<H', data, 52)[0]
        sb['s_max_mnt_count']       = struct.unpack_from('<H', data, 54)[0]
        sb['s_magic']               = magic
        sb['s_state']               = struct.unpack_from('<H', data, 58)[0]
        sb['s_errors']              = struct.unpack_from('<H', data, 60)[0]
        sb['s_minor_rev_level']     = struct.unpack_from('<H', data, 62)[0]
        sb['s_lastcheck']           = struct.unpack_from('<I', data, 64)[0]
        sb['s_checkinterval']       = struct.unpack_from('<I', data, 68)[0]
        sb['s_creator_os']          = struct.unpack_from('<I', data, 72)[0]
        sb['s_rev_level']           = struct.unpack_from('<I', data, 76)[0]
        sb['s_def_resuid']          = struct.unpack_from('<H', data, 80)[0]
        sb['s_def_resgid']          = struct.unpack_from('<H', data, 82)[0]
        sb['s_first_ino']           = struct.unpack_from('<I', data, 84)[0]
        sb['s_inode_size']          = struct.unpack_from('<H', data, 88)[0]
        sb['s_block_group_nr']      = struct.unpack_from('<H', data, 90)[0]
        sb['s_feature_compat']      = struct.unpack_from('<I', data, 92)[0]
        sb['s_feature_incompat']    = struct.unpack_from('<I', data, 96)[0]
        sb['s_feature_ro_compat']   = struct.unpack_from('<I', data, 100)[0]
        sb['s_uuid']                = data[104:120]
        sb['s_volume_name']         = data[120:136].rstrip(b'\x00').decode(
                                          'utf-8', errors='replace')
        sb['s_last_mounted']        = data[136:200].rstrip(b'\x00').decode(
                                          'utf-8', errors='replace')
        sb['s_algorithm_usage_bitmap'] = struct.unpack_from('<I', data, 200)[0]
        sb['s_prealloc_blocks']     = data[204]
        sb['s_prealloc_dir_blocks'] = data[205]
        sb['s_reserved_gdt_blocks'] = struct.unpack_from('<H', data, 206)[0]
        sb['s_journal_uuid']        = data[208:224]
        sb['s_journal_inum']        = struct.unpack_from('<I', data, 224)[0]
        sb['s_journal_dev']         = struct.unpack_from('<I', data, 228)[0]
        sb['s_last_orphan']         = struct.unpack_from('<I', data, 232)[0]
        sb['s_hash_seed']           = struct.unpack_from('<4I', data, 236)
        sb['s_def_hash_version']    = data[252]
        sb['s_desc_size']           = struct.unpack_from('<H', data, 254)[0]
        sb['s_default_mount_opts']  = struct.unpack_from('<I', data, 256)[0]
        sb['s_first_meta_bg']       = struct.unpack_from('<I', data, 260)[0]
        sb['s_mkfs_time']           = struct.unpack_from('<I', data, 264)[0]

        # 64-bit поля (ext4)
        if len(data) >= 352:
            sb['s_blocks_count_hi']      = struct.unpack_from('<I', data, 336)[0]
            sb['s_r_blocks_count_hi']    = struct.unpack_from('<I', data, 340)[0]
            sb['s_free_blocks_count_hi'] = struct.unpack_from('<I', data, 344)[0]
            sb['s_min_extra_isize']      = struct.unpack_from('<H', data, 348)[0]
            sb['s_want_extra_isize']     = struct.unpack_from('<H', data, 350)[0]
        else:
            sb['s_blocks_count_hi'] = 0
            sb['s_r_blocks_count_hi'] = 0
            sb['s_free_blocks_count_hi'] = 0
            sb['s_min_extra_isize'] = 0
            sb['s_want_extra_isize'] = 0

        # Вычисленные значения
        sb['block_size'] = 1024 << sb['s_log_block_size']
        sb['blocks_count'] = (
            sb['s_blocks_count_lo'] |
            (sb['s_blocks_count_hi'] << 32)
        )
        sb['free_blocks_count'] = (
            sb['s_free_blocks_count_lo'] |
            (sb['s_free_blocks_count_hi'] << 32)
        )
        sb['is_64bit'] = bool(
            sb['s_feature_incompat'] & EXT4_FEATURE_INCOMPAT_64BIT
        )
        sb['has_filetype'] = bool(
            sb['s_feature_incompat'] & EXT4_FEATURE_INCOMPAT_FILETYPE
        )
        sb['desc_size'] = sb['s_desc_size'] if sb['is_64bit'] and sb['s_desc_size'] >= 64 else 32

        self._sb = sb
        return sb

    def parse_superblock(self) -> ParsedStructure:
        sb = self._read_superblock_raw()
        data = self._read(EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE)
        disk_off = self._partition_offset + EXT4_SUPERBLOCK_OFFSET

        ps = ParsedStructure(
            name="Суперблок ext4",
            disk_offset=disk_off,
            size=EXT4_SUPERBLOCK_SIZE,
        )

        def a(name, off, sz, val, desc=""):
            ps.add(name, off, sz, data[off:off+sz], val, desc)

        a("s_inodes_count",        0,   4, sb['s_inodes_count'],
          "Общее число инодов")
        a("s_blocks_count_lo",     4,   4, sb['s_blocks_count_lo'],
          "Число блоков (младшие 32 бита)")
        a("s_r_blocks_count_lo",   8,   4, sb['s_r_blocks_count_lo'],
          "Зарезервированные блоки")
        a("s_free_blocks_count_lo", 12, 4, sb['s_free_blocks_count_lo'],
          "Свободные блоки (младшие 32 бита)")
        a("s_free_inodes_count",   16,  4, sb['s_free_inodes_count'],
          "Свободные иноды")
        a("s_first_data_block",    20,  4, sb['s_first_data_block'],
          "Первый блок данных")
        a("s_log_block_size",      24,  4, sb['s_log_block_size'],
          f"Логарифм размера блока → {sb['block_size']} байт")
        a("s_blocks_per_group",    32,  4, sb['s_blocks_per_group'],
          "Блоков в группе")
        a("s_inodes_per_group",    40,  4, sb['s_inodes_per_group'],
          "Инодов в группе")
        a("s_mtime",               44,  4,
          str(ts_to_datetime(sb['s_mtime']) or "—"),
          "Время последнего монтирования")
        a("s_wtime",               48,  4,
          str(ts_to_datetime(sb['s_wtime']) or "—"),
          "Время последней записи")
        a("s_mnt_count",           52,  2, sb['s_mnt_count'],
          "Число монтирований")
        a("s_magic",               56,  2, f"0x{sb['s_magic']:04X}",
          "Сигнатура")
        a("s_state",               58,  2, sb['s_state'],
          "Состояние ФС (1=clean, 2=errors)")
        a("s_inode_size",          88,  2, sb['s_inode_size'],
          "Размер инода в байтах")
        a("s_feature_compat",      92,  4, f"0x{sb['s_feature_compat']:08X}",
          "Флаги совместимости")
        a("s_feature_incompat",    96,  4, f"0x{sb['s_feature_incompat']:08X}",
          "Флаги несовместимости")
        a("s_feature_ro_compat",  100,  4, f"0x{sb['s_feature_ro_compat']:08X}",
          "Флаги RO-совместимости")
        a("s_uuid",               104, 16,
          str(_uuid.UUID(bytes=sb['s_uuid'])),
          "UUID файловой системы")
        a("s_volume_name",        120, 16, sb['s_volume_name'],
          "Метка тома")
        a("s_last_mounted",       136, 64, sb['s_last_mounted'],
          "Точка последнего монтирования")
        a("s_desc_size",          254,  2, sb['s_desc_size'],
          "Размер дескриптора группы")
        a("s_mkfs_time",          264,  4,
          str(ts_to_datetime(sb['s_mkfs_time']) or "—"),
          "Время создания ФС")

        # Вычисленные поля
        ps.add("block_size (вычислено)",  -1, 0, b'',
               f"{sb['block_size']} байт",
               "1024 << s_log_block_size")
        ps.add("blocks_count (вычислено)", -1, 0, b'',
               f"{sb['blocks_count']} ({format_size(sb['blocks_count'] * sb['block_size'])})",
               "Полное число блоков (lo + hi)")
        ps.add("64-bit режим",            -1, 0, b'',
               "Да" if sb['is_64bit'] else "Нет",
               "EXT4_FEATURE_INCOMPAT_64BIT")

        return ps

    # ── Группы блоков ──────────────────────────────────────

    def get_block_group_count(self) -> int:
        sb = self._read_superblock_raw()
        return ((sb['blocks_count'] - sb['s_first_data_block']
                 + sb['s_blocks_per_group'] - 1)
                // sb['s_blocks_per_group'])

    def _gdt_offset(self) -> int:
        """Смещение таблицы дескрипторов групп блоков."""
        sb = self._read_superblock_raw()
        # GDT начинается в блоке, следующем за суперблоком
        block_size = sb['block_size']
        if block_size == 1024:
            return 2 * block_size  # блок 2
        else:
            return block_size  # блок 1

    def get_block_group_info(self, group_index: int) -> ParsedStructure:
        sb = self._read_superblock_raw()
        desc_size = sb['desc_size']
        gdt_off = self._gdt_offset()
        offset = gdt_off + group_index * desc_size
        data = self._read(offset, desc_size)
        disk_off = self._partition_offset + offset

        ps = ParsedStructure(
            name=f"Дескриптор группы блоков #{group_index}",
            disk_offset=disk_off,
            size=desc_size,
        )

        bg_block_bitmap_lo  = struct.unpack_from('<I', data, 0)[0]
        bg_inode_bitmap_lo  = struct.unpack_from('<I', data, 4)[0]
        bg_inode_table_lo   = struct.unpack_from('<I', data, 8)[0]
        bg_free_blocks      = struct.unpack_from('<H', data, 12)[0]
        bg_free_inodes      = struct.unpack_from('<H', data, 14)[0]
        bg_used_dirs        = struct.unpack_from('<H', data, 16)[0]
        bg_flags            = struct.unpack_from('<H', data, 18)[0]
        bg_itable_unused    = struct.unpack_from('<H', data, 28)[0]
        bg_checksum         = struct.unpack_from('<H', data, 30)[0]

        ps.add("bg_block_bitmap_lo",  0, 4, data[0:4],   bg_block_bitmap_lo,
               "Блок с битовой картой блоков")
        ps.add("bg_inode_bitmap_lo",  4, 4, data[4:8],   bg_inode_bitmap_lo,
               "Блок с битовой картой инодов")
        ps.add("bg_inode_table_lo",   8, 4, data[8:12],  bg_inode_table_lo,
               "Начальный блок таблицы инодов")
        ps.add("bg_free_blocks_count", 12, 2, data[12:14], bg_free_blocks,
               "Свободных блоков в группе")
        ps.add("bg_free_inodes_count", 14, 2, data[14:16], bg_free_inodes,
               "Свободных инодов в группе")
        ps.add("bg_used_dirs_count",  16, 2, data[16:18], bg_used_dirs,
               "Каталогов в группе")
        ps.add("bg_flags",           18, 2, data[18:20], f"0x{bg_flags:04X}",
               "Флаги группы")
        ps.add("bg_itable_unused",   28, 2, data[28:30], bg_itable_unused,
               "Неиспользуемых инодов в таблице")
        ps.add("bg_checksum",        30, 2, data[30:32], f"0x{bg_checksum:04X}",
               "Контрольная сумма")

        if desc_size >= 64:
            bg_block_bitmap_hi = struct.unpack_from('<I', data, 32)[0]
            bg_inode_bitmap_hi = struct.unpack_from('<I', data, 36)[0]
            bg_inode_table_hi  = struct.unpack_from('<I', data, 40)[0]
            ps.add("bg_block_bitmap_hi", 32, 4, data[32:36],
                   bg_block_bitmap_hi, "Битовая карта блоков (старшие)")
            ps.add("bg_inode_bitmap_hi", 36, 4, data[36:40],
                   bg_inode_bitmap_hi, "Битовая карта инодов (старшие)")
            ps.add("bg_inode_table_hi",  40, 4, data[40:44],
                   bg_inode_table_hi, "Таблица инодов (старшие)")

        return ps

    def _inode_table_block(self, group_index: int) -> int:
        """Номер блока начала таблицы инодов в группе."""
        sb = self._read_superblock_raw()
        desc_size = sb['desc_size']
        gdt_off = self._gdt_offset()
        offset = gdt_off + group_index * desc_size
        data = self._read(offset, desc_size)

        lo = struct.unpack_from('<I', data, 8)[0]
        if desc_size >= 64:
            hi = struct.unpack_from('<I', data, 40)[0]
            return lo | (hi << 32)
        return lo

    # ── Иноды ──────────────────────────────────────────────

    def _inode_offset(self, inode_number: int) -> int:
        """Вычислить абсолютное смещение инода на диске."""
        sb = self._read_superblock_raw()
        group = (inode_number - 1) // sb['s_inodes_per_group']
        index = (inode_number - 1) % sb['s_inodes_per_group']
        table_block = self._inode_table_block(group)
        return table_block * sb['block_size'] + index * sb['s_inode_size']

    def _parse_inode_data(self, data: bytes, inode_number: int,
                          disk_offset: int) -> tuple[dict, ParsedStructure]:
        """Разобрать сырые байты инода."""
        sb = self._read_superblock_raw()
        inode_size = sb['s_inode_size']

        i_mode       = struct.unpack_from('<H', data, 0)[0]
        i_uid        = struct.unpack_from('<H', data, 2)[0]
        i_size_lo    = struct.unpack_from('<I', data, 4)[0]
        i_atime      = struct.unpack_from('<I', data, 8)[0]
        i_ctime      = struct.unpack_from('<I', data, 12)[0]
        i_mtime      = struct.unpack_from('<I', data, 16)[0]
        i_dtime      = struct.unpack_from('<I', data, 20)[0]
        i_gid        = struct.unpack_from('<H', data, 24)[0]
        i_links      = struct.unpack_from('<H', data, 26)[0]
        i_blocks_lo  = struct.unpack_from('<I', data, 28)[0]
        i_flags      = struct.unpack_from('<I', data, 32)[0]
        i_block      = data[40:100]
        i_generation = struct.unpack_from('<I', data, 100)[0]
        i_file_acl   = struct.unpack_from('<I', data, 104)[0]
        i_size_hi    = struct.unpack_from('<I', data, 108)[0]
        i_crtime = None
        i_crtime_extra = None
        if inode_size >= 160 and len(data) >= 160:
            i_crtime = struct.unpack_from('<I', data, 144)[0]
            i_crtime_extra = struct.unpack_from('<I', data, 148)[0]

        size = i_size_lo | (i_size_hi << 32)

        # Определение типа файла по i_mode
        mode_type = i_mode & 0o170000
        ft_map = {
            0o100000: FileType.REGULAR,
            0o040000: FileType.DIRECTORY,
            0o120000: FileType.SYMLINK,
            0o020000: FileType.CHARDEV,
            0o060000: FileType.BLOCKDEV,
            0o010000: FileType.FIFO,
            0o140000: FileType.SOCKET,
        }
        file_type = ft_map.get(mode_type, FileType.UNKNOWN)

        raw = {
            'i_mode': i_mode,
            'i_uid': i_uid,
            'i_size': size,
            'i_atime': i_atime,
            'i_ctime': i_ctime,
            'i_mtime': i_mtime,
            'i_dtime': i_dtime,
            'i_gid': i_gid,
            'i_links_count': i_links,
            'i_blocks_lo': i_blocks_lo,
            'i_flags': i_flags,
            'i_block': i_block,
            'i_generation': i_generation,
            'i_file_acl_lo': i_file_acl,
            'i_crtime': i_crtime,
            'i_crtime_extra': i_crtime_extra,
            'file_type': file_type,
            'uses_extents': bool(i_flags & EXT4_EXTENTS_FL),
        }

        ps = ParsedStructure(
            name=f"Инод #{inode_number}",
            disk_offset=disk_offset,
            size=inode_size,
        )

        ps.add("i_mode",       0,  2, data[0:2],
               f"0o{i_mode:06o} ({format_mode(i_mode)})",
               "Тип и права доступа")
        ps.add("i_uid",        2,  2, data[2:4],   i_uid, "UID владельца")
        ps.add("i_size_lo",    4,  4, data[4:8],
               f"{size} ({format_size(size)})",
               "Размер файла")
        ps.add("i_atime",      8,  4, data[8:12],
               str(ts_to_datetime(i_atime) or "—"),
               "Время последнего доступа")
        ps.add("i_ctime",     12,  4, data[12:16],
               str(ts_to_datetime(i_ctime) or "—"),
               "Время изменения метаданных")
        ps.add("i_mtime",     16,  4, data[16:20],
               str(ts_to_datetime(i_mtime) or "—"),
               "Время изменения данных")
        ps.add("i_dtime",     20,  4, data[20:24],
               str(ts_to_datetime(i_dtime) or "—"),
               "Время удаления")
        ps.add("i_gid",       24,  2, data[24:26], i_gid, "GID владельца")
        ps.add("i_links_count", 26, 2, data[26:28], i_links,
               "Число жёстких ссылок")
        ps.add("i_blocks_lo", 28,  4, data[28:32], i_blocks_lo,
               "Число 512-байтных секторов")
        ps.add("i_flags",     32,  4, data[32:36],
               f"0x{i_flags:08X}",
               "Флаги инода" +
               (" [EXTENTS]" if raw['uses_extents'] else ""))
        ps.add("i_block",     40, 60, i_block,
               "extents" if raw['uses_extents'] else "block pointers",
               "Указатели на данные / дерево экстентов")
        if i_crtime is not None:
            ps.add("i_crtime", 144, 4, data[144:148],
                   str(ts_to_datetime(i_crtime) or "—"),
                   "Время создания (ext4 crtime)")
            ps.add("i_crtime_extra", 148, 4, data[148:152],
                   f"0x{i_crtime_extra:08X}",
                   "Дополнительные биты времени создания")

        if raw['uses_extents'] and len(i_block) >= 12:
            eh_magic = struct.unpack_from('<H', i_block, 0)[0]
            eh_entries = struct.unpack_from('<H', i_block, 2)[0]
            eh_max = struct.unpack_from('<H', i_block, 4)[0]
            eh_depth = struct.unpack_from('<H', i_block, 6)[0]
            ps.add("  eh_magic",   40, 2, i_block[0:2],
                   f"0x{eh_magic:04X}", "Сигнатура дерева экстентов")
            ps.add("  eh_entries", 42, 2, i_block[2:4],
                   eh_entries, "Число записей")
            ps.add("  eh_max",    44, 2, i_block[4:6],
                   eh_max, "Макс. записей")
            ps.add("  eh_depth",  46, 2, i_block[6:8],
                   eh_depth, "Глубина дерева")

            if eh_depth == 0:
                for ei in range(min(eh_entries, 4)):
                    eoff = 12 + ei * 12
                    if eoff + 12 > len(i_block):
                        break
                    ee_block = struct.unpack_from('<I', i_block, eoff)[0]
                    ee_len   = struct.unpack_from('<H', i_block, eoff + 4)[0]
                    ee_hi    = struct.unpack_from('<H', i_block, eoff + 6)[0]
                    ee_lo    = struct.unpack_from('<I', i_block, eoff + 8)[0]
                    phys = ee_lo | (ee_hi << 32)
                    ps.add(f"  extent[{ei}]", 40 + eoff, 12,
                           i_block[eoff:eoff+12],
                           f"logical={ee_block} len={ee_len} phys={phys}",
                           f"Экстент: логич. блок {ee_block}, "
                           f"длина {ee_len}, физ. блок {phys}")

        return raw, ps

    def get_inode(self, inode_number: int) -> ParsedStructure:
        sb = self._read_superblock_raw()
        offset = self._inode_offset(inode_number)
        data = self._read(offset, sb['s_inode_size'])
        disk_off = self._partition_offset + offset
        _, ps = self._parse_inode_data(data, inode_number, disk_off)
        return ps

    def get_inode_meta(self, inode_number: int) -> InodeMeta:
        sb = self._read_superblock_raw()
        offset = self._inode_offset(inode_number)
        data = self._read(offset, sb['s_inode_size'])
        raw, _ = self._parse_inode_data(data, inode_number,
                                        self._partition_offset + offset)

        mode_type = raw['i_mode'] & 0o170000
        ft_map = {
            0o100000: FileType.REGULAR,
            0o040000: FileType.DIRECTORY,
            0o120000: FileType.SYMLINK,
        }

        return InodeMeta(
            number=inode_number,
            mode=raw['i_mode'],
            uid=raw['i_uid'],
            gid=raw['i_gid'],
            size=raw['i_size'],
            links=raw['i_links_count'],
            atime=ts_to_datetime(raw['i_atime']),
            mtime=ts_to_datetime(raw['i_mtime']),
            ctime=ts_to_datetime(raw['i_ctime']),
            flags=raw['i_flags'],
            file_type=raw['file_type'],
            disk_offset=self._partition_offset + offset,
        )

    def _read_inode_raw(self, inode_number: int) -> tuple[dict, ParsedStructure]:
        sb = self._read_superblock_raw()
        offset = self._inode_offset(inode_number)
        data = self._read(offset, sb['s_inode_size'])
        return self._parse_inode_data(
            data,
            inode_number,
            self._partition_offset + offset,
        )

    @staticmethod
    def _timestamp_value(raw: dict, name: str) -> str | None:
        value = raw.get(name)
        if not value:
            return None
        dt = ts_to_datetime(value)
        return dt.isoformat(sep=" ") if dt else None

    def _file_extents(self, raw: dict) -> tuple[list[dict], list[str]]:
        """Вернуть карту данных файла в порядке logical block index."""
        sb = self._read_superblock_raw()
        block_size = sb['block_size']
        i_block = raw['i_block']
        warnings: list[str] = []
        extents: list[dict] = []

        def parse_extent_node(node: bytes, base_offset: int = 0) -> None:
            if len(node) < 12:
                warnings.append("extent node is shorter than header")
                return
            eh_magic = struct.unpack_from('<H', node, 0)[0]
            if eh_magic != 0xF30A:
                warnings.append(f"invalid extent header magic 0x{eh_magic:04X}")
                return
            eh_entries = struct.unpack_from('<H', node, 2)[0]
            eh_depth = struct.unpack_from('<H', node, 6)[0]
            for index in range(eh_entries):
                eoff = 12 + index * 12
                if eoff + 12 > len(node):
                    warnings.append("extent entry exceeds node size")
                    break
                if eh_depth == 0:
                    ee_block = struct.unpack_from('<I', node, eoff)[0]
                    ee_len_raw = struct.unpack_from('<H', node, eoff + 4)[0]
                    ee_hi = struct.unpack_from('<H', node, eoff + 6)[0]
                    ee_lo = struct.unpack_from('<I', node, eoff + 8)[0]
                    length = ee_len_raw & ~EXT4_EXTENT_UNWRITTEN
                    uninitialized = bool(ee_len_raw & EXT4_EXTENT_UNWRITTEN)
                    physical = ee_lo | (ee_hi << 32)
                    if length == 0 or physical == 0:
                        continue
                    extents.append({
                        "logical": ee_block,
                        "physical": physical,
                        "length": length,
                        "uninitialized": uninitialized,
                        "blockStart": self._partition_offset + physical * block_size,
                    })
                    if uninitialized:
                        warnings.append(
                            f"extent logical={ee_block} physical={physical} is uninitialized"
                        )
                else:
                    ei_lo = struct.unpack_from('<I', node, eoff + 4)[0]
                    ei_hi = struct.unpack_from('<H', node, eoff + 8)[0]
                    child_block = ei_lo | (ei_hi << 32)
                    if child_block == 0:
                        continue
                    try:
                        child = self._read(child_block * block_size, block_size)
                        parse_extent_node(child, child_block * block_size)
                    except Exception as exc:
                        warnings.append(
                            f"failed to read extent node at block {child_block}: {exc}"
                        )

        if raw['i_flags'] & EXT4_EXTENTS_FL:
            parse_extent_node(i_block)
        else:
            for logical in range(12):
                physical = struct.unpack_from('<I', i_block, logical * 4)[0]
                if physical:
                    extents.append({
                        "logical": logical,
                        "physical": physical,
                        "length": 1,
                        "uninitialized": False,
                        "blockStart": self._partition_offset + physical * block_size,
                    })

            indirect = struct.unpack_from('<I', i_block, 48)[0]
            if indirect:
                indirect_blocks: list[int] = []
                try:
                    self._read_indirect(indirect, block_size, indirect_blocks, 1)
                except Exception as exc:
                    warnings.append(f"failed to read indirect block {indirect}: {exc}")
                for offset, physical in enumerate(indirect_blocks):
                    extents.append({
                        "logical": 12 + offset,
                        "physical": physical,
                        "length": 1,
                        "uninitialized": False,
                        "blockStart": self._partition_offset + physical * block_size,
                    })

        extents.sort(key=lambda item: int(item["logical"]))
        return extents, warnings

    def _is_deleted_regular_candidate(self, raw: dict, extents: list[dict]) -> bool:
        return (
            (raw['i_mode'] & 0o170000) == EXT4_S_IFREG
            and raw['i_size'] > 0
            and (raw['i_dtime'] != 0 or raw['i_links_count'] == 0)
            and len(extents) > 0
        )

    def _deleted_file_record(self, inode_number: int, raw: dict,
                             extents: list[dict], warnings: list[str]) -> dict:
        block_size = self._read_superblock_raw()['block_size']
        block_count = sum(int(extent["length"]) for extent in extents)
        recoverable_bytes = min(raw['i_size'], block_count * block_size)
        if recoverable_bytes < raw['i_size']:
            warnings = [*warnings, "mapped blocks cover fewer bytes than i_size"]
        if any(extent.get("uninitialized") for extent in extents):
            warnings = [*warnings, "contains uninitialized extent; recovery may contain zero/stale data"]

        confidence = "high" if raw['i_dtime'] and raw['i_links_count'] == 0 else "medium"
        summary = ", ".join(
            f"L{extent['logical']}→B{extent['physical']}×{extent['length']}"
            for extent in extents[:4]
        )
        if len(extents) > 4:
            summary += f", +{len(extents) - 4} extents"

        return {
            "inode": inode_number,
            "filename": "unknown",
            "size": raw['i_size'],
            "sizeHuman": format_size(raw['i_size']),
            "mode": f"0o{raw['i_mode']:06o} ({format_mode(raw['i_mode'])})",
            "uid": raw['i_uid'],
            "gid": raw['i_gid'],
            "links": raw['i_links_count'],
            "atime": self._timestamp_value(raw, 'i_atime'),
            "ctime": self._timestamp_value(raw, 'i_ctime'),
            "mtime": self._timestamp_value(raw, 'i_mtime'),
            "dtime": self._timestamp_value(raw, 'i_dtime'),
            "crtime": self._timestamp_value(raw, 'i_crtime'),
            "deleted": True,
            "confidence": confidence,
            "blockCount": block_count,
            "firstBlock": extents[0]["physical"] if extents else None,
            "extentSummary": summary or "no mapped blocks",
            "recoverableBytes": recoverable_bytes,
            "recoverability": "full" if recoverable_bytes >= raw['i_size'] else "partial",
            "warnings": warnings,
            "extents": extents,
        }

    def scan_deleted_files(self, limit: int = 100, cursor: int = 1,
                           min_size: int = 1, name_hint: str | None = None) -> dict:
        """Сканировать таблицу inode и найти удалённые regular files."""
        inode_count = int(self.get_inode_count())
        limit = max(1, min(int(limit), 500))
        start_inode = max(1, int(cursor or 1))
        min_size = max(0, int(min_size or 0))
        results: list[dict] = []
        scanned = 0
        inode = start_inode

        while inode <= inode_count and len(results) < limit:
            scanned += 1
            try:
                raw, _ = self._read_inode_raw(inode)
                if raw['i_size'] < min_size:
                    inode += 1
                    continue
                extents, warnings = self._file_extents(raw)
                if not self._is_deleted_regular_candidate(raw, extents):
                    inode += 1
                    continue
                # v1 does not prove deleted filenames. Keep name_hint as a no-op
                # API placeholder so later directory slack/journal analysis can use it.
                results.append(self._deleted_file_record(inode, raw, extents, warnings))
            except Exception:
                pass
            inode += 1

        return {
            "items": results,
            "cursor": start_inode,
            "nextCursor": inode if inode <= inode_count else None,
            "scanned": scanned,
            "totalInodes": inode_count,
            "truncated": inode <= inode_count,
            "nameHintApplied": False,
        }

    def get_deleted_file(self, inode_number: int) -> dict:
        raw, _ = self._read_inode_raw(inode_number)
        extents, warnings = self._file_extents(raw)
        if not self._is_deleted_regular_candidate(raw, extents):
            raise ValueError(f"Инод #{inode_number} не похож на восстановимый удалённый regular file")
        return self._deleted_file_record(inode_number, raw, extents, warnings)

    def recover_file(self, inode_number: int, max_bytes: int | None = None) -> dict:
        record = self.get_deleted_file(inode_number)
        block_size = self._read_superblock_raw()['block_size']
        target_size = int(record["size"])
        if max_bytes is not None:
            target_size = min(target_size, max(0, int(max_bytes)))

        recovered = bytearray()
        warnings = list(record["warnings"])
        for extent in record["extents"]:
            if len(recovered) >= target_size:
                break
            if extent.get("uninitialized"):
                warnings.append(
                    f"skipped uninitialized extent at physical block {extent['physical']}"
                )
                continue
            for block_index in range(int(extent["length"])):
                if len(recovered) >= target_size:
                    break
                physical = int(extent["physical"]) + block_index
                remaining = target_size - len(recovered)
                try:
                    chunk = self._read(physical * block_size, min(block_size, remaining))
                    recovered.extend(chunk)
                    if len(chunk) < min(block_size, remaining):
                        warnings.append(f"short read at physical block {physical}")
                        break
                except Exception as exc:
                    warnings.append(f"failed to read physical block {physical}: {exc}")
                    break

        return {
            "inode": inode_number,
            "filename": f"recovered_inode_{inode_number}.bin",
            "data": bytes(recovered[:target_size]),
            "expectedSize": int(record["size"]),
            "recoveredBytes": min(len(recovered), target_size),
            "warnings": warnings,
            "record": record,
        }

    def read_file_preview(self, inode_number: int, length: int = 4096) -> dict:
        recovery = self.recover_file(inode_number, max_bytes=max(1, int(length)))
        data = recovery["data"]
        return {
            "inode": inode_number,
            "length": len(data),
            "hex": data.hex(" "),
            "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data),
            "warnings": recovery["warnings"],
        }

    @staticmethod
    def _looks_like_dir_name(name: bytes) -> bool:
        if not name or b"\x00" in name or b"/" in name:
            return False
        try:
            text = name.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if text in (".", ".."):
            return True
        printable = sum(1 for char in text if char.isprintable())
        return printable == len(text)

    def _parse_dirent_candidate(self, block: bytes, offset: int) -> dict | None:
        sb = self._read_superblock_raw()
        if offset + 8 > len(block):
            return None
        inode = struct.unpack_from('<I', block, offset)[0]
        rec_len = struct.unpack_from('<H', block, offset + 4)[0]
        name_len = block[offset + 6]
        file_type = block[offset + 7] if sb['has_filetype'] else 0
        min_rec_len = 8 + ((name_len + 3) & ~3)

        if inode < 1 or inode > sb['s_inodes_count']:
            return None
        if rec_len < min_rec_len or rec_len % 4 != 0:
            return None
        if offset + rec_len > len(block):
            return None
        if file_type not in _DIR_FILE_TYPES:
            return None
        name_bytes = block[offset + 8:offset + 8 + name_len]
        if not self._looks_like_dir_name(name_bytes):
            return None
        name = name_bytes.decode("utf-8", errors="replace")
        return {
            "inode": inode,
            "recordLength": rec_len,
            "nameLength": name_len,
            "fileType": _DIR_FILE_TYPE_NAMES.get(file_type, "unknown"),
            "name": name,
        }

    def _inode_artifact_state(self, inode_number: int) -> dict:
        try:
            raw, _ = self._read_inode_raw(inode_number)
            extents, warnings = self._file_extents(raw)
        except Exception as exc:
            return {
                "state": "unreadable",
                "mode": None,
                "size": 0,
                "links": 0,
                "dtime": None,
                "crtime": None,
                "mtime": None,
                "recoverable": False,
                "warnings": [str(exc)],
            }

        mode_type = raw['i_mode'] & 0o170000
        if raw['i_mode'] == 0:
            state = "wiped"
        elif raw['i_dtime'] or raw['i_links_count'] == 0:
            state = "deleted"
        else:
            state = "active"

        recoverable = (
            mode_type == EXT4_S_IFREG
            and raw['i_size'] > 0
            and len(extents) > 0
        )
        return {
            "state": state,
            "mode": f"0o{raw['i_mode']:06o} ({format_mode(raw['i_mode'])})",
            "size": raw['i_size'],
            "sizeHuman": format_size(raw['i_size']),
            "links": raw['i_links_count'],
            "dtime": self._timestamp_value(raw, 'i_dtime'),
            "crtime": self._timestamp_value(raw, 'i_crtime'),
            "mtime": self._timestamp_value(raw, 'i_mtime'),
            "recoverable": recoverable,
            "extentCount": len(extents),
            "warnings": warnings,
        }

    def scan_directory_inode_artifacts(self, limit: int = 100,
                                       name_hint: str | None = None,
                                       cancel_check=None) -> dict:
        """
        Быстрый поиск имён по активным directory inode.

        В отличие от raw block scan, читает только блоки каталогов, найденные
        через inode table. Это не видит все варианты directory slack, зато
        достаточно быстро даёт path hints для обычного forensic search.
        """
        sb = self._read_superblock_raw()
        block_size = sb['block_size']
        inode_size = sb['s_inode_size']
        inodes_per_group = sb['s_inodes_per_group']
        inode_count = int(self.get_inode_count())
        hint = (name_hint or "").strip().lower()
        limit = max(1, min(int(limit), 500))
        results: list[dict] = []
        seen: set[tuple[int, int, str]] = set()
        scanned_inodes = 0
        scanned_blocks = 0

        group_count = self.get_block_group_count()
        for group_index in range(group_count):
            try:
                table_block = self._inode_table_block(group_index)
                first_inode = group_index * inodes_per_group + 1
                group_inode_count = min(inodes_per_group, inode_count - first_inode + 1)
                if group_inode_count <= 0:
                    break
                table = self._read(table_block * block_size, group_inode_count * inode_size)
            except Exception:
                continue
            for group_offset in range(group_inode_count):
                inode_number = first_inode + group_offset
                scanned_inodes += 1
                if cancel_check is not None and inode_number % 4096 == 0:
                    cancel_check()
                if len(results) >= limit:
                    break
                start = group_offset * inode_size
                inode_data = table[start:start + inode_size]
                if len(inode_data) < 100:
                    continue
                i_mode = struct.unpack_from('<H', inode_data, 0)[0]
                if (i_mode & 0o170000) != EXT4_S_IFDIR:
                    continue
                i_flags = struct.unpack_from('<I', inode_data, 32)[0]
                raw = {
                    "i_mode": i_mode,
                    "i_flags": i_flags,
                    "i_block": inode_data[40:100],
                }
                extents, _warnings = self._file_extents(raw)
                for extent in extents:
                    if len(results) >= limit:
                        break
                    for block_delta in range(int(extent["length"])):
                        if len(results) >= limit:
                            break
                        if cancel_check is not None and scanned_blocks % 128 == 0:
                            cancel_check()
                        block_number = int(extent["physical"]) + block_delta
                        try:
                            block = self._read(block_number * block_size, block_size)
                        except Exception:
                            continue
                        scanned_blocks += 1
                        if not block or not block.strip(b"\x00"):
                            continue
                        dot = self._parse_dirent_candidate(block, 0)
                        dotdot = self._parse_dirent_candidate(block, 12) if dot and dot.get("name") == "." else None
                        container_inode = dot["inode"] if dot and dot.get("name") == "." else inode_number
                        parent_inode = dotdot["inode"] if dotdot and dotdot.get("name") == ".." else None
                        for pos in range(0, block_size - 8, 4):
                            entry = self._parse_dirent_candidate(block, pos)
                            if entry is None or entry["name"] in (".", ".."):
                                continue
                            if hint and hint not in entry["name"].lower():
                                continue
                            key = (block_number, pos, entry["name"])
                            if key in seen:
                                continue
                            seen.add(key)
                            absolute = self._partition_offset + block_number * block_size + pos
                            results.append({
                                "name": entry["name"],
                                "inode": entry["inode"],
                                "fileType": entry["fileType"],
                                "recordLength": entry["recordLength"],
                                "nameLength": entry["nameLength"],
                                "diskOffset": absolute,
                                "block": block_number,
                                "blockOffset": pos,
                                "containerInode": container_inode,
                                "parentInode": parent_inode,
                                "sourceInode": inode_number,
                                "inodeState": self._inode_artifact_state(int(entry["inode"])),
                                "evidence": "directory_inode_entry",
                                "confidence": "high",
                            })
                            if len(results) >= limit:
                                break
            if len(results) >= limit:
                break

        by_inode = {
            item["inode"]: item
            for item in results
            if item["fileType"] == "directory"
        }
        for item in results:
            parent = by_inode.get(item.get("containerInode"))
            if parent and item["name"] != parent["name"]:
                item["pathHint"] = f"{parent['name']}/{item['name']}"
            else:
                item["pathHint"] = item["name"]

        return {
            "items": results,
            "cursorBlock": 0,
            "nextCursorBlock": None,
            "scannedBlocks": scanned_blocks,
            "scannedInodes": scanned_inodes,
            "totalBlocks": int(sb['blocks_count']),
            "truncated": len(results) >= limit,
            "nameHint": name_hint or "",
        }

    def scan_directory_artifacts(self, limit: int = 100, cursor_block: int = 0,
                                 name_hint: str | None = None,
                                 max_blocks: int | None = None,
                                 block_numbers: list[int] | None = None,
                                 cancel_check=None) -> dict:
        """
        Найти старые ext4 directory entries в raw directory blocks.

        Это не доказывает полный путь и не восстанавливает содержимое само по себе.
        Зато позволяет обнаружить имена вроде deleted secret.txt, даже когда inode
        уже wiped и не попадает в deleted inode recovery.
        """
        sb = self._read_superblock_raw()
        block_size = sb['block_size']
        total_blocks = min(
            int(sb['blocks_count']),
            max(0, (self._reader.size - self._partition_offset) // block_size),
        )
        start = max(0, int(cursor_block or 0))
        limit = max(1, min(int(limit), 500))
        hint = (name_hint or "").strip().lower()
        candidate_blocks = None
        if block_numbers is not None:
            candidate_blocks = [
                block for block in dict.fromkeys(int(block) for block in block_numbers)
                if 0 <= block < total_blocks
            ]
        max_to_scan = max_blocks if max_blocks is not None else total_blocks - start
        max_to_scan = max(0, int(max_to_scan))

        results: list[dict] = []
        scanned = 0
        seen: set[tuple[int, int, str]] = set()
        cursor = start
        block_iter = candidate_blocks if candidate_blocks is not None else None

        while (
            ((block_iter is not None and scanned < len(block_iter))
             or (block_iter is None and cursor < total_blocks and scanned < max_to_scan))
            and len(results) < limit
        ):
            if cancel_check is not None and scanned % 512 == 0:
                cancel_check()
            block_number = block_iter[scanned] if block_iter is not None else cursor
            try:
                block = self._read(block_number * block_size, block_size)
            except Exception:
                cursor += 1
                scanned += 1
                continue

            if block and block.strip(b"\x00"):
                dot = self._parse_dirent_candidate(block, 0)
                dotdot = self._parse_dirent_candidate(block, 12) if dot and dot.get("name") == "." else None
                container_inode = dot["inode"] if dot and dot.get("name") == "." else None
                parent_inode = dotdot["inode"] if dotdot and dotdot.get("name") == ".." else None
                block_has_dir_shape = bool(container_inode and parent_inode)

                for pos in range(0, block_size - 8, 4):
                    entry = self._parse_dirent_candidate(block, pos)
                    if entry is None or entry["name"] in (".", ".."):
                        continue
                    if hint and hint not in entry["name"].lower():
                        continue
                    state = self._inode_artifact_state(int(entry["inode"]))
                    if not hint and state["state"] == "active":
                        continue
                    if not block_has_dir_shape and not hint:
                        continue
                    key = (block_number, pos, entry["name"])
                    if key in seen:
                        continue
                    seen.add(key)
                    absolute = self._partition_offset + block_number * block_size + pos
                    results.append({
                        "name": entry["name"],
                        "inode": entry["inode"],
                        "fileType": entry["fileType"],
                        "recordLength": entry["recordLength"],
                        "nameLength": entry["nameLength"],
                        "diskOffset": absolute,
                        "block": block_number,
                        "blockOffset": pos,
                        "containerInode": container_inode,
                        "parentInode": parent_inode,
                        "inodeState": state,
                        "evidence": "directory_entry",
                        "confidence": "high" if block_has_dir_shape else "medium",
                    })
                    if len(results) >= limit:
                        break

            cursor = block_number + 1 if block_iter is not None else cursor + 1
            scanned += 1

        by_inode = {
            item["inode"]: item
            for item in results
            if item["fileType"] == "directory"
        }
        for item in results:
            parent = by_inode.get(item.get("containerInode"))
            if parent and item["name"] != parent["name"]:
                item["pathHint"] = f"{parent['name']}/{item['name']}"
            else:
                item["pathHint"] = item["name"]

        return {
            "items": results,
            "cursorBlock": start,
            "nextCursorBlock": None if block_iter is not None else (cursor if cursor < total_blocks else None),
            "scannedBlocks": scanned,
            "totalBlocks": total_blocks,
            "truncated": False if block_iter is not None else cursor < total_blocks,
            "nameHint": name_hint or "",
        }

    # ── Каталоги ───────────────────────────────────────────

    def _get_data_blocks(self, inode_number: int) -> list[int]:
        """
        Получить список физических номеров блоков данных инода.

        Поддерживает экстенты (ext4) и прямые указатели (ext2/ext3).
        """
        blocks = []
        raw, _ = self._read_inode_raw(inode_number)
        extents, _ = self._file_extents(raw)
        for extent in extents:
            for offset in range(int(extent["length"])):
                blocks.append(int(extent["physical"]) + offset)
        return blocks

    def _walk_extent_tree(self, header_data: bytes, block_size: int,
                          blocks: list[int], depth: int) -> None:
        """Рекурсивный обход дерева экстентов."""
        if len(header_data) < 12:
            return

        eh_entries = struct.unpack_from('<H', header_data, 2)[0]
        eh_depth = struct.unpack_from('<H', header_data, 6)[0]

        for i in range(eh_entries):
            eoff = 12 + i * 12
            if eoff + 12 > len(header_data):
                break

            if eh_depth == 0:
                # Лист — экстент
                ee_block = struct.unpack_from('<I', header_data, eoff)[0]
                ee_len = struct.unpack_from('<H', header_data, eoff + 4)[0]
                ee_hi = struct.unpack_from('<H', header_data, eoff + 6)[0]
                ee_lo = struct.unpack_from('<I', header_data, eoff + 8)[0]
                phys = ee_lo | (ee_hi << 32)
                # ee_len > 32768 означает неинициализированный экстент
                actual_len = ee_len if ee_len <= 32768 else ee_len - 32768
                for b in range(actual_len):
                    blocks.append(phys + b)
            else:
                # Индексный узел
                ei_lo = struct.unpack_from('<I', header_data, eoff + 4)[0]
                ei_hi = struct.unpack_from('<H', header_data, eoff + 8)[0]
                child_block = ei_lo | (ei_hi << 32)
                child_data = self._read(child_block * block_size, block_size)
                self._walk_extent_tree(child_data, block_size, blocks,
                                       depth + 1)

    def _read_indirect(self, block_num: int, block_size: int,
                       blocks: list[int], level: int) -> None:
        """Чтение косвенных блоков (level: 1, 2, 3)."""
        if level > 3 or block_num == 0:
            return
        data = self._read(block_num * block_size, block_size)
        entries = block_size // 4
        for i in range(entries):
            blk = struct.unpack_from('<I', data, i * 4)[0]
            if blk == 0:
                continue
            if level == 1:
                blocks.append(blk)
            else:
                self._read_indirect(blk, block_size, blocks, level - 1)

    def list_directory(self, inode_number: int) -> list[DirEntry]:
        sb = self._read_superblock_raw()
        block_size = sb['block_size']
        data_blocks = self._get_data_blocks(inode_number)

        entries = []
        for blk_num in data_blocks:
            blk_data = self._read(blk_num * block_size, block_size)
            pos = 0
            while pos < block_size - 8:
                d_inode = struct.unpack_from('<I', blk_data, pos)[0]
                d_rec_len = struct.unpack_from('<H', blk_data, pos + 4)[0]
                if d_rec_len == 0:
                    break
                d_name_len = blk_data[pos + 6]
                d_file_type = blk_data[pos + 7] if sb['has_filetype'] else 0

                if d_inode != 0 and d_name_len > 0:
                    name_bytes = blk_data[pos + 8:pos + 8 + d_name_len]
                    name = name_bytes.decode('utf-8', errors='replace')
                    disk_off = (self._partition_offset
                                + blk_num * block_size + pos)
                    entries.append(DirEntry(
                        name=name,
                        inode=d_inode,
                        file_type=_DIR_FILE_TYPES.get(
                            d_file_type, FileType.UNKNOWN),
                        disk_offset=disk_off,
                        rec_len=d_rec_len,
                    ))

                pos += d_rec_len

        return entries

    # ── Счётчики ────────────────────────────────────────────

    def get_inode_count(self) -> int:
        """Общее число инодов в ФС."""
        sb = self._read_superblock_raw()
        return sb['s_inodes_count']

    # ── Сводная информация ─────────────────────────────────

    def get_fs_info(self) -> dict[str, str]:
        sb = self._read_superblock_raw()
        return {
            "Файловая система": "ext4 (ext2/ext3/ext4)",
            "UUID": str(_uuid.UUID(bytes=sb['s_uuid'])),
            "Метка тома": sb['s_volume_name'] or "—",
            "Размер блока": f"{sb['block_size']} байт",
            "Число блоков": f"{sb['blocks_count']}",
            "Свободных блоков": f"{sb['free_blocks_count']}",
            "Число инодов": f"{sb['s_inodes_count']}",
            "Свободных инодов": f"{sb['s_free_inodes_count']}",
            "Размер инода": f"{sb['s_inode_size']} байт",
            "Блоков в группе": f"{sb['s_blocks_per_group']}",
            "Инодов в группе": f"{sb['s_inodes_per_group']}",
            "Групп блоков": f"{self.get_block_group_count()}",
            "64-bit": "Да" if sb['is_64bit'] else "Нет",
            "Объём ФС": format_size(sb['blocks_count'] * sb['block_size']),
            "Последнее монтирование": sb['s_last_mounted'] or "—",
        }
