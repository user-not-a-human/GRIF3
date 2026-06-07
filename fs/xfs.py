"""
Парсер файловой системы XFS.

Разбирает суперблок, заголовки групп размещения (AG),
иноды и записи каталогов.

XFS использует big-endian порядок байт.

Ссылки:
  - https://xfs.wiki.kernel.org/
  - xfs_format.h в исходниках ядра Linux
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

XFS_SB_MAGIC = 0x58465342  # 'XFSB'
XFS_AGF_MAGIC = 0x58414746  # 'XAGF'
XFS_AGI_MAGIC = 0x58414749  # 'XAGI'

XFS_DINODE_MAGIC = 0x494E  # 'IN'

# Форматы каталогов
XFS_DIR3_FT_UNKNOWN   = 0
XFS_DIR3_FT_REG_FILE  = 1
XFS_DIR3_FT_DIR       = 2
XFS_DIR3_FT_CHRDEV    = 3
XFS_DIR3_FT_BLKDEV    = 4
XFS_DIR3_FT_FIFO      = 5
XFS_DIR3_FT_SOCK      = 6
XFS_DIR3_FT_SYMLINK   = 7

_FILE_TYPES = {
    XFS_DIR3_FT_UNKNOWN:  FileType.UNKNOWN,
    XFS_DIR3_FT_REG_FILE: FileType.REGULAR,
    XFS_DIR3_FT_DIR:      FileType.DIRECTORY,
    XFS_DIR3_FT_CHRDEV:   FileType.CHARDEV,
    XFS_DIR3_FT_BLKDEV:   FileType.BLOCKDEV,
    XFS_DIR3_FT_FIFO:     FileType.FIFO,
    XFS_DIR3_FT_SOCK:     FileType.SOCKET,
    XFS_DIR3_FT_SYMLINK:  FileType.SYMLINK,
}


class XFSParser(FSParser):
    """Парсер файловой системы XFS."""

    def __init__(self, reader: DiskReader, partition_offset: int = 0):
        super().__init__(reader, partition_offset)
        self._sb: Optional[dict] = None

    @staticmethod
    def fs_name() -> str:
        return "XFS"

    # ── Суперблок ──────────────────────────────────────────

    def _read_superblock_raw(self) -> dict:
        if self._sb is not None:
            return self._sb

        data = self._read(0, 512)
        if len(data) < 272:
            raise ValueError("Недостаточно данных для суперблока XFS")

        magic = struct.unpack_from('>I', data, 0)[0]
        if magic != XFS_SB_MAGIC:
            raise ValueError(
                f"Неверная сигнатура суперблока XFS: "
                f"0x{magic:08X} (ожидалось 0x{XFS_SB_MAGIC:08X})"
            )

        sb = {}
        sb['sb_magicnum']   = magic
        sb['sb_blocksize']  = struct.unpack_from('>I', data, 4)[0]
        sb['sb_dblocks']    = struct.unpack_from('>Q', data, 8)[0]
        sb['sb_rblocks']    = struct.unpack_from('>Q', data, 16)[0]
        sb['sb_rextents']   = struct.unpack_from('>Q', data, 24)[0]
        sb['sb_uuid']       = data[32:48]
        sb['sb_logstart']   = struct.unpack_from('>Q', data, 48)[0]
        sb['sb_rootino']    = struct.unpack_from('>Q', data, 56)[0]
        sb['sb_rbmino']     = struct.unpack_from('>Q', data, 64)[0]
        sb['sb_rsumino']    = struct.unpack_from('>Q', data, 72)[0]
        sb['sb_rextsize']   = struct.unpack_from('>I', data, 80)[0]
        sb['sb_agblocks']   = struct.unpack_from('>I', data, 84)[0]
        sb['sb_agcount']    = struct.unpack_from('>I', data, 88)[0]
        sb['sb_rbmblocks']  = struct.unpack_from('>I', data, 92)[0]
        sb['sb_logblocks']  = struct.unpack_from('>I', data, 96)[0]
        sb['sb_versionnum'] = struct.unpack_from('>H', data, 100)[0]
        sb['sb_sectsize']   = struct.unpack_from('>H', data, 102)[0]
        sb['sb_inodesize']  = struct.unpack_from('>H', data, 104)[0]
        sb['sb_inopblock']  = struct.unpack_from('>H', data, 106)[0]
        sb['sb_fname']      = data[108:120].rstrip(b'\x00').decode(
                                  'utf-8', errors='replace')
        sb['sb_blocklog']   = data[120]
        sb['sb_sectlog']    = data[121]
        sb['sb_inodelog']   = data[122]
        sb['sb_inopblog']   = data[123]
        sb['sb_agblklog']   = data[124]
        sb['sb_rextslog']   = data[125]
        sb['sb_inprogress'] = data[126]
        sb['sb_imax_pct']   = data[127]
        sb['sb_icount']     = struct.unpack_from('>Q', data, 128)[0]
        sb['sb_ifree']      = struct.unpack_from('>Q', data, 136)[0]
        sb['sb_fdblocks']   = struct.unpack_from('>Q', data, 144)[0]
        sb['sb_frextents']  = struct.unpack_from('>Q', data, 152)[0]
        sb['sb_uquotino']   = struct.unpack_from('>Q', data, 160)[0]
        sb['sb_gquotino']   = struct.unpack_from('>Q', data, 168)[0]
        sb['sb_qflags']     = struct.unpack_from('>H', data, 176)[0]
        sb['sb_flags']      = data[178]
        sb['sb_shared_vn']  = data[179]

        self._sb = sb
        return sb

    def parse_superblock(self) -> ParsedStructure:
        sb = self._read_superblock_raw()
        data = self._read(0, 512)
        disk_off = self._partition_offset

        ps = ParsedStructure(
            name="Суперблок XFS",
            disk_offset=disk_off,
            size=512,
        )

        def a(name, off, sz, val, desc=""):
            ps.add(name, off, sz, data[off:off+sz], val, desc)

        a("sb_magicnum",   0, 4, "XFSB", "Сигнатура")
        a("sb_blocksize",  4, 4, sb['sb_blocksize'],
          f"Размер блока ({sb['sb_blocksize']} байт)")
        a("sb_dblocks",    8, 8, sb['sb_dblocks'],
          f"Блоков данных ({format_size(sb['sb_dblocks'] * sb['sb_blocksize'])})")
        a("sb_rblocks",   16, 8, sb['sb_rblocks'],
          "Блоков реального времени")
        a("sb_uuid",      32, 16,
          str(_uuid.UUID(bytes=sb['sb_uuid'])), "UUID")
        a("sb_logstart",  48, 8, sb['sb_logstart'],
          "Начальный блок журнала")
        a("sb_rootino",   56, 8, sb['sb_rootino'],
          "Номер корневого инода")
        a("sb_agblocks",  84, 4, sb['sb_agblocks'],
          "Блоков в группе размещения (AG)")
        a("sb_agcount",   88, 4, sb['sb_agcount'],
          "Число групп размещения (AG)")
        a("sb_versionnum", 100, 2, f"0x{sb['sb_versionnum']:04X}",
          "Номер версии")
        a("sb_sectsize",  102, 2, sb['sb_sectsize'],
          "Размер сектора")
        a("sb_inodesize", 104, 2, sb['sb_inodesize'],
          "Размер инода")
        a("sb_inopblock", 106, 2, sb['sb_inopblock'],
          "Инодов в блоке")
        a("sb_fname",     108, 12, sb['sb_fname'],
          "Метка тома")
        a("sb_icount",    128, 8, sb['sb_icount'],
          "Всего инодов (выделено)")
        a("sb_ifree",     136, 8, sb['sb_ifree'],
          "Свободных инодов")
        a("sb_fdblocks",  144, 8, sb['sb_fdblocks'],
          "Свободных блоков данных")

        return ps

    # ── AG (Allocation Groups) ─────────────────────────────

    def get_block_group_count(self) -> int:
        sb = self._read_superblock_raw()
        return sb['sb_agcount']

    def get_block_group_info(self, group_index: int) -> ParsedStructure:
        sb = self._read_superblock_raw()
        ag_offset = group_index * sb['sb_agblocks'] * sb['sb_blocksize']

        # AGF header at ag_offset + sectsize
        agf_off = ag_offset + sb['sb_sectsize']
        agf_data = self._read(agf_off, 256)

        # AGI header at ag_offset + 2*sectsize
        agi_off = ag_offset + 2 * sb['sb_sectsize']
        agi_data = self._read(agi_off, 256)

        disk_off = self._partition_offset + ag_offset
        ps = ParsedStructure(
            name=f"AG #{group_index} (Allocation Group)",
            disk_offset=disk_off,
            size=sb['sb_agblocks'] * sb['sb_blocksize'],
        )

        # AG суперблок (копия основного)
        ag_sb_data = self._read(ag_offset, 512)
        ag_magic = struct.unpack_from('>I', ag_sb_data, 0)[0]
        ps.add("AG Superblock magic", 0, 4, ag_sb_data[0:4],
               f"0x{ag_magic:08X}", "Копия суперблока в AG")

        # AGF
        if len(agf_data) >= 80:
            agf_magic = struct.unpack_from('>I', agf_data, 0)[0]
            agf_freeblks = struct.unpack_from('>I', agf_data, 16)[0]
            agf_longest = struct.unpack_from('>I', agf_data, 20)[0]
            ps.add("AGF magic", 0, 4, agf_data[0:4],
                   f"0x{agf_magic:08X}",
                   "Заголовок AGF (Free Space)")
            ps.add("AGF freeblks", 16, 4, agf_data[16:20],
                   agf_freeblks, "Свободных блоков в AG")
            ps.add("AGF longest", 20, 4, agf_data[20:24],
                   agf_longest, "Длиннейший свободный экстент")

        # AGI
        if len(agi_data) >= 48:
            agi_magic = struct.unpack_from('>I', agi_data, 0)[0]
            agi_count = struct.unpack_from('>I', agi_data, 16)[0]
            agi_freecount = struct.unpack_from('>I', agi_data, 24)[0]
            agi_root = struct.unpack_from('>I', agi_data, 20)[0]
            ps.add("AGI magic", 0, 4, agi_data[0:4],
                   f"0x{agi_magic:08X}",
                   "Заголовок AGI (Inode Index)")
            ps.add("AGI count", 16, 4, agi_data[16:20],
                   agi_count, "Число инодов в AG")
            ps.add("AGI root", 20, 4, agi_data[20:24],
                   agi_root, "Корень B+дерева инодов")
            ps.add("AGI freecount", 24, 4, agi_data[24:28],
                   agi_freecount, "Свободных инодов в AG")

        return ps

    # ── Иноды ──────────────────────────────────────────────

    def _inode_offset(self, inode_number: int) -> int:
        """Вычислить смещение инода XFS на диске."""
        sb = self._read_superblock_raw()
        agblklog = sb['sb_agblklog']
        inodelog = sb['sb_inodelog']
        blocksize = sb['sb_blocksize']
        agblocks = sb['sb_agblocks']

        # Номер AG и позиция внутри AG
        ag_number = inode_number >> (agblklog + sb['sb_inopblog'])
        ag_relative = inode_number & ((1 << (agblklog + sb['sb_inopblog'])) - 1)

        # Номер блока внутри AG и позиция инода в блоке
        block_in_ag = ag_relative >> sb['sb_inopblog']
        offset_in_block = (ag_relative & ((1 << sb['sb_inopblog']) - 1)) * sb['sb_inodesize']

        return (ag_number * agblocks + block_in_ag) * blocksize + offset_in_block

    def _parse_xfs_inode(self, data: bytes, inode_number: int,
                         disk_offset: int) -> tuple[dict, ParsedStructure]:
        """Разобрать XFS dinode (v2/v3)."""
        sb = self._read_superblock_raw()
        inode_size = sb['sb_inodesize']

        di_magic    = struct.unpack_from('>H', data, 0)[0]
        di_mode     = struct.unpack_from('>H', data, 2)[0]
        di_version  = data[4]
        di_format   = data[5]
        di_uid      = struct.unpack_from('>I', data, 8)[0]
        di_gid      = struct.unpack_from('>I', data, 12)[0]
        di_nlink    = struct.unpack_from('>I', data, 16)[0]
        di_atime_s  = struct.unpack_from('>I', data, 24)[0]
        di_mtime_s  = struct.unpack_from('>I', data, 32)[0]
        di_ctime_s  = struct.unpack_from('>I', data, 40)[0]
        di_size     = struct.unpack_from('>Q', data, 48)[0]
        di_nblocks  = struct.unpack_from('>Q', data, 56)[0]
        di_flags    = struct.unpack_from('>H', data, 68)[0]
        di_gen      = struct.unpack_from('>I', data, 72)[0]

        # Тип файла
        mode_type = di_mode & 0o170000
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

        # data fork offset
        di_forkoff = data[6]
        if di_version == 3:
            data_fork_offset = 176
        else:
            data_fork_offset = 100

        raw = {
            'di_magic': di_magic,
            'di_mode': di_mode,
            'di_version': di_version,
            'di_format': di_format,
            'di_uid': di_uid,
            'di_gid': di_gid,
            'di_nlink': di_nlink,
            'di_atime': di_atime_s,
            'di_mtime': di_mtime_s,
            'di_ctime': di_ctime_s,
            'di_size': di_size,
            'di_nblocks': di_nblocks,
            'di_flags': di_flags,
            'file_type': file_type,
            'data_fork_offset': data_fork_offset,
            'di_forkoff': di_forkoff,
        }

        format_names = {
            0: "dev", 1: "local", 2: "extents", 3: "btree", 4: "uuid",
        }

        ps = ParsedStructure(
            name=f"Инод XFS #{inode_number}",
            disk_offset=disk_offset,
            size=inode_size,
        )
        ps.add("di_magic",   0, 2, data[0:2],
               f"0x{di_magic:04X}", "Сигнатура ('IN')")
        ps.add("di_mode",    2, 2, data[2:4],
               f"0o{di_mode:06o} ({format_mode(di_mode)})",
               "Тип и права")
        ps.add("di_version", 4, 1, data[4:5], di_version, "Версия инода")
        ps.add("di_format",  5, 1, data[5:6],
               format_names.get(di_format, str(di_format)),
               "Формат данных")
        ps.add("di_uid",     8, 4, data[8:12],  di_uid,  "UID")
        ps.add("di_gid",    12, 4, data[12:16], di_gid,  "GID")
        ps.add("di_nlink",  16, 4, data[16:20], di_nlink, "Жёстких ссылок")
        ps.add("di_atime",  24, 4, data[24:28],
               str(ts_to_datetime(di_atime_s) or "—"), "Время доступа")
        ps.add("di_mtime",  32, 4, data[32:36],
               str(ts_to_datetime(di_mtime_s) or "—"), "Время изменения")
        ps.add("di_ctime",  40, 4, data[40:44],
               str(ts_to_datetime(di_ctime_s) or "—"), "Время метаданных")
        ps.add("di_size",   48, 8, data[48:56],
               f"{di_size} ({format_size(di_size)})", "Размер")
        ps.add("di_nblocks", 56, 8, data[56:64], di_nblocks,
               "Число блоков")
        ps.add("di_flags",  68, 2, data[68:70],
               f"0x{di_flags:04X}", "Флаги")

        return raw, ps

    def get_inode(self, inode_number: int) -> ParsedStructure:
        sb = self._read_superblock_raw()
        offset = self._inode_offset(inode_number)
        data = self._read(offset, sb['sb_inodesize'])
        disk_off = self._partition_offset + offset
        _, ps = self._parse_xfs_inode(data, inode_number, disk_off)
        return ps

    def get_inode_meta(self, inode_number: int) -> InodeMeta:
        sb = self._read_superblock_raw()
        offset = self._inode_offset(inode_number)
        data = self._read(offset, sb['sb_inodesize'])
        raw, _ = self._parse_xfs_inode(
            data, inode_number, self._partition_offset + offset)
        return InodeMeta(
            number=inode_number,
            mode=raw['di_mode'],
            uid=raw['di_uid'],
            gid=raw['di_gid'],
            size=raw['di_size'],
            links=raw['di_nlink'],
            atime=ts_to_datetime(raw['di_atime']),
            mtime=ts_to_datetime(raw['di_mtime']),
            ctime=ts_to_datetime(raw['di_ctime']),
            flags=raw['di_flags'],
            file_type=raw['file_type'],
            disk_offset=self._partition_offset + offset,
        )

    # ── Каталоги ───────────────────────────────────────────

    def list_directory(self, inode_number: int) -> list[DirEntry]:
        """
        Прочитать записи каталога XFS.

        Поддерживает shortform каталоги (формат local)
        и block-формат каталогов.
        """
        sb = self._read_superblock_raw()
        offset = self._inode_offset(inode_number)
        data = self._read(offset, sb['sb_inodesize'])
        raw, _ = self._parse_xfs_inode(
            data, inode_number, self._partition_offset + offset)

        entries = []

        if raw['di_format'] == 1:
            # shortform — данные прямо в иноде
            fork_offset = raw['data_fork_offset']
            fork_data = data[fork_offset:]
            entries = self._parse_shortform_dir(
                fork_data, raw['di_size'],
                self._partition_offset + offset + fork_offset)
        elif raw['di_format'] == 2:
            # extents — данные в экстентах
            entries = self._parse_extent_dir(data, raw, inode_number)
        elif raw['di_format'] == 3:
            # btree — B+tree формат (сложный; показываем что есть)
            entries = self._parse_extent_dir(data, raw, inode_number)

        return entries

    def _parse_shortform_dir(self, fork_data: bytes, dir_size: int,
                             disk_offset: int) -> list[DirEntry]:
        """Разбор shortform каталога (данные внутри инода)."""
        entries = []
        if len(fork_data) < 6:
            return entries

        # Shortform header
        sf_count = fork_data[0]
        # i8count в позиции 1, parent в позиции 2..9 или 2..5
        i8count = fork_data[1]

        if i8count:
            parent_ino = struct.unpack_from('>Q', fork_data, 2)[0]
            pos = 10
        else:
            parent_ino = struct.unpack_from('>I', fork_data, 2)[0]
            pos = 6

        # Добавляем . и ..
        entries.append(DirEntry(
            name=".", inode=0, file_type=FileType.DIRECTORY,
            disk_offset=disk_offset, rec_len=0))
        entries.append(DirEntry(
            name="..", inode=parent_ino, file_type=FileType.DIRECTORY,
            disk_offset=disk_offset, rec_len=0))

        for _ in range(sf_count):
            if pos + 3 > len(fork_data):
                break
            namelen = fork_data[pos]
            # offset (2 bytes) — пропускаем
            pos += 1
            sf_offset = struct.unpack_from('>H', fork_data, pos)[0]
            pos += 2

            if pos + namelen > len(fork_data):
                break
            name = fork_data[pos:pos + namelen].decode(
                'utf-8', errors='replace')
            pos += namelen

            # filetype byte (если v3 inode)
            ftype = FileType.UNKNOWN
            if pos < len(fork_data):
                ft_byte = fork_data[pos]
                if ft_byte in _FILE_TYPES:
                    ftype = _FILE_TYPES[ft_byte]
                    pos += 1

            # inode number
            if i8count:
                if pos + 8 > len(fork_data):
                    break
                ino = struct.unpack_from('>Q', fork_data, pos)[0]
                pos += 8
            else:
                if pos + 4 > len(fork_data):
                    break
                ino = struct.unpack_from('>I', fork_data, pos)[0]
                pos += 4

            entries.append(DirEntry(
                name=name, inode=ino, file_type=ftype,
                disk_offset=disk_offset + pos - namelen - 3,
                rec_len=0))

        return entries

    def _parse_extent_dir(self, inode_data: bytes, raw: dict,
                          inode_number: int) -> list[DirEntry]:
        """Разбор каталога в формате extents (block/leaf directory)."""
        sb = self._read_superblock_raw()
        blocksize = sb['sb_blocksize']
        fork_offset = raw['data_fork_offset']

        entries = []

        # Читаем экстенты из data fork
        # XFS extent: 128 бит (16 байт) в packed формате
        # [flag(1):startoff(54):startblock(52):blockcount(21)]
        # Всё big-endian, bit-packed
        ext_data = inode_data[fork_offset:]
        max_extents = min(20, len(ext_data) // 16)

        for i in range(max_extents):
            ext_raw = ext_data[i * 16:(i + 1) * 16]
            if len(ext_raw) < 16 or ext_raw == b'\x00' * 16:
                break

            # Распаковка 128-бит packed extent
            hi = struct.unpack_from('>Q', ext_raw, 0)[0]
            lo = struct.unpack_from('>Q', ext_raw, 8)[0]

            flag = (hi >> 63) & 1
            startoff = (hi >> 9) & 0x1FFFFFFFFFFFF  # 54 бит
            startblock = ((hi & 0x1FF) << 43) | (lo >> 21)  # 52 бит
            blockcount = lo & 0x1FFFFF  # 21 бит

            if blockcount == 0:
                continue

            # startblock содержит AG number и block within AG
            ag_number = startblock >> sb['sb_agblklog']
            ag_block = startblock & ((1 << sb['sb_agblklog']) - 1)
            physical_offset = (ag_number * sb['sb_agblocks'] + ag_block) * blocksize

            for blk in range(blockcount):
                blk_offset = physical_offset + blk * blocksize
                blk_data = self._read(blk_offset, blocksize)
                blk_entries = self._parse_dir_block(
                    blk_data, self._partition_offset + blk_offset, blocksize)
                entries.extend(blk_entries)

        return entries

    def _parse_dir_block(self, blk_data: bytes, disk_offset: int,
                         blocksize: int) -> list[DirEntry]:
        """Разбор одного блока каталога XFS (data block)."""
        entries = []

        # Проверяем magic
        if len(blk_data) < 16:
            return entries

        magic = struct.unpack_from('>I', blk_data, 0)[0]

        # XFS dir data block magics
        # XFS_DIR2_DATA_MAGIC  = 0x58443244  'XD2D'
        # XFS_DIR3_DATA_MAGIC  = 0x58444433  'XDD3'
        # XFS_DIR2_BLOCK_MAGIC = 0x58443242  'XD2B'
        # XFS_DIR3_BLOCK_MAGIC = 0x58444233  'XDB3'
        valid_magics = {0x58443244, 0x58444433, 0x58443242, 0x58444233}

        if magic in {0x58444433, 0x58444233}:
            # v3 header: 48 bytes (magic + crc + blkno + lsn + uuid + owner)
            pos = 64
        elif magic in {0x58443244, 0x58443242}:
            # v2 header: 16 bytes
            pos = 16
        else:
            return entries

        # Разбираем записи
        while pos + 11 < blocksize:
            # Проверяем на freespace entry (magic 0xFFFF)
            freetag = struct.unpack_from('>H', blk_data, pos)[0]
            if freetag == 0xFFFF:
                # Free space
                free_len = struct.unpack_from('>H', blk_data, pos + 2)[0]
                if free_len == 0:
                    break
                pos += free_len
                continue

            # Data entry
            d_inumber = struct.unpack_from('>Q', blk_data, pos)[0]
            d_namelen = blk_data[pos + 8]

            if d_namelen == 0 or d_inumber == 0:
                break

            if pos + 11 + d_namelen > blocksize:
                break

            name = blk_data[pos + 9:pos + 9 + d_namelen].decode(
                'utf-8', errors='replace')

            # filetype byte после name
            ftype_off = pos + 9 + d_namelen
            ftype = FileType.UNKNOWN
            if ftype_off < blocksize:
                ft = blk_data[ftype_off]
                ftype = _FILE_TYPES.get(ft, FileType.UNKNOWN)

            entries.append(DirEntry(
                name=name,
                inode=d_inumber,
                file_type=ftype,
                disk_offset=disk_offset + pos,
                rec_len=0,
            ))

            # Entry size: 8 (ino) + 1 (namelen) + namelen + 1 (ftype) + padding to 8
            entry_len = 8 + 1 + d_namelen + 1
            entry_len = (entry_len + 7) & ~7  # align to 8
            pos += entry_len

        return entries

    def get_inode_count(self) -> int:
        sb = self._read_superblock_raw()
        return sb.get('sb_icount', 0)

    # ── Сводка ─────────────────────────────────────────────

    def get_fs_info(self) -> dict[str, str]:
        sb = self._read_superblock_raw()
        total = sb['sb_dblocks'] * sb['sb_blocksize']
        free = sb['sb_fdblocks'] * sb['sb_blocksize']

        return {
            "Файловая система": "XFS",
            "UUID": str(_uuid.UUID(bytes=sb['sb_uuid'])),
            "Метка тома": sb['sb_fname'] or "—",
            "Размер блока": f"{sb['sb_blocksize']} байт",
            "Число блоков": f"{sb['sb_dblocks']}",
            "Свободных блоков": f"{sb['sb_fdblocks']}",
            "Объём ФС": format_size(total),
            "Свободно": format_size(free),
            "Размер инода": f"{sb['sb_inodesize']} байт",
            "Корневой инод": f"{sb['sb_rootino']}",
            "Число AG": f"{sb['sb_agcount']}",
            "Блоков в AG": f"{sb['sb_agblocks']}",
            "Инодов (выделено)": f"{sb['sb_icount']}",
            "Инодов (свободно)": f"{sb['sb_ifree']}",
            "Размер сектора": f"{sb['sb_sectsize']} байт",
        }
