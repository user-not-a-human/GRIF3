"""
Unit-тесты для HexCorruptor.

Тестируют основные компоненты:
  - Парсеры ФС
  - Команды Undo/Redo
  - Виджеты GUI (базовые)
"""

import unittest
import tempfile
import os
import hashlib
import json
import time
import uuid
from unittest.mock import Mock

from core.disk import DiskReader
from fs.ext4 import Ext4Parser
from fs.detector import detect_filesystem
from commands import CommandHistory, ReplaceCommand


def create_ext4_deleted_file_image() -> str:
    block_size = 1024
    inode_size = 256
    inode_table_block = 5
    image = bytearray(256 * 1024)
    sb = bytearray(1024)
    sb[0:4] = (128).to_bytes(4, 'little')
    sb[4:8] = (256).to_bytes(4, 'little')
    sb[12:16] = (200).to_bytes(4, 'little')
    sb[16:20] = (110).to_bytes(4, 'little')
    sb[20:24] = (1).to_bytes(4, 'little')
    sb[24:28] = (0).to_bytes(4, 'little')
    sb[28:32] = (0).to_bytes(4, 'little')
    sb[32:36] = (8192).to_bytes(4, 'little')
    sb[36:40] = (8192).to_bytes(4, 'little')
    sb[40:44] = (128).to_bytes(4, 'little')
    sb[44:48] = (1700000000).to_bytes(4, 'little')
    sb[48:52] = (1700000000).to_bytes(4, 'little')
    sb[52:54] = (1).to_bytes(2, 'little')
    sb[54:56] = (20).to_bytes(2, 'little')
    sb[56:58] = (0xEF53).to_bytes(2, 'little')
    sb[58:60] = (1).to_bytes(2, 'little')
    sb[60:62] = (1).to_bytes(2, 'little')
    sb[76:80] = (1).to_bytes(4, 'little')
    sb[84:88] = (11).to_bytes(4, 'little')
    sb[88:90] = inode_size.to_bytes(2, 'little')
    sb[96:100] = (0x0042).to_bytes(4, 'little')
    sb[100:104] = (1).to_bytes(4, 'little')
    sb[104:120] = uuid.UUID('12345678-1234-1234-1234-123456789abc').bytes
    sb[120:136] = b'forensics'.ljust(16, b'\x00')
    sb[254:256] = (32).to_bytes(2, 'little')
    image[1024:2048] = sb

    group_desc = bytearray(32)
    group_desc[8:12] = inode_table_block.to_bytes(4, 'little')
    image[2048:2080] = group_desc

    def extent_block(block_number: int) -> bytes:
        i_block = bytearray(60)
        i_block[0:2] = (0xF30A).to_bytes(2, 'little')
        i_block[2:4] = (1).to_bytes(2, 'little')
        i_block[4:6] = (4).to_bytes(2, 'little')
        i_block[12:16] = (0).to_bytes(4, 'little')
        i_block[16:18] = (1).to_bytes(2, 'little')
        i_block[20:24] = block_number.to_bytes(4, 'little')
        return bytes(i_block)

    def put_inode(inode: int, mode: int, content: bytes, links: int, dtime: int) -> None:
        raw = bytearray(inode_size)
        now = 1700001000 + inode
        block_number = 40 + inode
        raw[0:2] = mode.to_bytes(2, 'little')
        raw[4:8] = len(content).to_bytes(4, 'little')
        raw[8:12] = now.to_bytes(4, 'little')
        raw[12:16] = now.to_bytes(4, 'little')
        raw[16:20] = now.to_bytes(4, 'little')
        raw[20:24] = dtime.to_bytes(4, 'little')
        raw[26:28] = links.to_bytes(2, 'little')
        raw[28:32] = (2).to_bytes(4, 'little')
        raw[32:36] = (0x00080000).to_bytes(4, 'little')
        raw[40:100] = extent_block(block_number)
        raw[144:148] = (now - 3600).to_bytes(4, 'little')
        inode_offset = inode_table_block * block_size + (inode - 1) * inode_size
        image[inode_offset:inode_offset + inode_size] = raw
        data_offset = block_number * block_size
        image[data_offset:data_offset + len(content)] = content

    def put_dir_block(block_number: int, self_inode: int, parent_inode: int, entries: list[tuple[int, str, int]]) -> None:
        block = bytearray(block_size)
        pos = 0
        all_entries = [(self_inode, '.', 2), (parent_inode, '..', 2), *entries]
        for index, (inode, name, file_type) in enumerate(all_entries):
            name_bytes = name.encode('utf-8')
            rec_len = 8 + ((len(name_bytes) + 3) & ~3)
            if index == len(all_entries) - 1:
                rec_len = block_size - pos
            block[pos:pos + 4] = inode.to_bytes(4, 'little')
            block[pos + 4:pos + 6] = rec_len.to_bytes(2, 'little')
            block[pos + 6] = len(name_bytes)
            block[pos + 7] = file_type
            block[pos + 8:pos + 8 + len(name_bytes)] = name_bytes
            pos += rec_len
        start = block_number * block_size
        image[start:start + block_size] = block

    put_inode(12, 0o100644, b'ACTIVE_FILE', 1, 0)
    put_inode(13, 0o100600, b'SECRET-DELETED-DATA', 0, 1700005000)
    put_inode(14, 0o100600, b'LINKS-ZERO-DATA', 0, 0)
    put_inode(15, 0o040755, b'DIRDATA', 0, 1700005000)
    put_inode(16, 0o120777, b'SYMLINKDATA', 0, 1700005000)
    put_inode(17, 0o100600, b'', 0, 1700005000)
    put_dir_block(90, 2, 2, [(18, 'secret_folder', 2)])
    put_dir_block(91, 18, 2, [(19, 'secret.txt', 1)])
    image[92 * block_size:92 * block_size + len(b'secret_text\n')] = b'secret_text\n'

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(image)
    temp_file.close()
    return temp_file.name


def create_boot_image(kind: str) -> str:
    image = bytearray(256 * 1024)
    boot = bytearray(512)
    boot[0:3] = b'\xeb\x52\x90'
    boot[510:512] = b'\x55\xaa'
    if kind == "ntfs":
        boot[3:11] = b'NTFS    '
        boot[11:13] = (512).to_bytes(2, 'little')
        boot[13] = 8
        boot[40:48] = (4096).to_bytes(8, 'little')
        boot[48:56] = (4).to_bytes(8, 'little')
        boot[56:64] = (8).to_bytes(8, 'little')
        boot[64:65] = (-10).to_bytes(1, 'little', signed=True)
    elif kind == "exfat":
        boot[3:11] = b'EXFAT   '
        boot[64:72] = (0).to_bytes(8, 'little')
        boot[72:80] = (4096).to_bytes(8, 'little')
        boot[80:84] = (128).to_bytes(4, 'little')
        boot[84:88] = (16).to_bytes(4, 'little')
        boot[88:92] = (256).to_bytes(4, 'little')
        boot[92:96] = (1024).to_bytes(4, 'little')
        boot[96:100] = (2).to_bytes(4, 'little')
        boot[108] = 9
        boot[109] = 3
    elif kind == "fat32":
        boot[3:11] = b'MSWIN4.1'
        boot[11:13] = (512).to_bytes(2, 'little')
        boot[13] = 8
        boot[14:16] = (32).to_bytes(2, 'little')
        boot[16] = 2
        boot[17:19] = (0).to_bytes(2, 'little')
        boot[32:36] = (4096).to_bytes(4, 'little')
        boot[36:40] = (64).to_bytes(4, 'little')
        boot[44:48] = (2).to_bytes(4, 'little')
        boot[71:82] = b'NO NAME    '
        boot[82:90] = b'FAT32   '
    else:
        raise ValueError(kind)
    image[0:512] = boot
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(image)
    temp_file.close()
    return temp_file.name


class TestExt4Parser(unittest.TestCase):
    """Тесты для парсера ext4."""

    def setUp(self):
        # Создать синтетический ext4 суперблок
        self.superblock_data = bytearray(1024)
        # s_inodes_count (offset 0x00)
        self.superblock_data[0:4] = (1280).to_bytes(4, 'little')
        # s_blocks_count_lo (0x04)
        self.superblock_data[4:8] = (65536).to_bytes(4, 'little')
        # s_r_blocks_count_lo (0x08)
        self.superblock_data[8:12] = (0).to_bytes(4, 'little')
        # s_free_blocks_count_lo (0x0C)
        self.superblock_data[12:16] = (60000).to_bytes(4, 'little')
        # s_free_inodes_count (0x10)
        self.superblock_data[16:20] = (1200).to_bytes(4, 'little')
        # s_first_data_block (0x14)
        self.superblock_data[20:24] = (1).to_bytes(4, 'little')
        # s_log_block_size (0x18)
        self.superblock_data[24:28] = (0).to_bytes(4, 'little')  # 1KB blocks
        # s_log_cluster_size (0x1C) - ext4 only
        self.superblock_data[28:32] = (0).to_bytes(4, 'little')
        # s_blocks_per_group (0x20)
        self.superblock_data[32:36] = (32768).to_bytes(4, 'little')
        # s_clusters_per_group (0x24)
        self.superblock_data[36:40] = (32768).to_bytes(4, 'little')
        # s_inodes_per_group (0x28)
        self.superblock_data[40:44] = (1600).to_bytes(4, 'little')
        # s_mtime (0x2C)
        self.superblock_data[44:48] = (1609459200).to_bytes(4, 'little')  # 2021-01-01
        # s_wtime (0x30)
        self.superblock_data[48:52] = (1609459200).to_bytes(4, 'little')
        # s_mnt_count (0x34)
        self.superblock_data[52:56] = (1).to_bytes(2, 'little')
        # s_max_mnt_count (0x36)
        self.superblock_data[54:58] = (20).to_bytes(2, 'little')
        # s_magic (0x38)
        self.superblock_data[56:58] = (0xEF53).to_bytes(2, 'little')
        # s_state (0x3A)
        self.superblock_data[58:60] = (1).to_bytes(2, 'little')  # cleanly unmounted
        # s_errors (0x3C)
        self.superblock_data[60:62] = (1).to_bytes(2, 'little')
        # s_minor_rev_level (0x3E)
        self.superblock_data[62:64] = (0).to_bytes(2, 'little')
        # s_lastcheck (0x40)
        self.superblock_data[64:68] = (1609459200).to_bytes(4, 'little')
        # s_checkinterval (0x44)
        self.superblock_data[68:72] = (15552000).to_bytes(4, 'little')  # 6 months
        # s_creator_os (0x48)
        self.superblock_data[72:76] = (0).to_bytes(4, 'little')  # Linux
        # s_rev_level (0x4C)
        self.superblock_data[76:80] = (1).to_bytes(4, 'little')  # dynamic
        # s_def_resuid (0x50)
        self.superblock_data[80:82] = (0).to_bytes(2, 'little')
        # s_def_resgid (0x52)
        self.superblock_data[82:84] = (0).to_bytes(2, 'little')
        # s_first_ino (0x58)
        self.superblock_data[84:88] = (11).to_bytes(4, 'little')
        # s_inode_size (0x5C)
        self.superblock_data[88:90] = (256).to_bytes(2, 'little')
        # s_block_group_nr (0x5E)
        self.superblock_data[90:92] = (0).to_bytes(2, 'little')
        # s_feature_compat (0x60)
        self.superblock_data[92:96] = (60).to_bytes(4, 'little')  # dir_index, filetype
        # s_feature_incompat (0x64)
        self.superblock_data[96:100] = (6).to_bytes(4, 'little')  # filetype, extents
        # s_feature_ro_compat (0x68)
        self.superblock_data[100:104] = (1).to_bytes(4, 'little')  # sparse_super
        # s_uuid (0x6C)
        self.superblock_data[104:120] = uuid.UUID(
            '12345678-1234-1234-1234-123456789abc'
        ).bytes
        # s_volume_name (0x78)
        self.superblock_data[120:136] = b'test_volume'.ljust(16, b'\x00')
        # s_last_mounted (0x8C)
        self.superblock_data[136:200] = b'/mnt/test'.ljust(64, b'\x00')
        # s_algorithm_usage_bitmap (0xC8)
        self.superblock_data[200:204] = (0).to_bytes(4, 'little')

        # Создать временный файл с суперблоком по offset 1024
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        # Заполнить первые 1024 байта нулями, затем суперблок
        self.temp_file.write(b'\x00' * 1024)
        self.temp_file.write(self.superblock_data)
        self.temp_file.close()

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_superblock_parsing(self):
        """Тест парсинга суперблока ext4."""
        reader = DiskReader(self.temp_file.name, read_only=True)
        reader.open()

        parser = Ext4Parser(reader, 0)
        sb = parser.parse_superblock()

        self.assertEqual(sb.fields[0].value, 1280)  # s_inodes_count
        self.assertEqual(sb.fields[1].value, 65536)  # s_blocks_count
        self.assertEqual(sb.fields[12].value, "0xEF53")  # s_magic
        self.assertEqual(sb.fields[18].value, "12345678-1234-1234-1234-123456789abc")  # s_uuid
        self.assertEqual(sb.fields[19].value, "test_volume")  # s_volume_name

        reader.close()


class TestExt4DeletedFilesForensics(unittest.TestCase):
    def setUp(self):
        self.path = create_ext4_deleted_file_image()
        self.reader = DiskReader(self.path, read_only=True)
        self.reader.open()
        self.parser = Ext4Parser(self.reader, 0)

    def tearDown(self):
        self.reader.close()
        os.unlink(self.path)

    def test_scan_deleted_files_filters_inode_types(self):
        scan = self.parser.scan_deleted_files(limit=20)
        inodes = {item["inode"] for item in scan["items"]}
        self.assertIn(13, inodes)
        self.assertIn(14, inodes)
        self.assertNotIn(12, inodes)
        self.assertNotIn(15, inodes)
        self.assertNotIn(16, inodes)
        self.assertNotIn(17, inodes)

    def test_deleted_file_detail_has_timestamps_and_extents(self):
        detail = self.parser.get_deleted_file(13)
        self.assertEqual(detail["filename"], "unknown")
        self.assertEqual(detail["firstBlock"], 53)
        self.assertEqual(detail["links"], 0)
        self.assertIsNotNone(detail["crtime"])
        self.assertIsNotNone(detail["mtime"])
        self.assertIsNotNone(detail["ctime"])
        self.assertIsNotNone(detail["atime"])
        self.assertIsNotNone(detail["dtime"])

    def test_recovery_returns_exact_i_size_bytes(self):
        recovery = self.parser.recover_file(13)
        self.assertEqual(recovery["data"], b'SECRET-DELETED-DATA')
        self.assertEqual(recovery["recoveredBytes"], len(b'SECRET-DELETED-DATA'))

    def test_preview_returns_first_bytes(self):
        preview = self.parser.read_file_preview(13, length=8)
        self.assertEqual(preview["ascii"], "SECRET-D")
        self.assertEqual(preview["length"], 8)

    def test_session_backend_forensics_methods(self):
        from web_backend import HexCorruptorSession

        session = HexCorruptorSession()
        try:
            session.open_source(self.path)
            scan = session.deleted_files(limit=10, cursor=1, min_size=1)
            self.assertGreaterEqual(len(scan["items"]), 2)
            detail = session.deleted_file(13)
            self.assertEqual(detail["inode"], 13)
            preview = session.deleted_file_preview(13)
            self.assertIn("SECRET-DELETED-DATA", preview["ascii"])
            recovery = session.recover_deleted_file(13)
            self.assertEqual(recovery["data"], b'SECRET-DELETED-DATA')
            report = session.deleted_file_report(13)
            self.assertIn("inode #13", report)
            self.assertIn("best-effort", report)
        finally:
            session.close()

    def test_directory_artifacts_find_wiped_inode_names(self):
        artifacts = self.parser.scan_directory_artifacts(limit=10, name_hint="secret")
        names = {item["name"]: item for item in artifacts["items"]}
        self.assertIn("secret_folder", names)
        self.assertIn("secret.txt", names)
        self.assertEqual(names["secret_folder"]["inodeState"]["state"], "wiped")
        self.assertEqual(names["secret.txt"]["pathHint"], "secret_folder/secret.txt")

    def test_session_artifacts_find_names_and_raw_content(self):
        from web_backend import HexCorruptorSession

        session = HexCorruptorSession()
        try:
            session.open_source(self.path)
            names = session.forensic_artifacts("secret", limit=10)
            self.assertGreaterEqual(len(names["directoryEntries"]["items"]), 2)
            content = session.forensic_artifacts("secret_text", limit=10)
            self.assertEqual(content["rawMatches"]["items"][0]["offset"], 92 * 1024)
        finally:
            session.close()

    def test_session_v2_search_timeline_dossier_and_reports(self):
        from web_backend import HexCorruptorSession

        session = HexCorruptorSession()
        try:
            session.open_source(self.path)
            search = session.forensic_search("secret", limit=20)
            self.assertGreaterEqual(len(search["names"]), 2)
            self.assertGreaterEqual(len(search["content"]), 1)
            self.assertTrue(search["capabilities"]["deletedRecovery"])

            timeline = session.forensic_timeline(
                "13",
                from_value="1699990000",
                to_value="1700010000",
                event_types="deleted",
                limit=50,
            )
            event_types = {event["eventType"] for event in timeline["events"]}
            self.assertIn("deleted", event_types)
            self.assertTrue(all(event["timestampLocal"] for event in timeline["events"]))

            dossier_by_name = session.file_dossier(name="secret.txt")
            self.assertEqual(dossier_by_name["names"][0]["pathHint"], "secret_folder/secret.txt")
            self.assertEqual(dossier_by_name["inode"], 19)

            dossier_by_inode = session.file_dossier(inode=13)
            self.assertEqual(dossier_by_inode["recoverableFile"]["inode"], 13)
            self.assertGreater(len(dossier_by_inode["timeline"]), 0)

            body, content_type, filename = session.forensic_report("json", "secret")
            self.assertEqual(content_type, "application/json; charset=utf-8")
            self.assertEqual(filename, "hexcorruptor-forensics.json")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload["query"], "secret")
            self.assertGreaterEqual(len(payload["search"]["names"]), 2)

            md_body, md_type, md_filename = session.forensic_report("markdown", "secret")
            self.assertIn("text/markdown", md_type)
            self.assertEqual(md_filename, "hexcorruptor-forensics.md")
            self.assertIn("## Сводка".encode("utf-8"), md_body)
        finally:
            session.close()

    def test_lightweight_filesystem_detection_and_capabilities(self):
        from web_backend import HexCorruptorSession

        expected = {
            "ntfs": "NTFS",
            "exfat": "exFAT",
            "fat32": "FAT32",
        }
        paths = [create_boot_image(kind) for kind in expected]
        try:
            for path, kind in zip(paths, expected):
                reader = DiskReader(path, read_only=True)
                reader.open()
                try:
                    parser = detect_filesystem(reader, 0)
                    self.assertIsNotNone(parser)
                    self.assertEqual(parser.fs_name(), expected[kind])
                    self.assertGreater(len(parser.get_fs_info()), 0)
                finally:
                    reader.close()

            session = HexCorruptorSession()
            try:
                session.open_source(paths[0])
                status = session.status()
                self.assertEqual(status["filesystem"], "NTFS")
                self.assertFalse(status["capabilities"]["deletedRecovery"])
                self.assertTrue(status["capabilities"]["rawSearch"])
                with self.assertRaises(ValueError):
                    session.deleted_files()
            finally:
                session.close()
        finally:
            for path in paths:
                os.unlink(path)

    def test_capture_job_copies_source_and_writes_hash_logs(self):
        from web_backend import HexCorruptorSession

        payload = b"capture-test-payload" * 1024
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "source.bin")
            destination = os.path.join(tmp, "captured.img")
            with open(source, "wb") as handle:
                handle.write(payload)

            session = HexCorruptorSession()
            job = session.start_capture(source, destination, unmount=False)
            for _ in range(100):
                job = session.get_capture_job(job["jobId"])
                if job["status"] in {"complete", "error", "cancelled"}:
                    break
                time.sleep(0.02)

            self.assertEqual(job["status"], "complete")
            self.assertEqual(job["bytesCopied"], len(payload))
            self.assertEqual(job["sha256"], hashlib.sha256(payload).hexdigest())
            with open(destination, "rb") as handle:
                self.assertEqual(handle.read(), payload)
            self.assertTrue(os.path.exists(f"{destination}.capture.json"))
            self.assertTrue(os.path.exists(f"{destination}.capture.md"))


class TestCommandHistory(unittest.TestCase):
    """Тесты для истории команд."""

    def test_undo_redo(self):
        """Тест отмены и повтора команд."""
        history = CommandHistory()

        # Mock reader
        reader = Mock()
        reader.write = Mock()

        # Выполнить команду
        cmd = ReplaceCommand(reader, 0, b'old', b'new')
        history.execute(cmd)

        self.assertTrue(history.can_undo())
        self.assertFalse(history.can_redo())

        # Отменить
        undo_cmd = history.undo()
        self.assertEqual(undo_cmd, cmd)
        reader.write.assert_called_with(0, b'old')

        self.assertFalse(history.can_undo())
        self.assertTrue(history.can_redo())

        # Повторить
        redo_cmd = history.redo()
        self.assertEqual(redo_cmd, cmd)
        reader.write.assert_called_with(0, b'new')


if __name__ == '__main__':
    unittest.main()
