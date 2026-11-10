import unittest

from file_guard.structure import inspect_binary_structure
from file_guard.engine import scan_bytes, scan_stream
from io import BytesIO


class BinaryStructureTests(unittest.TestCase):
    def valid_pe(self):
        data = bytearray(512)
        data[:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\x00\x00"
        coff = 0x84
        data[coff:coff + 2] = (0x8664).to_bytes(2, "little")
        data[coff + 2:coff + 4] = (1).to_bytes(2, "little")
        data[coff + 16:coff + 18] = (0xF0).to_bytes(2, "little")
        data[0x98:0x9A] = (0x20B).to_bytes(2, "little")
        return bytes(data)

    def valid_elf64(self):
        data = bytearray(64)
        data[:4] = b"\x7fELF"
        data[4:7] = bytes((2, 1, 1))
        data[16:18] = (2).to_bytes(2, "little")
        data[18:20] = (62).to_bytes(2, "little")
        data[20:24] = (1).to_bytes(4, "little")
        data[52:54] = (64).to_bytes(2, "little")
        data[54:56] = (56).to_bytes(2, "little")
        data[58:60] = (64).to_bytes(2, "little")
        return bytes(data)

    def valid_dex(self):
        data = bytearray(0x70)
        data[:8] = b"dex\n035\x00"
        data[32:36] = (0x70).to_bytes(4, "little")
        data[36:40] = (0x70).to_bytes(4, "little")
        data[40:44] = (0x12345678).to_bytes(4, "little")
        return bytes(data)

    def test_valid_pe_elf_and_dex_headers_have_no_structural_findings(self):
        cases = [
            (self.valid_pe(), "Windows executable"),
            (self.valid_elf64(), "ELF executable"),
            (self.valid_dex(), "Android DEX"),
        ]
        for payload, kind in cases:
            with self.subTest(kind=kind):
                report = inspect_binary_structure(payload[:4096], kind, len(payload))
                self.assertEqual(report["findings"], [])

    def test_malformed_pe_header_is_a_review_signal(self):
        payload = bytearray(self.valid_pe())
        payload[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
        report = inspect_binary_structure(bytes(payload[:4096]), "Windows executable", len(payload))
        self.assertIn("PE_HEADER_OFFSET_INVALID", [item["rule_id"] for item in report["findings"]])
        result = scan_bytes(bytes(payload), "sample.exe")
        self.assertEqual(result.verdict, "Needs review")
        self.assertIn("BINARY_STRUCTURE_ANOMALY", [item["code"] for item in result.signals])

    def test_malformed_elf_and_dex_headers_are_detected(self):
        elf = bytearray(self.valid_elf64())
        elf[4] = 3
        elf_report = inspect_binary_structure(bytes(elf), "ELF executable", len(elf))
        self.assertIn("ELF_CLASS_INVALID", [item["rule_id"] for item in elf_report["findings"]])

        dex = bytearray(self.valid_dex())
        dex[36:40] = (0x60).to_bytes(4, "little")
        dex_report = inspect_binary_structure(bytes(dex), "Android DEX", len(dex))
        self.assertIn("DEX_HEADER_SIZE_INVALID", [item["rule_id"] for item in dex_report["findings"]])

    def test_stream_and_bytes_scans_agree_on_structural_findings(self):
        payload = bytearray(self.valid_pe())
        payload[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
        direct = scan_bytes(bytes(payload), "sample.exe")
        streamed = scan_stream(BytesIO(bytes(payload)), "sample.exe")
        self.assertEqual(direct.sha256, streamed.sha256)
        self.assertEqual(direct.verdict, streamed.verdict)
        self.assertEqual(
            [item["rule_id"] for item in next(x for x in direct.agent_trace if x["agent"] == "binary_structure")["findings"]],
            [item["rule_id"] for item in next(x for x in streamed.agent_trace if x["agent"] == "binary_structure")["findings"]],
        )


if __name__ == "__main__":
    unittest.main()
