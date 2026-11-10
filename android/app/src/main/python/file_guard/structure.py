"""Bounded static structural checks for PE, ELF and Android DEX headers.

This module reads only fixed binary headers. It does not decode strings, extract
document text, unpack archives, execute files, or inspect full payload semantics.
"""
from __future__ import annotations


def _u16(data: bytes, offset: int, byteorder: str) -> int:
    return int.from_bytes(data[offset:offset + 2], byteorder=byteorder, signed=False)


def _u32(data: bytes, offset: int, byteorder: str) -> int:
    return int.from_bytes(data[offset:offset + 4], byteorder=byteorder, signed=False)


def _u64(data: bytes, offset: int, byteorder: str) -> int:
    return int.from_bytes(data[offset:offset + 8], byteorder=byteorder, signed=False)


def inspect_binary_structure(header: bytes, detected_type: str, file_size: int) -> dict:
    """Return bounded structural findings and machine-readable evidence."""
    findings = []
    status = "not_applicable"

    def flag(rule_id: str, detail: str) -> None:
        findings.append({"rule_id": rule_id, "detail": detail})

    if detected_type == "Windows executable":
        status = "checked"
        if file_size < 64 or len(header) < 64:
            flag("PE_DOS_HEADER_TRUNCATED", "Windows executable is shorter than the 64-byte DOS header.")
        else:
            pe_offset = _u32(header, 0x3C, "little")
            if pe_offset < 64 or pe_offset + 24 > file_size:
                flag("PE_HEADER_OFFSET_INVALID", "PE header offset is outside the file or overlaps the DOS header.")
            elif pe_offset + 24 > len(header):
                status = "header_outside_bounded_window"
            elif header[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                flag("PE_SIGNATURE_INVALID", "MZ header does not point to a valid PE signature.")
            else:
                coff = pe_offset + 4
                section_count = _u16(header, coff + 2, "little")
                optional_size = _u16(header, coff + 16, "little")
                optional_offset = pe_offset + 24
                if section_count == 0 or section_count > 96:
                    flag("PE_SECTION_COUNT_INVALID", "PE section count is outside the supported loader range.")
                if optional_size < 2:
                    flag("PE_OPTIONAL_HEADER_MISSING", "PE optional header is missing or too short.")
                elif optional_offset + optional_size > file_size:
                    flag("PE_OPTIONAL_HEADER_OUT_OF_BOUNDS", "PE optional header extends beyond the file.")
                elif optional_offset + 2 <= len(header):
                    magic = _u16(header, optional_offset, "little")
                    if magic not in (0x10B, 0x20B):
                        flag("PE_OPTIONAL_HEADER_MAGIC_INVALID", "PE optional-header magic is neither PE32 nor PE32+.")
                    elif optional_offset + optional_size > len(header):
                        status = "partial_optional_header"

    elif detected_type == "ELF executable":
        status = "checked"
        if file_size < 16 or len(header) < 16:
            flag("ELF_IDENT_TRUNCATED", "ELF identification header is truncated.")
        else:
            elf_class = header[4]
            data_encoding = header[5]
            ident_version = header[6]
            if elf_class not in (1, 2):
                flag("ELF_CLASS_INVALID", "ELF class is neither 32-bit nor 64-bit.")
            if data_encoding not in (1, 2):
                flag("ELF_ENDIAN_INVALID", "ELF byte order is neither little-endian nor big-endian.")
            if ident_version != 1:
                flag("ELF_IDENT_VERSION_INVALID", "ELF identification version is not current.")
            if elf_class in (1, 2) and data_encoding in (1, 2):
                byteorder = "little" if data_encoding == 1 else "big"
                expected_header = 52 if elf_class == 1 else 64
                if file_size < expected_header or len(header) < expected_header:
                    flag("ELF_HEADER_TRUNCATED", "ELF file is shorter than its declared class header.")
                else:
                    if elf_class == 1:
                        program_offset = _u32(header, 28, byteorder)
                        section_offset = _u32(header, 32, byteorder)
                        header_size = _u16(header, 40, byteorder)
                        program_entry_size = _u16(header, 42, byteorder)
                        program_count = _u16(header, 44, byteorder)
                        section_entry_size = _u16(header, 46, byteorder)
                        section_count = _u16(header, 48, byteorder)
                        min_program_entry, min_section_entry = 32, 40
                    else:
                        program_offset = _u64(header, 32, byteorder)
                        section_offset = _u64(header, 40, byteorder)
                        header_size = _u16(header, 52, byteorder)
                        program_entry_size = _u16(header, 54, byteorder)
                        program_count = _u16(header, 56, byteorder)
                        section_entry_size = _u16(header, 58, byteorder)
                        section_count = _u16(header, 60, byteorder)
                        min_program_entry, min_section_entry = 56, 64
                    if header_size != expected_header:
                        flag("ELF_HEADER_SIZE_INVALID", "ELF header-size field does not match its class.")
                    if program_count:
                        if program_entry_size < min_program_entry or program_offset == 0:
                            flag("ELF_PROGRAM_TABLE_INVALID", "ELF program-header table has invalid entry size or offset.")
                        elif program_offset + program_entry_size * program_count > file_size:
                            flag("ELF_PROGRAM_TABLE_OUT_OF_BOUNDS", "ELF program-header table extends beyond the file.")
                    if section_count:
                        if section_entry_size < min_section_entry or section_offset == 0:
                            flag("ELF_SECTION_TABLE_INVALID", "ELF section-header table has invalid entry size or offset.")
                        elif section_offset + section_entry_size * section_count > file_size:
                            flag("ELF_SECTION_TABLE_OUT_OF_BOUNDS", "ELF section-header table extends beyond the file.")

    elif detected_type == "Android DEX":
        status = "checked"
        if file_size < 0x70 or len(header) < 0x70:
            flag("DEX_HEADER_TRUNCATED", "DEX file is shorter than its 0x70-byte header.")
        else:
            version = header[4:7]
            if len(version) != 3 or not version.isdigit() or header[7] != 0:
                flag("DEX_VERSION_INVALID", "DEX magic contains an invalid version field.")
            declared_size = _u32(header, 32, "little")
            header_size = _u32(header, 36, "little")
            endian_tag = _u32(header, 40, "little")
            if declared_size != file_size:
                flag("DEX_FILE_SIZE_MISMATCH", "DEX header file-size field does not match the actual file size.")
            if header_size != 0x70:
                flag("DEX_HEADER_SIZE_INVALID", "DEX header-size field is not 0x70.")
            if endian_tag not in (0x12345678, 0x78563412):
                flag("DEX_ENDIAN_TAG_INVALID", "DEX endian tag is invalid.")

    signals = [{
        "code": "BINARY_STRUCTURE_ANOMALY",
        "severity": "medium",
        "detail": item["detail"],
        "rule_id": item["rule_id"],
    } for item in findings]
    return {
        "agent": "binary_structure",
        "status": "match" if findings else status,
        "findings": findings,
        "signals": signals,
    }
