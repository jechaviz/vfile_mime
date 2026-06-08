module vfile_mime

import os

pub const octet_stream = 'application/octet-stream'

const msword_mime = 'application/msword'
const ms_excel_mime = 'application/vnd.ms-excel'
const ms_powerpoint_mime = 'application/vnd.ms-powerpoint'
const ole_compound_file_mime = 'application/vnd.ms-office'
const rtf_mime = 'application/rtf'
const tsv_mime = 'text/tab-separated-values'
const ole_magic = [u8(0xd0), 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
const rtf_magic = [u8(0x7b), 0x5c, 0x72, 0x74, 0x66]
const ole_free_sector = u32(0xffffffff)
const ole_end_of_chain = u32(0xfffffffe)
const ole_fat_sector = u32(0xfffffffd)

pub struct MimeProbe {
pub:
	name     string
	declared string
	bytes    []u8
}

pub fn detect(input MimeProbe) string {
	declared := normalize(input.declared)
	if !is_generic(declared) {
		return declared
	}
	if magic := detect_magic(input.bytes) {
		return magic
	}
	if ext := from_extension(input.name) {
		return ext
	}
	return octet_stream
}

pub fn is_generic(value string) bool {
	mime := normalize(value)
	return mime == '' || mime in [octet_stream, 'application/x-binary', 'binary/octet-stream']
}

pub fn detect_magic(bytes []u8) ?string {
	if starts_with(bytes, '%PDF-'.bytes()) {
		return 'application/pdf'
	}
	if starts_with(bytes, rtf_magic) {
		return rtf_mime
	}
	if starts_with(bytes, [u8(0x89), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) {
		return 'image/png'
	}
	if starts_with(bytes, [u8(0xff), 0xd8, 0xff]) {
		return 'image/jpeg'
	}
	if starts_with(bytes, 'GIF87a'.bytes()) || starts_with(bytes, 'GIF89a'.bytes()) {
		return 'image/gif'
	}
	if starts_with(bytes, 'RIFF'.bytes()) && bytes.len >= 12
		&& starts_with(bytes[8..], 'WEBP'.bytes()) {
		return 'image/webp'
	}
	if is_mp4_magic(bytes) {
		return 'video/mp4'
	}
	if is_webm_magic(bytes) {
		return 'video/webm'
	}
	if starts_with(bytes, 'PK\x03\x04'.bytes()) {
		if office := detect_openxml_package(bytes) {
			return office
		}
		if odf := detect_opendocument_package(bytes) {
			return odf
		}
		return 'application/zip'
	}
	if starts_with(bytes, ole_magic) {
		return detect_ole_compound_file(bytes)
	}
	return none
}

fn detect_ole_compound_file(bytes []u8) string {
	for name in ole_directory_names(bytes) {
		match name.to_lower() {
			'worddocument' {
				return msword_mime
			}
			'workbook', 'book' {
				return ms_excel_mime
			}
			'powerpoint document' {
				return ms_powerpoint_mime
			}
			else {}
		}
	}
	return ole_compound_file_mime
}

fn ole_directory_names(bytes []u8) []string {
	if bytes.len < 512 {
		return []
	}
	sector_shift := read_u16_le(bytes, 30)
	if sector_shift != 9 && sector_shift != 12 {
		return []
	}
	sector_size := 1 << int(sector_shift)
	first_dir_sector := read_u32_le(bytes, 48)
	if !ole_is_regular_sector(first_dir_sector) {
		return []
	}
	fat_sector_count := read_u32_le(bytes, 44)
	fat_sectors := ole_difat_sectors(bytes, sector_size, fat_sector_count)
	fat := ole_fat_entries(bytes, sector_size, fat_sectors)
	if fat.len == 0 {
		return []
	}

	mut names := []string{}
	mut seen_sectors := []u32{}
	mut sector := first_dir_sector
	for ole_is_regular_sector(sector) && names.len < 256 {
		if sector in seen_sectors {
			break
		}
		seen_sectors << sector
		offset := ole_sector_offset(bytes, sector_size, sector) or { break }
		for entry_offset := offset; entry_offset + 128 <= offset + sector_size; entry_offset += 128 {
			name := ole_directory_entry_name(bytes[entry_offset..entry_offset + 128])
			if name != '' {
				names << name
			}
		}
		if int(sector) >= fat.len {
			break
		}
		next_sector := fat[int(sector)]
		if next_sector == ole_end_of_chain {
			break
		}
		sector = next_sector
	}
	return names
}

fn ole_difat_sectors(bytes []u8, sector_size int, fat_sector_count u32) []u32 {
	mut sectors := []u32{}
	fat_sector_limit := capped_u32_to_int(fat_sector_count, ole_regular_sector_count(bytes,
		sector_size))
	for i in 0 .. 109 {
		if sectors.len >= fat_sector_limit {
			return sectors
		}
		sector := read_u32_le(bytes, 76 + (i * 4))
		if ole_is_regular_sector(sector) {
			sectors << sector
		}
	}

	mut difat_sector := read_u32_le(bytes, 68)
	difat_sector_limit := capped_u32_to_int(read_u32_le(bytes, 72), ole_regular_sector_count(bytes,
		sector_size))
	mut seen_difat_sectors := []u32{}
	for _ in 0 .. difat_sector_limit {
		if sectors.len >= fat_sector_limit || !ole_is_regular_sector(difat_sector)
			|| difat_sector in seen_difat_sectors {
			break
		}
		seen_difat_sectors << difat_sector
		offset := ole_sector_offset(bytes, sector_size, difat_sector) or { break }
		entries_per_sector := (sector_size / 4) - 1
		for i in 0 .. entries_per_sector {
			if sectors.len >= fat_sector_limit {
				return sectors
			}
			sector := read_u32_le(bytes, offset + (i * 4))
			if ole_is_regular_sector(sector) {
				sectors << sector
			}
		}
		difat_sector = read_u32_le(bytes, offset + (entries_per_sector * 4))
	}
	return sectors
}

fn ole_fat_entries(bytes []u8, sector_size int, fat_sectors []u32) []u32 {
	mut fat := []u32{}
	for sector in fat_sectors {
		offset := ole_sector_offset(bytes, sector_size, sector) or { continue }
		for entry_offset := offset; entry_offset + 4 <= offset + sector_size; entry_offset += 4 {
			fat << read_u32_le(bytes, entry_offset)
		}
	}
	return fat
}

fn ole_sector_offset(bytes []u8, sector_size int, sector u32) ?int {
	if !ole_is_regular_sector(sector) || bytes.len < 512 {
		return none
	}
	if sector >= u32(ole_regular_sector_count(bytes, sector_size)) {
		return none
	}
	return 512 + (int(sector) * sector_size)
}

fn ole_regular_sector_count(bytes []u8, sector_size int) int {
	if bytes.len < 512 || sector_size <= 0 {
		return 0
	}
	return (bytes.len - 512) / sector_size
}

fn capped_u32_to_int(value u32, cap int) int {
	if cap <= 0 {
		return 0
	}
	if value > u32(cap) {
		return cap
	}
	return int(value)
}

fn ole_is_regular_sector(sector u32) bool {
	return sector < 0xfffffff0
}

fn ole_directory_entry_name(entry []u8) string {
	if entry.len < 128 {
		return ''
	}
	name_len := int(read_u16_le(entry, 64))
	if name_len < 2 || name_len > 64 {
		return ''
	}
	mut name := []u8{}
	for offset := 0; offset + 1 < name_len - 2; offset += 2 {
		if entry[offset + 1] == 0 && entry[offset] != 0 {
			name << entry[offset]
		}
	}
	return name.bytestr()
}

fn detect_openxml_package(bytes []u8) ?string {
	text := bytes.bytestr()
	if !text.contains('[Content_Types].xml') {
		return none
	}
	if text.contains('word/document.xml')
		|| text.contains('application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml') {
		return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
	}
	if text.contains('ppt/presentation.xml') || text.contains('ppt/slides/slide')
		|| text.contains('application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml') {
		return 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
	}
	if text.contains('xl/workbook.xml')
		|| text.contains('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml') {
		return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
	}
	return none
}

fn detect_opendocument_package(bytes []u8) ?string {
	text := bytes.bytestr()
	if !text.contains('mimetypeapplication/vnd.oasis.opendocument.') {
		return none
	}
	if text.contains('mimetypeapplication/vnd.oasis.opendocument.text') {
		return 'application/vnd.oasis.opendocument.text'
	}
	if text.contains('mimetypeapplication/vnd.oasis.opendocument.spreadsheet') {
		return 'application/vnd.oasis.opendocument.spreadsheet'
	}
	if text.contains('mimetypeapplication/vnd.oasis.opendocument.presentation') {
		return 'application/vnd.oasis.opendocument.presentation'
	}
	return none
}

pub fn from_extension(name string) ?string {
	ext := os.file_ext(name).trim_left('.').to_lower()
	return match ext {
		'pdf' { 'application/pdf' }
		'txt', 'log' { 'text/plain' }
		'md' { 'text/markdown' }
		'html', 'htm' { 'text/html' }
		'xml' { 'application/xml' }
		'json' { 'application/json' }
		'csv' { 'text/csv' }
		'tsv' { tsv_mime }
		'rtf' { rtf_mime }
		'png' { 'image/png' }
		'jpg', 'jpeg' { 'image/jpeg' }
		'gif' { 'image/gif' }
		'webp' { 'image/webp' }
		'tif', 'tiff' { 'image/tiff' }
		'mp4', 'm4v' { 'video/mp4' }
		'webm' { 'video/webm' }
		'eml' { 'message/rfc822' }
		'doc', 'dot' { msword_mime }
		'xls', 'xlt', 'xla' { ms_excel_mime }
		'ppt', 'pps', 'pot' { ms_powerpoint_mime }
		'docx' { 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }
		'pptx' { 'application/vnd.openxmlformats-officedocument.presentationml.presentation' }
		'xlsx' { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }
		'odt' { 'application/vnd.oasis.opendocument.text' }
		'ods' { 'application/vnd.oasis.opendocument.spreadsheet' }
		'odp' { 'application/vnd.oasis.opendocument.presentation' }
		'zip' { 'application/zip' }
		else { none }
	}
}

fn normalize(value string) string {
	return value.all_before(';').trim_space().to_lower()
}

fn starts_with(bytes []u8, prefix []u8) bool {
	if bytes.len < prefix.len {
		return false
	}
	for i, expected in prefix {
		if bytes[i] != expected {
			return false
		}
	}
	return true
}

fn is_mp4_magic(bytes []u8) bool {
	return bytes.len >= 12 && bytes[4..8].bytestr() == 'ftyp'
}

fn is_webm_magic(bytes []u8) bool {
	if !starts_with(bytes, [u8(0x1a), 0x45, 0xdf, 0xa3]) {
		return false
	}
	limit := if bytes.len < 4096 { bytes.len } else { 4096 }
	return bytes[..limit].bytestr().contains('webm')
}

fn read_u16_le(bytes []u8, offset int) u16 {
	return u16(bytes[offset]) | (u16(bytes[offset + 1]) << 8)
}

fn read_u32_le(bytes []u8, offset int) u32 {
	b0 := u32(bytes[offset])
	b1 := u32(bytes[offset + 1]) << 8
	b2 := u32(bytes[offset + 2]) << 16
	b3 := u32(bytes[offset + 3]) << 24
	return b0 | b1 | b2 | b3
}
