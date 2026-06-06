module vfile_mime

import os

pub const octet_stream = 'application/octet-stream'

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
	if starts_with(bytes, 'PK\x03\x04'.bytes()) {
		if office := detect_openxml_package(bytes) {
			return office
		}
		if odf := detect_opendocument_package(bytes) {
			return odf
		}
		return 'application/zip'
	}
	return none
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
		'png' { 'image/png' }
		'jpg', 'jpeg' { 'image/jpeg' }
		'gif' { 'image/gif' }
		'webp' { 'image/webp' }
		'tif', 'tiff' { 'image/tiff' }
		'eml' { 'message/rfc822' }
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
