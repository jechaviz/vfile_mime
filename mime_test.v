module vfile_mime

fn test_detect_keeps_specific_declared_mime() {
	mime := detect(MimeProbe{
		name:     'scan.pdf'
		declared: 'text/plain; charset=utf-8'
		bytes:    '%PDF-1.7'.bytes()
	})
	assert mime == 'text/plain'
}

fn test_detect_pdf_magic_for_generic_mime() {
	mime := detect(MimeProbe{
		name:     'scan.bin'
		declared: 'application/octet-stream'
		bytes:    '%PDF-1.7'.bytes()
	})
	assert mime == 'application/pdf'
}

fn test_detect_rtf_magic_for_generic_mime() {
	mime := detect(MimeProbe{
		name:     'notes.bin'
		declared: 'application/octet-stream'
		bytes:    r'{\rtf1\ansi hello}'.bytes()
	})
	assert mime == 'application/rtf'
}

fn test_detect_extension_for_generic_mime_when_magic_unknown() {
	mime := detect(MimeProbe{
		name:     'report.docx'
		declared: ''
		bytes:    'body'.bytes()
	})
	assert mime == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}

fn test_detect_openxml_magic_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'blob'
		declared: 'application/octet-stream'
		bytes:    openxml_probe_bytes('[Content_Types].xml word/document.xml')
	}) == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    openxml_probe_bytes('[Content_Types].xml ppt/presentation.xml ppt/slides/slide1.xml')
	}) == 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    openxml_probe_bytes('[Content_Types].xml xl/workbook.xml')
	}) == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
}

fn test_detect_opendocument_magic_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    odf_probe_bytes('application/vnd.oasis.opendocument.text')
	}) == 'application/vnd.oasis.opendocument.text'
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    odf_probe_bytes('application/vnd.oasis.opendocument.presentation')
	}) == 'application/vnd.oasis.opendocument.presentation'
}

fn test_detect_ole_word_magic_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    ole_probe_bytes(['Root Entry', 'WordDocument', '1Table'])
	}) == 'application/msword'
}

fn test_detect_ole_excel_magic_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'blob'
		declared: 'application/octet-stream'
		bytes:    ole_probe_bytes(['Root Entry', 'Workbook'])
	}) == 'application/vnd.ms-excel'
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    ole_probe_bytes(['Root Entry', 'Book'])
	}) == 'application/vnd.ms-excel'
}

fn test_detect_ole_powerpoint_magic_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    ole_probe_bytes(['Root Entry', 'PowerPoint Document', 'Current User'])
	}) == 'application/vnd.ms-powerpoint'
}

fn test_detect_ole_magic_falls_back_to_generic_office_mime() {
	assert detect(MimeProbe{
		name:     'blob'
		declared: ''
		bytes:    ole_probe_bytes(['Root Entry', 'SummaryInformation'])
	}) == 'application/vnd.ms-office'
}

fn test_detect_legacy_office_extensions_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'report.doc'
		declared: ''
		bytes:    'body'.bytes()
	}) == 'application/msword'
	assert detect(MimeProbe{
		name:     'budget.xls'
		declared: ''
		bytes:    'body'.bytes()
	}) == 'application/vnd.ms-excel'
	assert detect(MimeProbe{
		name:     'deck.ppt'
		declared: ''
		bytes:    'body'.bytes()
	}) == 'application/vnd.ms-powerpoint'
}

fn test_detect_rtf_extension_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'notes.rtf'
		declared: ''
		bytes:    'body'.bytes()
	}) == 'application/rtf'
}

fn test_detect_delimited_text_extensions_for_generic_mime() {
	assert detect(MimeProbe{
		name:     'rows.csv'
		declared: ''
		bytes:    'a,b\n1,2\n'.bytes()
	}) == 'text/csv'
	assert detect(MimeProbe{
		name:     'rows.tsv'
		declared: ''
		bytes:    'a\tb\n1\t2\n'.bytes()
	}) == 'text/tab-separated-values'
}

fn test_detect_unknown_generic_falls_back_to_octet_stream() {
	mime := detect(MimeProbe{
		name:     'blob'
		declared: 'binary/octet-stream'
		bytes:    [u8(0x00), 0x01]
	})
	assert mime == octet_stream
}

fn openxml_probe_bytes(names string) []u8 {
	mut out := 'PK\x03\x04'.bytes()
	out << names.bytes()
	return out
}

fn odf_probe_bytes(mime string) []u8 {
	mut out := 'PK\x03\x04mimetype'.bytes()
	out << mime.bytes()
	return out
}

fn ole_probe_bytes(names []string) []u8 {
	mut out := []u8{len: 1536, init: 0}
	for i, value in ole_magic {
		out[i] = value
	}
	write_u16_le(mut out, 30, 9)
	write_u32_le(mut out, 44, 1)
	write_u32_le(mut out, 48, 1)
	write_u32_le(mut out, 76, 0)

	fat_offset := 512
	write_u32_le(mut out, fat_offset, ole_fat_sector)
	write_u32_le(mut out, fat_offset + 4, ole_end_of_chain)
	for entry_offset := fat_offset + 8; entry_offset + 4 <= fat_offset + 512; entry_offset += 4 {
		write_u32_le(mut out, entry_offset, ole_free_sector)
	}

	directory_offset := 1024
	for i, name in names {
		if i >= 4 {
			break
		}
		write_ole_directory_entry(mut out, directory_offset + (i * 128), name)
	}
	return out
}

fn write_ole_directory_entry(mut bytes []u8, offset int, name string) {
	mut name_len := name.len
	if name_len > 31 {
		name_len = 31
	}
	for i in 0 .. name_len {
		bytes[offset + (i * 2)] = name[i]
	}
	write_u16_le(mut bytes, offset + 64, u16((name_len + 1) * 2))
	bytes[offset + 66] = 2
}

fn write_u16_le(mut bytes []u8, offset int, value u16) {
	bytes[offset] = u8(value & 0xff)
	bytes[offset + 1] = u8(value >> 8)
}

fn write_u32_le(mut bytes []u8, offset int, value u32) {
	bytes[offset] = u8(value & 0xff)
	bytes[offset + 1] = u8((value >> 8) & 0xff)
	bytes[offset + 2] = u8((value >> 16) & 0xff)
	bytes[offset + 3] = u8((value >> 24) & 0xff)
}
