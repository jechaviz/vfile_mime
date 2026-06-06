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
