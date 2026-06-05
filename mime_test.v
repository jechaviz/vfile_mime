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

fn test_detect_unknown_generic_falls_back_to_octet_stream() {
	mime := detect(MimeProbe{
		name:     'blob'
		declared: 'binary/octet-stream'
		bytes:    [u8(0x00), 0x01]
	})
	assert mime == octet_stream
}
