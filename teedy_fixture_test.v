module vfile_mime

import os

struct TeedyMimeFixture {
	name       string
	probe_name string
	expected   string
}

fn test_teedy_core_mime_fixtures_detect_expected_types() {
	fixtures := [
		TeedyMimeFixture{
			name:       'document.odt'
			probe_name: 'document.odt'
			expected:   'application/vnd.oasis.opendocument.text'
		},
		TeedyMimeFixture{
			name:       'document.docx'
			probe_name: 'document.odt'
			expected:   'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
		},
		TeedyMimeFixture{
			name:       'apache.pptx'
			probe_name: 'apache.pptx'
			expected:   'application/vnd.openxmlformats-officedocument.presentationml.presentation'
		},
		TeedyMimeFixture{
			name:       'document.xlsx'
			probe_name: 'document.xlsx'
			expected:   'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
		},
		TeedyMimeFixture{
			name:       'document.txt'
			probe_name: 'document.txt'
			expected:   'text/plain'
		},
		TeedyMimeFixture{
			name:       'document.csv'
			probe_name: 'document.csv'
			expected:   'text/csv'
		},
		TeedyMimeFixture{
			name:       'udhr.pdf'
			probe_name: 'udhr.pdf'
			expected:   'application/pdf'
		},
		TeedyMimeFixture{
			name:       'apollo_portrait.jpg'
			probe_name: 'apollo_portrait.jpg'
			expected:   'image/jpeg'
		},
		TeedyMimeFixture{
			name:       'image.gif'
			probe_name: 'image.gif'
			expected:   'image/gif'
		},
		TeedyMimeFixture{
			name:       'image.png'
			probe_name: 'image.png'
			expected:   'image/png'
		},
		TeedyMimeFixture{
			name:       'document.zip'
			probe_name: 'document.zip'
			expected:   'application/zip'
		},
		TeedyMimeFixture{
			name:       'video.webm'
			probe_name: 'video.webm'
			expected:   'video/webm'
		},
		TeedyMimeFixture{
			name:       'video.mp4'
			probe_name: 'video.mp4'
			expected:   'video/mp4'
		},
	]
	for fixture in fixtures {
		path := teedy_mime_fixture_path(fixture.name)
		if path == '' {
			continue
		}
		assert detect(MimeProbe{
			name:     fixture.probe_name
			declared: octet_stream
			bytes:    os.read_bytes(path)!
		}) == fixture.expected
	}
}

fn teedy_mime_fixture_path(name string) string {
	rel := os.join_path('_refs', 'Teedy', 'docs-core', 'src', 'test', 'resources', 'file', name)
	candidates := [
		os.join_path(os.dir(os.getwd()), rel),
		os.join_path('C:\\git\\v_projects', rel),
	]
	for candidate in candidates {
		if os.exists(candidate) {
			return candidate
		}
	}
	return ''
}
