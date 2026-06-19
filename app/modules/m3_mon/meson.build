project('m3', 'c', version: '0.1', default_options: ['warning_level=2', 'c_std=c11'])

curl_dep = dependency('libcurl', required: true)
dpdk_dep = dependency('libdpdk', required: false)

inc = include_directories('src', '../common')

sources = [
  'src/main.c',
  'src/capture.c',
  'src/flow_table.c',
  'src/host_table.c',
  'src/bloom.c',
  'src/detection.c',
  'src/alert.c',
  '../common/alert_schema.c',
  '../common/cJSON.c',
]

executable('m3', sources,
  include_directories: inc,
  dependencies: [curl_dep, dpdk_dep],
)
