project('tpm2-client', 'c',
  version: '0.1',
  default_options: ['warning_level=3'],
)
add_languages('cpp')
conf = configuration_data()

tss2_esys_lib = dependency('tss2-esys', version: '>= 3.0.3')
tss2_mu_lib = dependency('tss2-mu', version: '>= 3.0.3')
tss2_sys_lib = dependency('tss2-sys', version: '>= 3.0.3')
tss2_tcti_device_lib = [
  dependency('tss2-tcti-device', version: '>= 3.0.3'),
]
tss2_tcti_mssim_lib = [
  dependency('tss2-tcti-mssim', version: '>= 3.0.3'),
]
tss2_tcti_swtpm_lib = [
  dependency('tss2-tcti-swtpm', version: '>= 3.0.3'),
]

#conf.set('HAVE_TSS2', '1')
#configure_file(
#  output: 'config.h',
#  configuration: conf
#)

exe = executable('main',
  sources: [
    'main.cpp',
    'NVSpaceMaster.cpp',
    'NVSpaceMaster.h',
    'ResponseCodeResolver.cpp',
    'ResponseCodeResolver.h',
    'sockets.h',
    'tcti_util.c',
    'tcti_util.h',
  ],
  install: true,
  dependencies: [
    tss2_sys_lib,
    tss2_tcti_swtpm_lib,
    tss2_tcti_mssim_lib,
    tss2_mu_lib,
  ],
)

#testproj2_src = [
#  'HashSequenceScheduler.cpp',
#  'HashSequenceScheduler.h',
#  'HashSequenceScheduler_test.cpp',
#]

test('basic', exe)
