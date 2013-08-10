{
  'target_defaults': {
    'cflags': [
      '-Wall',
      '-Werror',
      '-std=c++0x',
    ],
    'product_dir': 'bin',
  },
  'targets': [
    {
      'target_name': 'cloudproxy',
      'type': 'static_library',
      'variables': {
        'src': 'cloudproxy',
      },
      'sources': [
        '<(src)/cloudproxy.proto',
        '<(src)/cloud_auth.cc',
        '<(src)/cloud_auth.h',
        '<(src)/cloud_client.cc',
        '<(src)/cloud_client.h',
        '<(src)/cloud_server.cc',
        '<(src)/cloud_server.h',
        '<(src)/cloud_server_thread_data.cc',
        '<(src)/cloud_server_thread_data.h',
        '<(src)/cloud_user_manager.cc',
        '<(src)/cloud_user_manager.h',
        '<(src)/file_client.cc',
        '<(src)/file_client.h',
        '<(src)/file_server.cc',
        '<(src)/file_server.h',
        '<(src)/util.cc',
        '<(src)/util.h',
      ],
      'libraries': [
        '-lgflags',
        '-lglog',
        '-lkeyczar',
        '-lcrypto',
        '-lprotobuf',
        '-lssl',
        '-lpthread',
      ],
      'include_dirs': [
        '<(SHARED_INTERMEDIATE_DIR)',
        '.',
      ],
      'includes': [
        'build/protoc.gypi',
      ],
      'direct_dependent_settings': {
        'libraries': [
          '-lgflags',
          '-lglog',
          '-lkeyczar',
          '-lcrypto',
          '-lprotobuf',
          '-lssl',
          '-lpthread',
        ],
        'include_dirs': [
          '<(SHARED_INTERMEDIATE_DIR)',
          '.',
        ],
      },
    },
    {
      'target_name': 'tao',
      'type': 'static_library',
      'variables': {
        'src': 'tao',
      },
      'sources': [
        '<(src)/attestation.proto',
        '<(src)/hosted_programs.proto',
        '<(src)/pipe_tao_channel.h',
        '<(src)/pipe_tao_channel.cc',
        '<(src)/quote.proto',
        '<(src)/tao.h',
        '<(src)/tao_channel.h',
        '<(src)/tao_channel.cc',
        '<(src)/tao_channel_rpc.proto',
        '<(src)/tao_binary_cache.h',
      ],
      'libraries': [
        '-lgflags',
        '-lglog',
        '-lkeyczar',
        '-lcrypto',
        '-lprotobuf',
        '-lssl',
      ],
      'include_dirs': [
        '<(SHARED_INTERMEDIATE_DIR)',
        '.',
      ],
      'includes': [
        'build/protoc.gypi',
      ],
      'direct_dependent_settings': {
        'libraries': [
          '-lgflags',
          '-lglog',
          '-lkeyczar',
          '-lcrypto',
          '-lprotobuf',
          '-lssl',
        ],
        'include_dirs': [
          '<(SHARED_INTERMEDIATE_DIR)',
          '.',
        ],
      },
    },
    {
      'target_name': 'test',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/main.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'sign_acls',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/sign_acls.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'verify_acls',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/verify_acls.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'sign_pub_key',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/sign_pub_key.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'verify_pub_key',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/verify_pub_key.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'client',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/client.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'fclient',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/fclient.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'server',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/server.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [
         'cloudproxy',
         'tao',
      ],
    },
    {
      'target_name': 'fserver',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/fserver.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'cloudproxy', ],
    },
    {
      'target_name': 'hash_file',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/hash_file.cc', ],
      'include_dirs': [ '.', ],
      'libraries' : [
        '-lgflags',
        '-lglog',
        '-lkeyczar',
        '-lcrypto',
      ],
    },
    {
      'target_name': 'sign_whitelist',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/sign_whitelist.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ 'tao', ],
    },
    {
        'target_name': 'legacy_tao',
        'type': 'static_library',
        'variables': {
            'src': 'legacy_tao',
            'basejlm': '../..',
            'ac': '<(basejlm)/accessControl',
            'ch': '<(basejlm)/channels',
            'cl': '<(basejlm)/claims',
            'cm': '<(basejlm)/commonCode',
            'fp': '<(basejlm)/fileProxy',
            'kn': '<(basejlm)/keyNegoServer',
            'jb': '<(basejlm)/jlmbignum',
            'jc': '<(basejlm)/jlmcrypto',
            'pr': '<(basejlm)/protocolChannel',
            'ta': '<(basejlm)/tao',
            'tc': '<(basejlm)/tcService',
            'tp': '<(basejlm)/TPMDirect',
            'vt': '<(basejlm)/vault',
        },
        'cflags': [
            '-Wall',
            '-Werror',
            '-Wno-unknown-pragmas',
            '-Wno-format',
            '-O3',
        ],
        'libraries': [
            '-lpthread',
        ],
        'defines': [
            'LINUX',
            'FILECLIENT',
            'TEST',
            'TIXML_USE_STL',
            '__FLUSHIO__',
            'ENCRYPTTHENMAC',
        ],
        'include_dirs': [
            '.',
            '<(fp)',
            '<(cm)',
            '<(jc)',
            '<(jb)',
            '<(cl)',
            '<(ta)',
            '<(tc)',
            '<(tp)',
            '<(ch)',
            '<(pr)',
            '<(ac)',
            '<(vt)',
        ],
        'sources': [
            '<(src)/legacy_tao.h',
            '<(src)/legacy_tao.cc',
            '<(cm)/jlmUtility.cpp',
            '<(jc)/keys.cpp',
            '<(jc)/cryptoHelper.cpp',
            '<(jc)/jlmcrypto.cpp',
            '<(jc)/aesni.cpp',
            '<(jc)/sha256.cpp',
            '<(jc)/sha1.cpp',
            '<(jc)/hmacsha256.cpp',
            '<(jc)/encryptedblockIO.cpp',
            '<(jc)/modesandpadding.cpp',
            '<(ta)/taoSupport.cpp',
            '<(ta)/taoEnvironment.cpp',
            '<(ta)/taoHostServices.cpp',
            '<(ta)/taoInit.cpp',
            '<(ta)/linuxHostsupport.cpp',
            '<(ta)/trustedKeyNego.cpp',
            '<(ta)/TPMHostsupport.cpp',
            '<(tp)/vTCIDirect.cpp',
            '<(tp)/hmacsha1.cpp',
            '<(cl)/cert.cpp',
            '<(cl)/quote.cpp',
            '<(cm)/tinyxml.cpp',
            '<(cm)/tinyxmlparser.cpp',
            '<(cm)/tinystr.cpp',
            '<(cm)/tinyxmlerror.cpp',
            '<(ch)/channel.cpp',
            '<(ch)/safeChannel.cpp',
            '<(cl)/validateEvidence.cpp',
            '<(tc)/buffercoding.cpp',
            '<(tc)/tcIO.cpp',
            '<(tp)/hashprep.cpp',
            '<(cm)/logging.cpp',
	        '<(fp)/policyCert.inc',
        ],
        'dependencies': [
            '../../jlmtao.gyp:bignum_O1',
            'tao',
        ],
        'direct_dependent_settings': {
          'include_dirs': [
            '<(SHARED_INTERMEDIATE_DIR)',
            '.',
            '<(fp)',
            '<(cm)',
            '<(jc)',
            '<(jb)',
            '<(cl)',
            '<(ta)',
            '<(tc)',
            '<(tp)',
            '<(ch)',
            '<(pr)',
            '<(ac)',
            '<(vt)',
          ],
        },
        'export_dependent_settings': [
            'tao',
        ],
    },
    {
      'target_name': 'bootstrap',
      'type': 'executable',
      'variables': { 'src' : 'apps', },
      'sources': [ '<(src)/bootstrap.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [
        'legacy_tao',
      ],
    },
    
  ]
}
