package=native_boost
$(package)_version=1_66_0
$(package)_download_path=https://dl.bintray.com/boostorg/release/1.66.0/source
$(package)_file_name=boost_$($(package)_version).tar.bz2
$(package)_sha256_hash=5721818253e6a0989583192f96782c4a98eb6204965316df9f5ad75819225ca9

define $(package)_set_vars
$(package)_config_opts_release=variant=release
$(package)_config_opts_debug=variant=debug
$(package)_config_opts=--layout=system --user-config=user-config.jam
$(package)_config_opts+=threading=multi link=static -sNO_BZIP2=1 -sNO_ZLIB=1
$(package)_config_opts+=threadapi=pthread runtime-link=shared
$(package)_toolset=gcc
$(package)_config_libraries=chrono,filesystem,program_options,system,thread,test,random,regex
$(package)_cxxflags=-std=c++11 -fvisibility=hidden -fPIC
endef

define $(package)_preprocess_cmds
  echo "using $(boost_toolset_$(host_os)) : : $($(package)_cxx) : <cxxflags>\"$($(package)_cxxflags) $($(package)_cppflags)\" <linkflags>\"$($(package)_ldflags)\" <archiver>\"$(boost_archiver)\" <striper>\"$(build_STRIP)\"  <ranlib>\"$(build_RANLIB)\" <rc>\"$(build_WINDRES)\" : ;" > user-config.jam 
endef

define $(package)_config_cmds
  ./bootstrap.sh --without-icu --with-libraries=$(boost_config_libraries)
endef

define $(package)_build_cmds
  ./b2 -d2 -j4 -d1 --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) stage
endef

define $(package)_stage_cmds
  ./b2 -d0 -j4 --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) install
endef
