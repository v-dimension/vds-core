package=solidity
$(package)_version=0.4.24
$(package)_download_path=https://github.com/ethereum/solidity/archive
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=fad18c3810bed345391df629d268cfa151fd8af99a961b94e3db0b34aa8437eb
$(package)_dependencies=native_boost

define $(package)_preprocess_cmds
  mkdir -p build/;echo $($(package)_version) > prerelease.txt; echo "e67f0147998a9e3835ed3ce8bf6a0a0c634216c5" > commit_hash.txt
endef

define $(package)_config_cmds
  cd build; cmake .. -DCMAKE_CXX_STANDARD=11 -DCMAKE_INSTALL_PREFIX=$(build_prefix) -DCMAKE_BUILD_TYPE=Release -DBoost_FOUND=1 -DTEST=0 -DBoost_INCLUDE_DIR=$(build_prefix)/include
endef

define $(package)_build_cmds
  cd build; $(MAKE) VERBOSE=2 solc
endef

define $(package)_stage_cmds
  cd build; $(MAKE) VERBOSE=1 DESTDIR=$($(package)_staging_dir) install/fast solc
endef
