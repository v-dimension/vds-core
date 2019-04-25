DIST_SUBDIRS = secp256k1 snark univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS) -DETH_FATDB=1 $(PIC_FLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS) -DQTUM_BUILD $(PIC_FLAGS)

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
VDS_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS) -I$(srcdir)/cpp-ethereum/utils

VDS_INCLUDES += -I$(srcdir)/secp256k1/include
VDS_INCLUDES += -I$(srcdir)/snark
VDS_INCLUDES += -I$(srcdir)/snark/libsnark
VDS_INCLUDES += -I$(srcdir)/univalue/include
VDS_INCLUDES += -I$(srcdir)/cpp-ethereum

LIBVDS_SERVER=libvds_server.a
LIBVDS_WALLET=libvds_wallet.a
LIBVDS_COMMON=libvds_common.a
LIBVDS_SQLITE=libvds_sqlite3.a
LIBVDS_CLI=libvds_cli.a
LIBVDS_UTIL=libvds_util.a
LIBVDS_CONSENSUS=libvds_consensus.a
if BUILD_BITCOIN_LIBS
LIBVDSCONSENSUS=libvdsconsensus.la
endif
LIBVDS_CRYPTO=crypto/libvds_crypto.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBSNARK=snark/libsnark.a
LIBUNIVALUE=univalue/libunivalue.la
LIBCRYPTOPP=cryptopp/libcryptopp.a
LIBVDS=libvds.a

$(LIBSECP256K1): $(LIBSNARK) $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

LIBSNARK_CXXFLAGS = $(AM_CXXFLAGS) $(PIC_FLAGS) -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1 -fstack-protector-all
LIBSNARK_CONFIG_FLAGS = CURVE=ALT_BN128 NO_PROCPS=1 NO_DOCS=1 STATIC=1 NO_SUPERCOP=1 FEATUREFLAGS=-DMONTGOMERY_OUTPUT NO_COPY_DEPINST=1 NO_COMPILE_LIBGTEST=1
if HAVE_OPENMP
LIBSNARK_CONFIG_FLAGS += MULTICORE=1
endif
if TARGET_DARWIN
LIBSNARK_CONFIG_FLAGS += PLATFORM=darwin
endif

$(LIBSNARK): $(wildcard snark/src/*)
	$(AM_V_at) CC="$(CC)" CXX="$(CXX)" AR="$(AR)" CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64"

libsnark-tests: $(wildcard snark/src/*)
	$(AM_V_at) CC="$(CC)" CXX="$(CXX)" AR="$(AR)" CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ check DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64"

$(LIBUNIVALUE): $(wildcard univalue/lib/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C univalue/

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES = \
  $(LIBVDS_CRYPTO) \
  $(LIBVDS_UTIL) \
  $(LIBVDS_SQLITE) \
  $(LIBVDS_COMMON) \
  $(LIBVDS_SERVER) \
  $(LIBVDS_CLI) \
  $(LIBVDS_CONSENSUS) \
  $(LIBVDS_LIGHTNODE) \
  $(LIBVDS)

if ENABLE_WALLET
VDS_INCLUDES += $(BDB_CPPFLAGS)
EXTRA_LIBRARIES += $(LIBVDS_WALLET)
endif
if ENABLE_ZMQ
EXTRA_LIBRARIES += $(LIBVDS_ZMQ)
endif
if ENABLE_PROTON
EXTRA_LIBRARIES += $(LIBVDS_PROTON)
endif

lib_LTLIBRARIES = $(LIBVDSCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =

if BUILD_BITCOIND
  bin_PROGRAMS += vdsd 
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += vds-cli vds-tx
endif

LIBVDS_H = \
  vds/IncrementalMerkleTree.hpp \
  vds/NoteEncryption.hpp \
  vds/Address.hpp \
  vds/JoinSplit.hpp \
  vds/Note.hpp \
  vds/prf.h \
  vds/Proof.hpp \
  vds/util.h \
  vds/Vds.h \
  vds/zip32.h

.PHONY: FORCE check-symbols check-security
# bitcoin core #
VDS_CORE_H = \
  addressindex.h \
  spentindex.h \
  addrman.h \
  alert.h \
  amount.h \
  amqp/amqpabstractnotifier.h \
  amqp/amqpconfig.h \
  amqp/amqpnotificationinterface.h \
  amqp/amqppublishnotifier.h \
  amqp/amqpsender.h \
  arith_uint256.h \
  asyncrpcoperation.h \
  asyncrpcqueue.h \
  activemasternode.h \
  masternode.h \
  base58.h \
  bech32.h \
  bip38_key.h \
  bloom.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  clue.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/params.h \
  consensus/validation.h \
  contract.h \
  contractabi.h \
  contractman.h \
  core_io.h \
  core_memusage.h \
  crypto/pbkdf2.h \
  fs.h \
  vib.h\
  eccryptoverify.h \
  deprecation.h \
  ecwrapper.h \
  flat-database.h \
  hash.h \
  httprpc.h \
  httpserver.h \
  init.h \
  dsnotificationinterface.h \
  key.h \
  key_io.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  masternode.h \
  masternode-payments.h \
  masternode-sync.h \
  masternodeman.h \
  masternodeconfig.h \
  masternodestatistic.h\
  memusage.h \
  merkleblock.h \
  messagesigner.h \
  metrics.h \
  mruset.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netfulfilledman.h \
  noui.h \
  paymentdisclosure.h \
  paymentdisclosuredb.h \
  policy/fees.h \
  policy/feerate.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  prevector.h \
  primitives/block.h \
  primitives/transaction.h \
  protocol.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  scheduler.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  serialize.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/pagelocker.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  tinyformat.h \
  torcontrol.h \
  transaction_builder.h \
  txdb.h \
  txmempool.h \
  cluedb.h \
  txdestinationtool.h \
  addb.h \
  ui_interface.h \
  uint256.h \
  uint252.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utilstrencodings.h \
  utiltime.h \
  validation.h \
  validationinterface.h \
  version.h \
  versionbits.h \
  sqlitewrapper.h \
  wallet/asyncrpcoperation_sendmany.h \
  wallet/asyncrpcoperation_shieldcoinbase.h \
  wallet/bip39_mnemonic.h \
  wallet/bip39_words_english.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  qtum/qtumstate.h \
  qtum/qtumtransaction.h \
  qtum/qtumDGP.h \
  qtum/storageresults.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	$(abs_top_srcdir)


libvds_util_a-clientversion.$(OBJEXT): obj/build.h

#libvds_sqlite3.a
libvds_sqlite3_a_CFLAGS = $(AM_CFLAGS) $(PIC_FLAGS) -D_HAVE_SQLITE_CONFIG_H -DBUILD_sqlite -DNDEBUG  -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION=1   -DSQLITE_TEMP_STORE=1
libvds_sqlite3_a_SOURCES = sqlite3.c

# server: vdsd
libvds_server_a_CPPFLAGS = $(VDS_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS) $(PROTOBUF_CFLAGS) 
LIBVDS_SERVER_A_SOURCES = \
  sendalert.cpp \
  addrman.cpp \
  addrdb.cpp \
  alert.cpp \
  alertkeys.h \
  asyncrpcoperation.cpp \
  asyncrpcqueue.cpp \
  bloom.cpp \
  chain.cpp \
  checkpoints.cpp \
  clue.cpp \
  cluedb.cpp \
  deprecation.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dsnotificationinterface.cpp \
  dbwrapper.cpp \
  masternode.cpp \
  masternode-payments.cpp \
  masternode-sync.cpp \
  masternodeconfig.cpp \
  masternodeman.cpp \
  masternodestatistic.cpp\
  merkleblock.cpp \
  metrics.cpp \
  messagesigner.cpp \
  consensus/merkle.cpp \
  net.cpp \
  netfulfilledman.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/feerate.cpp \
  policy/policy.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/masternode.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/ad.cpp \
  rpc/masternode.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  sendalert.cpp \
  tandiadb.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txdestinationtool.cpp \
  addb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  qtum/qtumstate.cpp \
  qtum/qtumtransaction.cpp \
  qtum/qtumDGP.cpp \
  qtum/storageresults.cpp


libvds_server_a_SOURCES = \
  $(LIBVDS_SERVER_A_SOURCES) \
  $(GENERATED_DEP_FILES) \
  $(VDS_CORE_H) \
  $(LIBVDS_H)

libvds_server_a_LIBADD = $(LIBVDS_SQLITE) $(LIBVDS)

if ENABLE_ZMQ
LIBVDS_ZMQ=libvds_zmq.a

libvds_zmq_a_CPPFLAGS = $(VDS_INCLUDES) $(ZMQ_CFLAGS)
libvds_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif

if ENABLE_PROTON
LIBVDS_PROTON=libvds_proton.a

libvds_proton_a_CPPFLAGS = $(VDS_INCLUDES)
libvds_proton_a_SOURCES = \
  amqp/amqpabstractnotifier.cpp \
  amqp/amqpnotificationinterface.cpp \
  amqp/amqppublishnotifier.cpp
endif

# wallet: vdsd, but only linked when wallet enabled
libvds_wallet_a_CPPFLAGS = $(VDS_INCLUDES)
libvds_wallet_a_SOURCES = \
  ui_interface.cpp \
  zcbenchmarks.cpp \
  zcbenchmarks.h \
  activemasternode.cpp \
  contract.cpp \
  contractabi.cpp \
  contractman.cpp \
  masternode.cpp \
  masternodeman.cpp \
  masternodestatistic.cpp\
  masternodeconfig.cpp \
  masternode-sync.cpp \
  masternode-payments.cpp \
  base58.cpp \
  bip38_key.cpp \
  rpc/blockchain.cpp \
  rpc/misc.cpp \
  rpc/masternode.cpp \
  wallet/asyncrpcoperation_sendmany.cpp \
  wallet/asyncrpcoperation_shieldcoinbase.cpp \
  wallet/bip39_mnemonic.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  paymentdisclosure.cpp \
  paymentdisclosuredb.cpp \
  wallet/rpcdisclosure.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  $(VDS_CORE_H) \
  $(LIBVDS_H)

libvds_wallet_a_LIBADD = $(LIBVDS)

# crypto primitives library
crypto_libvds_crypto_a_CPPFLAGS = $(BITCOIN_CONFIG_INCLUDES)
crypto_libvds_crypto_a_CXXFLAGS = $(AM_CXXFLAGS)
crypto_libvds_crypto_a_CFLAGS = $(AM_CXXFLAGS)
crypto_libvds_crypto_a_SOURCES = \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/equihash.cpp \
  crypto/equihash.h \
  crypto/equihash.tcc \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/scrypt.cpp \
  crypto/scrypt.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  cpp-ethereum/utils/libscrypt/b64.c \
  cpp-ethereum/utils/libscrypt/b64.h \
  cpp-ethereum/utils/libscrypt/crypto-mcf.c \
  cpp-ethereum/utils/libscrypt/crypto_scrypt-check.c \
  cpp-ethereum/utils/libscrypt/crypto_scrypt-hash.c \
  cpp-ethereum/utils/libscrypt/crypto_scrypt-hexconvert.c \
  cpp-ethereum/utils/libscrypt/crypto_scrypt-hexconvert.h \
  cpp-ethereum/utils/libscrypt/crypto_scrypt-nosse.c \
  cpp-ethereum/utils/libscrypt/crypto-scrypt-saltgen.c \
  cpp-ethereum/utils/libscrypt/libscrypt.h \
  cpp-ethereum/utils/libscrypt/sha256.c \
  cpp-ethereum/utils/libscrypt/sha256.h \
  cpp-ethereum/utils/libscrypt/slowequals.c \
  cpp-ethereum/utils/libscrypt/slowequals.h \
  cpp-ethereum/utils/libscrypt/sysendian.h \
  support/cleanse.cpp 

if USE_ASM
crypto_libvds_crypto_a_SOURCES += crypto/sha256_sse4.cpp
endif

libvds_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(VDS_INCLUDES)
libvds_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvds_consensus_a_SOURCES = \
  crypto/equihash.cpp \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  eccryptoverify.cpp \
  ecwrapper.cpp \
  hash.cpp \
  primitives/transaction.cpp \
  pubkey.cpp \
  script/vdsconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  uint256.cpp \
  utilstrencodings.cpp

# common: shared between vdsd and non-server tools
libvds_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(VDS_INCLUDES) -DQTUM_BUILD
libvds_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(PIC_FLAGS)
libvds_common_a_LIBADD = $(LIBSECP256K1)
libvds_common_a_CFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(PIC_FLAGS) -std=c99
libvds_common_a_SOURCES = \
  arith_uint256.cpp \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  eccryptoverify.cpp \
  ecwrapper.cpp \
  hash.cpp \
  key.cpp \
  key_io.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  protocol.cpp \
  pubkey.cpp \
  scheduler.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/sign.cpp \
  script/standard.cpp \
  transaction_builder.cpp \
  cpp-ethereum/libdevcore/Base64.cpp \
  cpp-ethereum/libdevcore/Base64.h \
  cpp-ethereum/libdevcore/Common.cpp \
  cpp-ethereum/libdevcore/Common.h \
  cpp-ethereum/libdevcore/CommonData.cpp \
  cpp-ethereum/libdevcore/CommonData.h \
  cpp-ethereum/libdevcore/CommonIO.cpp \
  cpp-ethereum/libdevcore/CommonIO.h \
  cpp-ethereum/libdevcore/CommonJS.cpp \
  cpp-ethereum/libdevcore/CommonJS.h \
  cpp-ethereum/libdevcore/FileSystem.cpp \
  cpp-ethereum/libdevcore/FileSystem.h \
  cpp-ethereum/libdevcore/FixedHash.cpp \
  cpp-ethereum/libdevcore/FixedHash.h \
  cpp-ethereum/libdevcore/Guards.cpp \
  cpp-ethereum/libdevcore/Guards.h \
  cpp-ethereum/libdevcore/Hash.cpp \
  cpp-ethereum/libdevcore/Hash.h \
  cpp-ethereum/libdevcore/Log.cpp \
  cpp-ethereum/libdevcore/Log.h \
  cpp-ethereum/libdevcore/MemoryDB.cpp \
  cpp-ethereum/libdevcore/MemoryDB.h \
  cpp-ethereum/libdevcore/OverlayDB.cpp \
  cpp-ethereum/libdevcore/OverlayDB.h \
  cpp-ethereum/libdevcore/RLP.cpp \
  cpp-ethereum/libdevcore/RLP.h \
  cpp-ethereum/libdevcore/SHA3.cpp \
  cpp-ethereum/libdevcore/SHA3.h \
  cpp-ethereum/libdevcore/TransientDirectory.cpp \
  cpp-ethereum/libdevcore/TransientDirectory.h \
  cpp-ethereum/libdevcore/TrieCommon.cpp \
  cpp-ethereum/libdevcore/TrieCommon.h \
  cpp-ethereum/libdevcore/Worker.cpp \
  cpp-ethereum/libdevcore/Worker.h \
  cpp-ethereum/libevm/ExtVMFace.cpp \
  cpp-ethereum/libevm/ExtVMFace.h \
  cpp-ethereum/libevm/VM.cpp \
  cpp-ethereum/libevm/VM.h \
  cpp-ethereum/libevm/VMOpt.cpp \
  cpp-ethereum/libevm/VMCalls.cpp \
  cpp-ethereum/libevm/VMFactory.cpp \
  cpp-ethereum/libevm/VMFactory.h \
  cpp-ethereum/libevmcore/Instruction.cpp \
  cpp-ethereum/libevmcore/Instruction.h \
  cpp-ethereum/libevmcore/Exceptions.h \
  cpp-ethereum/libevmcore/EVMSchedule.h \
  cpp-ethereum/libethereum/Account.cpp \
  cpp-ethereum/libethereum/Defaults.cpp \
  cpp-ethereum/libethereum/GasPricer.cpp \
  cpp-ethereum/libethereum/State.cpp \
  cpp-ethereum/libethcore/ABI.cpp \
  cpp-ethereum/libethcore/ChainOperationParams.cpp \
  cpp-ethereum/libethcore/Common.cpp \
  cpp-ethereum/libethcore/ICAP.cpp \
  cpp-ethereum/libethcore/Precompiled.cpp \
  cpp-ethereum/libdevcore/TrieDB.cpp \
  cpp-ethereum/libdevcrypto/Common.cpp \
  cpp-ethereum/libdevcrypto/CryptoPP.cpp \
  cpp-ethereum/libdevcrypto/AES.cpp \
  cpp-ethereum/libdevcrypto/ECDHE.cpp \
  cpp-ethereum/libethashseal/GenesisInfo.cpp \
  cpp-ethereum/libethereum/ChainParams.cpp \
  cpp-ethereum/libethcore/Transaction.cpp \
  cpp-ethereum/libethereum/Transaction.cpp \
  cpp-ethereum/libethereum/Executive.cpp \
  cpp-ethereum/libethereum/ExtVM.cpp \
  cpp-ethereum/libethereum/Block.cpp \
  cpp-ethereum/libethereum/BlockChain.cpp \
  cpp-ethereum/libethereum/BlockDetails.cpp \
  cpp-ethereum/libethereum/TransactionQueue.cpp \
  cpp-ethereum/libethereum/BlockQueue.cpp \
  cpp-ethereum/libethcore/BlockHeader.cpp \
  cpp-ethereum/libdevcore/RLP.cpp \
  cpp-ethereum/libethereum/TransactionReceipt.cpp \
  cpp-ethereum/libethcore/SealEngine.cpp \
  cpp-ethereum/libdevcore/TrieHash.cpp \
  cpp-ethereum/libethereum/GenesisInfo.cpp \
  cpp-ethereum/libethashseal/Ethash.cpp \
  cpp-ethereum/libethashseal/EthashCPUMiner.cpp \
  cpp-ethereum/libethashseal/EthashAux.cpp \
  cpp-ethereum/libethashseal/EthashProofOfWork.cpp \
  cpp-ethereum/libethereum/Account.h \
  cpp-ethereum/libethereum/Defaults.h \
  cpp-ethereum/libethereum/GasPricer.h \
  cpp-ethereum/libethereum/State.h \
  cpp-ethereum/libethcore/ABI.h \
  cpp-ethereum/libethcore/ChainOperationParams.h \
  cpp-ethereum/libethcore/Common.h \
  cpp-ethereum/libethcore/ICAP.h \
  cpp-ethereum/libethcore/Precompiled.h \
  cpp-ethereum/libdevcore/TrieDB.h \
  cpp-ethereum/libdevcrypto/Common.h \
  cpp-ethereum/libdevcrypto/CryptoPP.h \
  cpp-ethereum/libdevcrypto/AES.h \
  cpp-ethereum/libdevcrypto/ECDHE.h \
  cpp-ethereum/libethashseal/GenesisInfo.h \
  cpp-ethereum/libethereum/ChainParams.h \
  cpp-ethereum/libethcore/Transaction.h \
  cpp-ethereum/libethcore/Exceptions.h \
  cpp-ethereum/libethereum/Transaction.h \
  cpp-ethereum/libethereum/Executive.h \
  cpp-ethereum/libethereum/ExtVM.h \
  cpp-ethereum/libethereum/Block.h \
  cpp-ethereum/libethereum/BlockChain.h \
  cpp-ethereum/libethereum/BlockDetails.h \
  cpp-ethereum/libethereum/TransactionQueue.h \
  cpp-ethereum/libethereum/BlockQueue.h \
  cpp-ethereum/libethcore/BlockHeader.h \
  cpp-ethereum/libdevcore/RLP.h \
  cpp-ethereum/libethereum/TransactionReceipt.h \
  cpp-ethereum/libethcore/SealEngine.h \
  cpp-ethereum/libdevcore/TrieHash.h \
  cpp-ethereum/libethereum/GenesisInfo.h \
  cpp-ethereum/libethashseal/Ethash.h \
  cpp-ethereum/libethashseal/EthashCPUMiner.h \
  cpp-ethereum/libethashseal/EthashAux.h \
  cpp-ethereum/libethashseal/EthashProofOfWork.h \
  cpp-ethereum/libethash/internal.c \
  cpp-ethereum/libethash/io.c \
  cpp-ethereum/libethash/sha3.c \
  cpp-ethereum/libethash/internal.h \
  cpp-ethereum/libethash/io.h \
  cpp-ethereum/libethash/sha3.h \
  cpp-ethereum/libdevcore/vector_ref.h \
  cpp-ethereum/libdevcore/Exceptions.h \
  cpp-ethereum/libdevcore/db.h \
  cpp-ethereum/libdevcore/concurrent_queue.h \
  cpp-ethereum/libdevcore/Terminal.h \
  cpp-ethereum/libethereum/CodeSizeCache.h \
  cpp-ethereum/libethereum/VerifiedBlock.h \
  cpp-ethereum/libdevcore/Assertions.h \
  cpp-ethereum/libdevcore/debugbreak.h \
  cpp-ethereum/libethereum/GenericMiner.h \
  cpp-ethereum/libevm/VMFace.h \
  cpp-ethereum/libethereum/GenericFarm.h \
  cpp-ethereum/libethereum/Interface.h \
  cpp-ethereum/libethcore/CommonJS.h \
  cpp-ethereum/libdevcore/picosha2.h \
  cpp-ethereum/libevm/VMConfig.h \
  cpp-ethereum/libethereum/LogFilter.h \
  cpp-ethereum/libdevcrypto/Exceptions.h \
  cpp-ethereum/libethashseal/genesis/mainNetwork.cpp \
  cpp-ethereum/libethashseal/genesis/eip150Test.cpp \
  cpp-ethereum/libethashseal/genesis/eip158Test.cpp \
  cpp-ethereum/libethashseal/genesis/frontierTest.cpp \
  cpp-ethereum/libethashseal/genesis/homesteadTest.cpp \
  cpp-ethereum/libethashseal/genesis/mainNetworkTest.cpp \
  cpp-ethereum/libethashseal/genesis/metropolisTest.cpp \
  cpp-ethereum/libethashseal/genesis/qtumMainNetwork.cpp \
  cpp-ethereum/libethashseal/genesis/qtumTestNetwork.cpp \
  cpp-ethereum/libethashseal/genesis/ropsten.cpp \
  cpp-ethereum/libethashseal/genesis/transitionnetTest.cpp \
  cpp-ethereum/libethash/ethash.h \
  cpp-ethereum/libethash/compiler.h \
  cpp-ethereum/libethash/data_sizes.h \
  cpp-ethereum/libethash/fnv.h \
  cpp-ethereum/libethash/mmap.h \
  cpp-ethereum/libethash/endian.h \
  cpp-ethereum/libethash/io.h \
  cpp-ethereum/libethash/ethash.h \
  cpp-ethereum/libethash/internal.h \
  cpp-ethereum/libethash/mmap_win32.c \
  cpp-ethereum/utils/json_spirit/JsonSpiritHeaders.h \
  cpp-ethereum/utils/json_spirit/json_spirit.h \
  cpp-ethereum/utils/json_spirit/json_spirit_error_position.h \
  cpp-ethereum/utils/json_spirit/json_spirit_reader.h \
  cpp-ethereum/utils/json_spirit/json_spirit_reader_template.h \
  cpp-ethereum/utils/json_spirit/json_spirit_stream_reader.h \
  cpp-ethereum/utils/json_spirit/json_spirit_utils.h \
  cpp-ethereum/utils/json_spirit/json_spirit_value.h \
  cpp-ethereum/utils/json_spirit/json_spirit_writer.h \
  cpp-ethereum/utils/json_spirit/json_spirit_writer_template.h \
  $(VDS_CORE_H) \
  $(LIBVDS_H)

#only added json_spirit so that `make dist` works properly

if TARGET_WINDOWS
  libvds_common_a_SOURCES += \
    cpp-ethereum/libethash/io_win32.c \
    cpp-ethereum/libethash/util_win32.c
else
  libvds_common_a_SOURCES += cpp-ethereum/libethash/io_posix.c
endif



# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libvds_util_a_CPPFLAGS = $(VDS_INCLUDES)
libvds_util_a_SOURCES = \
  support/pagelocker.cpp \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  uint256.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(VDS_CORE_H) \
  $(LIBVDS_H)

if GLIBC_BACK_COMPAT
libvds_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: vds-cli
libvds_cli_a_CPPFLAGS = $(VDS_INCLUDES)
libvds_cli_a_SOURCES = \
  rpc/client.cpp \
  $(VDS_CORE_H) \
  $(LIBVDS_H)

nodist_libvds_util_a_SOURCES = $(srcdir)/obj/build.h

# bitcoind binary #
vdsd_SOURCES = bitcoind.cpp 
vdsd_CPPFLAGS = $(VDS_INCLUDES)
vdsd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
vdsd_SOURCES += bitcoind-res.rc
endif

vdsd_LDADD = \
  $(LIBVDS_SERVER) \
  $(LIBVDS_SQLITE)

if ENABLE_WALLET
vdsd_LDADD += $(LIBVDS_WALLET)
endif

vdsd_LDADD += \
  $(LIBVDS_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBVDS_UTIL) \
  $(LIBVDS_CONSENSUS) \
  $(LIBVDS_CRYPTO) \
  $(LIBVDS) \
  $(LIBSNARK) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBCRYPTOPP) \
  $(LIBSECP256K1)

if ENABLE_ZMQ
vdsd_LDADD += $(LIBVDS_ZMQ) $(ZMQ_LIBS)
endif

vdsd_LDADD += \
  $(BOOST_LIBS) \
  $(BDB_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS) \
  $(MINIUPNPC_LIBS) \
  $(EVENT_PTHREADS_LIBS) \
  $(EVENT_LIBS) \
  $(LIBVDS_CRYPTO) \
  $(LIBVDS_LIBS) \
  $(PROTOBUF_LIBS)


if ENABLE_PROTON
vdsd_LDADD += $(LIBVDS_PROTON) $(PROTON_LIBS)
endif

# bitcoin-cli binary #
vds_cli_SOURCES = bitcoin-cli.cpp
vds_cli_CPPFLAGS = $(VDS_INCLUDES) $(EVENT_CFLAGS)
vds_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
vds_cli_SOURCES += bitcoin-cli-res.rc
endif

vds_cli_LDADD = \
  $(LIBVDS_CLI) \
  $(LIBUNIVALUE) \
  $(LIBVDS_UTIL) \
  $(BOOST_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS) \
  $(EVENT_LIBS) \
  $(LIBVDS) \
  $(LIBSNARK) \
  $(LIBVDS_CRYPTO) \
  $(LIBCRYPTOPP) \
  $(LIBVDS_LIBS)
#

# vds-tx binary #
vds_tx_SOURCES = bitcoin-tx.cpp
vds_tx_CPPFLAGS = $(VDS_INCLUDES)
vds_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
vds_tx_SOURCES += bitcoin-tx-res.rc
endif

# FIXME: Is libvds needed for vds_tx?
vds_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBVDS_COMMON) \
  $(LIBVDS_LIGHTNODE) \
  $(LIBVDS_UTIL) \
  $(LIBSECP256K1) \
  $(LIBVDS_CONSENSUS) \
  $(LIBVDS) \
  $(LIBSNARK) \
  $(LIBCRYPTOPP) \
  $(LIBVDS_CRYPTO) \
  $(LIBVDS_LIBS)

vds_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# vds protocol primitives #
libvds_a_SOURCES = \
  crypto/sha256.cpp \
  crypto/sha256.cpp \
  vds/IncrementalMerkleTree.cpp \
  vds/NoteEncryption.cpp \
  vds/Address.cpp \
  vds/JoinSplit.cpp \
  vds/Proof.cpp \
  vds/Note.cpp \
  vds/prf.cpp \
  vds/util.cpp \
  vds/zip32.cpp \
  vds/util.cpp \
  vds/circuit/commitment.tcc \
  vds/circuit/gadget.tcc \
  vds/circuit/merkle.tcc \
  vds/circuit/note.tcc \
  vds/circuit/prfs.tcc \
  vds/circuit/utils.tcc

libvds_a_CPPFLAGS = $(AM_CPPFLAGS) $(VDS_INCLUDES)
#libvds_a_CPPFLAGS += -DBINARY_OUTPUT -DCURVE_ALT_BN128 -DBOOST_SPIRIT_THREADSAFE -DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS -fvisibility=default
libvds_a_CPPFLAGS += -DBINARY_OUTPUT -DCURVE_ALT_BN128 -DBOOST_SPIRIT_THREADSAFE -DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS

libvds_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(PIC_FLAGS) $(HARDENED_CXXFLAGS) -fwrapv -fno-strict-aliasing 

# libvds_a_LDFLAGS = $(HARDENED_LDFLAGS)

libvds_a_LIBADD = $(LIBSECP256K1) $(LIBSNARK)

libvds_a_CPPFLAGS += -DMONTGOMERY_OUTPUT

# vdsconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/vdsconsensus.h
libvdsconsensus_la_SOURCES = \
  crypto/equihash.cpp \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  hash.cpp \
  primitives/transaction.cpp \
  pubkey.cpp \
  script/vdsconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libvdsconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libvdsconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libvdsconsensus_la_LIBADD = $(LIBSECP256K1)
libvdsconsensus_la_CPPFLAGS = $(VDS_INCLUDES) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL

endif
#
CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno */*.gcno wallet/*/*.gcno
CLEANFILES += $(EXTRA_LIBRARIES)
CLEANFILES += $(LIBSNARK)

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb snark

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C snark clean
	-$(MAKE) -C univalue clean
	-$(MAKE) -C net clean
	-rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	-rm -f cryptopp/*.o
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat of [$(bin_PROGRAMS)]..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security of [$(bin_PROGRAMS)]..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

%.contract.hpp: %.sol
	@test -f $(SOLC)
	$(AM_V_GEN) $(SOLC) --evm-version homestead --combined-json abi,bin $< > $(basename $<).json && $(top_srcdir)/contrib/devtools/gen_contracts.py $(basename $<).json


if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

include Makefile.cryptopp.include

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_TESTS
include Makefile.test.include
include Makefile.gtest.include
endif
