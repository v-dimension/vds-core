// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2017-2019 The Vds developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "init.h"
#include "key_io.h"
#include "validation.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

#include "paymentdisclosure.h"
#include "paymentdisclosuredb.h"

#include "vds/Note.hpp"
#include "vds/NoteEncryption.hpp"

using namespace std;
using namespace libzcash;

// Function declaration for function implemented in wallet/rpcwallet.cpp
bool EnsureWalletIsAvailable(bool avoidException);

