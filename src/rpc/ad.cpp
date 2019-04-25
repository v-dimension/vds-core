// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "utilstrencodings.h"
#include "init.h"
#include "protocol.h"
#include "server.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "wallet/wallet.h"
#include "validation.h"
#include "consensus/validation.h"
#include <utilmoneystr.h>
#include <key_io.h>
#include <univalue.h>
#include <wallet/coincontrol.h>
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;

extern bool EnsureWalletIsAvailable(bool avoidException);
extern void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage);
UniValue listad(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "listad \"count\" \n"
            "\nReturns the ad information.\n"
            "\nArguments:\n"
            "\1. \"count\"  (integer, required) The amount of ads, order by block height desc.\n"
            "\nResult:\n"
            "[\n"
            "   [\n"
            "      \"txid\",            (string)    the ad tx hash\n"
            "      \"blockHeight\",     (numeric)   the ad tx block height\n"
            "      \"advalue\",         (numeric)   the ad tx value\n"
            "      \"sender\",          (string)    the ad tx sender\n"
            "      \"msg\",             (string)    the ad tx message\n"
            "   ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listad", "\"0\"")
            + HelpExampleRpc("listad", "\"2\"")
        );

    double count = request.params[0].get_int();
    if (count < 1 )
        throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid count, must more than 1"));

    UniValue result(UniValue::VARR);

    for (int i = GetAdHeight((chainActive.Height() - Params().GetConsensus().nBidPeriod * 2)); i > 0; i -= Params().GetConsensus().nBidPeriod) {
        CAd ad;
        if (paddb->ReadAd(i, ad)) {
            UniValue adobj(UniValue::VOBJ);
            adobj.push_back(make_pair("txid", ad.txid.GetHex()));
            adobj.push_back(make_pair("blockHeight",  ad.blockHeight));
            adobj.push_back(make_pair("advalue", ad.adValue));
            adobj.push_back(make_pair("sender", EncodeDestination(ad.address)));
            adobj.push_back(make_pair("msg",  ad.admsg));
            result.push_back(adobj);
        }
        count--;
        if (count == 0)
            break;
    }
    return result;
}

UniValue adking(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "adking\n"
            "\nReturns the ad king information.\n"
            "\nResult:\n"
            "   [\n"
            "       \"txid\",            (string)    the ad tx hash\n"
            "       \"blockHeight\",     (numeric)   the ad tx block height\n"
            "       \"advalue\",         (numeric)   the ad tx value\n"
            "       \"sender\",          (string)    the ad tx sender address\n"
            "       \"msg\",             (string)    the ad tx message\n"
            "   ]\n"
            "\nExamples:\n"
            + HelpExampleCli("adking", "")
            + HelpExampleRpc("adking", "")
        );
    LOCK2(cs_main, mempool.cs);
    CAd adKing;
    if (!paddb->GetAdKing(adKing)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, string("ad king is not exist!"));
    }
    if ((chainActive.Height() - adKing.blockHeight) < Params().GetConsensus().nBidPeriod) {
        if (!paddb->GetAdKingLast(adKing))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("ad king is not exist!"));
    }
    UniValue adobj(UniValue::VOBJ);
    adobj.push_back(make_pair("txid",           adKing.txid.GetHex()));
    adobj.push_back(make_pair("blockHeight",    adKing.blockHeight));
    adobj.push_back(make_pair("advalue",        adKing.adValue));
    adobj.push_back(make_pair("sender",         EncodeDestination(adKing.address)));
    adobj.push_back(make_pair("msg",            adKing.admsg));


    return adobj;
}
static const CRPCCommand commands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    { "ad",                 "listad",                &listad,                true,   {"count"} },
    { "ad",                 "adking",                &adking,                true,   {} }
};

void RegisterAdRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
