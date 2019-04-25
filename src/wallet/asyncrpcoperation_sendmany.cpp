// Copyright (c) 2016 The Vds developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "asyncrpcoperation_sendmany.h"
#include "asyncrpcqueue.h"
#include "amount.h"
#include "core_io.h"
#include "init.h"
#include "key_io.h"
#include "validation.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"
#include "script/interpreter.h"
#include "utiltime.h"
#include "rpc/protocol.h"
#include "vds/IncrementalMerkleTree.hpp"
#include "sodium.h"
#include "miner.h"

#include <iostream>
#include <chrono>
#include <thread>
#include <string>

#include "paymentdisclosuredb.h"

using namespace libzcash;

extern UniValue signrawtransaction(const JSONRPCRequest& request);
extern UniValue sendrawtransaction(const JSONRPCRequest& request);

int find_output(UniValue obj, int n)
{
    UniValue outputMapValue = find_value(obj, "outputmap");
    if (!outputMapValue.isArray()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing outputmap for JoinSplit operation");
    }

    UniValue outputMap = outputMapValue.get_array();
    assert(outputMap.size() == ZC_NUM_JS_OUTPUTS);
    for (size_t i = 0; i < outputMap.size(); i++) {
        if (outputMap[i].get_int() == n) {
            return i;
        }
    }

    throw std::logic_error("n is not present in outputmap");
}

AsyncRPCOperation_sendmany::AsyncRPCOperation_sendmany(
    boost::optional<TransactionBuilder> builder,
    CMutableTransaction contextualTx,
    std::string fromAddress,
    std::vector<SendManyRecipient> tOutputs,
    std::vector<SendManyRecipient> zOutputs,
    int minDepth,
    CAmount fee,
    UniValue contextInfo) :
    tx_(contextualTx), fromaddress_(fromAddress), t_outputs_(tOutputs), z_outputs_(zOutputs), mindepth_(minDepth), fee_(fee), contextinfo_(contextInfo)
{
    assert(fee_ >= 0);

    if (minDepth < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be negative");
    }

    if (fromAddress.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "From address parameter missing");
    }

    if (tOutputs.size() == 0 && zOutputs.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No recipients");
    }
    isGuiMode = false;
    isUsingBuilder_ = false;
    if (builder) {
        isUsingBuilder_ = true;
        builder_ = builder.get();
    }

    fromtaddr_ = DecodeDestination(fromAddress);
    isfromtaddr_ = IsValidDestination(fromtaddr_);
    isfromzaddr_ = false;

    if (!isfromtaddr_) {
        auto address = DecodePaymentAddress(fromAddress);
        if (IsValidPaymentAddress(address)) {
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), address)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            isfromzaddr_ = true;
            frompaymentaddress_ = address;
            spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), address).get();
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address");
        }
    }

    if (isfromzaddr_ && minDepth == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be zero when sending from zaddr");
    }

    // Log the context info i.e. the call parameters to z_sendmany
    if (LogAcceptCategory("vrpcunsafe")) {
        LogPrint("vrpcunsafe", "%s: z_sendmany initialized (params=%s)\n", getId(), contextInfo.write());
    } else {
        LogPrint("vrpc", "%s: z_sendmany initialized\n", getId());
    }


    // Enable payment disclosure if requested
    paymentDisclosureMode = fExperimentalMode && GetBoolArg("-paymentdisclosure", false);
}

AsyncRPCOperation_sendmany::~AsyncRPCOperation_sendmany()
{
}

void AsyncRPCOperation_sendmany::main()
{
    if (isCancelled())
        return;

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;


    try {
        success = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
        NotifyOperationStateUpdate(this->getId(), code, message, uint256());
    } catch (const runtime_error& e) {
        int code = -1;
        std::string message = "runtime error: " + string(e.what());
        set_error_code(code);
        set_error_message(message);
        NotifyOperationStateUpdate(this->getId(), code, message, uint256());
    } catch (const logic_error& e) {
        int code = -1;
        std::string message = "logic error: " + string(e.what());
        set_error_code(code);
        set_error_message(message);
        NotifyOperationStateUpdate(this->getId(), code, message, uint256());
    } catch (const exception& e) {
        int code = -1;
        std::string message = "general exception: " + string(e.what());
        set_error_code(code);
        set_error_message(message);
        NotifyOperationStateUpdate(this->getId(), code, message, uint256());
    } catch (...) {
        int code = -2;
        std::string message = "unknown error";
        set_error_code(code);
        set_error_message(message);
        NotifyOperationStateUpdate(this->getId(), code, message, uint256());
    }


    stop_execution_clock();

    if (success) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: v_sendmany finished (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", txid=%s)\n", tx_.GetHash().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s", s);

    if (success) {
        uint256 txidhash = tx_.GetHash();
        int code = 0;
        std::string message = "success";
        NotifyOperationStateUpdate(this->getId(), code, message, txidhash);
    }
    // !!! Payment disclosure START
    if (success && paymentDisclosureMode && paymentDisclosureData_.size() > 0) {

        std::shared_ptr<PaymentDisclosureDB> db = PaymentDisclosureDB::sharedInstance();
        for (PaymentDisclosureKeyInfo p : paymentDisclosureData_) {
            uint256 txidhash = tx_.GetHash();
            p.first.hash = txidhash;
            if (!db->Put(p.first, p.second)) {
                LogPrint("paymentdisclosure", "%s: Payment Disclosure: Error writing entry to database for key %s\n", getId(), p.first.ToString());
            } else {
                LogPrint("paymentdisclosure", "%s: Payment Disclosure: Successfully added entry to database for key %s\n", getId(), p.first.ToString());
            }
        }
    }
    // !!! Payment disclosure END
}

// Notes:
// 1. #1159 Currently there is no limit set on the number of joinsplits, so size of tx could be invalid.
// 2. #1360 Note selection is not optimal
// 3. #1277 Spendable notes are not locked, so an operation running in parallel could also try to use them
bool AsyncRPCOperation_sendmany::main_impl()
{

    assert(isfromtaddr_ != isfromzaddr_);

    bool isSingleZaddrOutput = (t_outputs_.size() == 0 && z_outputs_.size() == 1);
    bool isMultipleZaddrOutput = (t_outputs_.size() == 0 && z_outputs_.size() >= 1);
    bool isPureTaddrOnlyTx = (isfromtaddr_ && z_outputs_.size() == 0);
    CAmount minersFee = fee_;

    // When spending coinbase utxos, you can only specify a single zaddr as the change must go somewhere
    // and if there are multiple zaddrs, we don't know where to send it.
    if (isfromtaddr_) {
        if (isSingleZaddrOutput) {
            bool bFind = false;
            if (HasSelected_tAddr()) {
                bFind = find_utxos_in_selected(true);
            } else {
                bFind = find_utxos(true);
            }
            if (!bFind) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no UTXOs found for taddr from address.");
            }
        } else {
            bool bFind = false;
            if (HasSelected_tAddr()) {
                bFind = find_utxos_in_selected(false);
            } else {
                bFind = find_utxos(false);
            }
            if (!bFind) {
                if (isMultipleZaddrOutput) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find any non-coinbase UTXOs to spend. Coinbase UTXOs can only be sent to a single zaddr recipient.");
                } else {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find any non-coinbase UTXOs to spend.");
                }
            }
        }
    }

    if (!HasSelected()) {
        if (isfromzaddr_ && !find_unspent_notes()) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no unspent notes found for zaddr from address.");
        }
    } else {
        if (isfromzaddr_ && !find_unspent_notes_in_selected()) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no unspent notes found for zaddr from address.");
        }
    }

    CAmount t_inputs_total = 0;
    for (SendManyInputUTXO& t : t_inputs_) {
        t_inputs_total += std::get<2>(t);
    }

    CAmount z_inputs_total = 0;
    for (auto t : z_sapling_inputs_) {
        z_inputs_total += t.note.value();
    }

    CAmount t_outputs_total = 0;
    for (SendManyRecipient& t : t_outputs_) {
        t_outputs_total += std::get<1>(t);
    }

    CAmount z_outputs_total = 0;
    for (SendManyRecipient& t : z_outputs_) {
        z_outputs_total += std::get<1>(t);
    }

    CAmount sendAmount = z_outputs_total + t_outputs_total;
    CAmount targetAmount = sendAmount + minersFee;

    assert(!isfromtaddr_ || z_inputs_total == 0);
    assert(!isfromzaddr_ || t_inputs_total == 0);

    if (isfromtaddr_ && (t_inputs_total < targetAmount)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           strprintf("Insufficient transparent funds, have %s, need %s",
                                     FormatMoney(t_inputs_total), FormatMoney(targetAmount)));
    }

    if (isfromzaddr_ && (z_inputs_total < targetAmount)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           strprintf("Insufficient shielded funds, have %s, need %s",
                                     FormatMoney(z_inputs_total), FormatMoney(targetAmount)));
    }

    // If from address is a taddr, select UTXOs to spend
    CAmount selectedUTXOAmount = 0;
    bool selectedUTXOCoinbase = false;
    if (isfromtaddr_) {
        // Get dust threshold
        CKey secret;
        secret.MakeNewKey(true);
        CScript scriptPubKey = GetScriptForDestination(secret.GetPubKey().GetID());
        CTxOut out(CAmount(1), CTxOut::NORMAL, scriptPubKey);
        CAmount dustThreshold = out.GetDustThreshold(minRelayTxFee);
        CAmount dustChange = -1;

        std::vector<SendManyInputUTXO> selectedTInputs;
        for (SendManyInputUTXO& t : t_inputs_) {
            bool b = std::get<3>(t);
            if (b) {
                selectedUTXOCoinbase = true;
            }
            selectedUTXOAmount += std::get<2>(t);
            selectedTInputs.push_back(t);
            if (selectedUTXOAmount >= targetAmount) {
                // Select another utxo if there is change less than the dust threshold.
                dustChange = selectedUTXOAmount - targetAmount;
                if (dustChange == 0 || dustChange >= dustThreshold) {
                    break;
                }
            }
        }

        // If there is transparent change, is it valid or is it dust?
        if (dustChange < dustThreshold && dustChange != 0) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               strprintf("Insufficient transparent funds, have %s, need %s more to avoid creating invalid change output %s (dust threshold is %s)",
                                         FormatMoney(t_inputs_total), FormatMoney(dustThreshold - dustChange), FormatMoney(dustChange), FormatMoney(dustThreshold)));
        }

        t_inputs_ = selectedTInputs;
        t_inputs_total = selectedUTXOAmount;

        // Check mempooltxinputlimit to avoid creating a transaction which the local mempool rejects
        size_t limit = (size_t)GetArg("-mempooltxinputlimit", 0);
        {
            LOCK(cs_main);
            limit = 0;
        }
        if (limit > 0) {
            size_t n = t_inputs_.size();
            if (n > limit) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Too many transparent inputs %zu > limit %zu", n, limit));
            }
        }

        // update the transaction with these inputs
        if (isUsingBuilder_) {
            CScript scriptPubKey = GetScriptForDestination(fromtaddr_);
            for (auto t : t_inputs_) {
                uint256 txid = std::get<0>(t);
                int vout = std::get<1>(t);
                CAmount amount = std::get<2>(t);
                uint8_t flag = std::get<4>(t);
                if (IsGuiMode()) {
                    if (pwalletMain->GetAddressCategory(fromtaddr_) & KeyCategoryHD) {
                        LOCK2(cs_main, pwalletMain->cs_wallet);
                        std::map<uint256, CWalletTx>::const_iterator mi = pwalletMain->mapWallet.find(txid);
                        if (mi == pwalletMain->mapWallet.end() || vout >= mi->second.tx->vout.size()) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "wallet main find txid failed");
                        }
                        const CScript& scriptPubKeyFindInWallet = mi->second.tx->vout[vout].scriptPubKey;
                        builder_.AddTransparentInput(COutPoint(txid, vout), scriptPubKeyFindInWallet, amount);
                    } else {
                        builder_.AddTransparentInput(COutPoint(txid, vout), scriptPubKey, amount);
                    }
                } else {
                    builder_.AddTransparentInput(COutPoint(txid, vout), scriptPubKey, amount);
                }

            }
        } else {
            CMutableTransaction rawTx(tx_);
            for (SendManyInputUTXO& t : t_inputs_) {
                uint256 txid = std::get<0>(t);
                int vout = std::get<1>(t);
                CAmount amount = std::get<2>(t);
                uint8_t flag = std::get<4>(t);
                CTxIn in(COutPoint(txid, vout));
                rawTx.vin.push_back(in);
            }
            tx_ = CTransaction(rawTx);
        }
    }

    LogPrint((isfromtaddr_) ? "vrpc" : "vrpcunsafe", "%s: spending %s to send %s with fee %s\n",
             getId(), FormatMoney(targetAmount), FormatMoney(sendAmount), FormatMoney(minersFee));
    LogPrint("vrpc", "%s: transparent input: %s (to choose from)\n", getId(), FormatMoney(t_inputs_total));
    LogPrint("vrpcunsafe", "%s: private input: %s (to choose from)\n", getId(), FormatMoney(z_inputs_total));
    LogPrint("vrpc", "%s: transparent output: %s\n", getId(), FormatMoney(t_outputs_total));
    LogPrint("vrpcunsafe", "%s: private output: %s\n", getId(), FormatMoney(z_outputs_total));
    LogPrint("vrpc", "%s: fee: %s\n", getId(), FormatMoney(minersFee));


    /**
     * SCENARIO #0
     *
     * Sprout not involved, so we just use the TransactionBuilder and we're done.
     * We added the transparent inputs to the builder earlier.
     */
    if (isUsingBuilder_) {
        builder_.SetFee(minersFee);

        // Get various necessary keys
        SaplingExpandedSpendingKey expsk;
        uint256 ovk;
        if (isfromzaddr_) {
            auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
            expsk = sk.expsk;
            ovk = expsk.full_viewing_key().ovk;
        } else {
            // Sending from a t-address, which we don't have an ovk for. Instead,
            // generate a common one from the HD seed. This ensures the data is
            // recoverable, while keeping it logically separate from the ZIP 32
            // Sapling key hierarchy, which the user might not be using.
            HDSeed seed;
            if (!pwalletMain->GetHDSeed(seed)) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    "CWallet::GenerateNewSaplingZKey(): HD seed not found");
            }
            ovk = ovkForShieldingFromTaddr(seed);
        }

        // Set change address if we are using transparent funds
        // TODO: Should we just use fromtaddr_ as the change address?
        if (isfromtaddr_) {
            if (!builder_.IsSendChangeT()) {
                LOCK2(cs_main, pwalletMain->cs_wallet);

                EnsureWalletIsUnlocked();
                CReserveKey keyChange(pwalletMain);
                CPubKey vchPubKey;
                bool ret = keyChange.GetReservedKey(vchPubKey);
                if (!ret) {
                    // should never fail, as we just unlocked
                    throw JSONRPCError(
                        RPC_WALLET_KEYPOOL_RAN_OUT,
                        "Could not generate a taddr to use as a change address");
                }

                CTxDestination changeAddr = vchPubKey.GetID();
                assert(builder_.SendChangeTo(changeAddr));
            }
        }

        // Select Sapling notes
        std::vector<SaplingOutPoint> ops;
        std::vector<SaplingNote> notes;
        CAmount sum = 0;
        for (auto t : z_sapling_inputs_) {
            ops.push_back(t.op);
            notes.push_back(t.note);
            sum += t.note.value();
            if (sum >= targetAmount) {
                break;
            }
        }

        // Fetch Sapling anchor and witnesses
        uint256 anchor;
        std::vector<boost::optional<SaplingWitness>> witnesses;
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->GetSaplingNoteWitnesses(ops, witnesses, anchor);
        }

        // Add Sapling spends
        for (size_t i = 0; i < notes.size(); i++) {
            if (!witnesses[i]) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Missing witness for Sapling note");
            }
            assert(builder_.AddSaplingSpend(expsk, notes[i], anchor, witnesses[i].get()));
        }

        // Add Sapling outputs
        for (auto r : z_outputs_) {
            auto address = std::get<0>(r);
            auto value = std::get<1>(r);
            auto hexMemo = std::get<2>(r);

            auto addr = DecodePaymentAddress(address);
            assert(boost::get<libzcash::SaplingPaymentAddress>(&addr) != nullptr);
            auto to = boost::get<libzcash::SaplingPaymentAddress>(addr);

            auto memo = get_memo_from_hex_string(hexMemo);

            builder_.AddSaplingOutput(ovk, to, value, memo);
        }

        // Add transparent outputs
        for (auto r : t_outputs_) {
            auto outputAddress = std::get<0>(r);
            auto amount = std::get<1>(r);

            auto address = DecodeDestination(outputAddress);
            if (!builder_.AddTransparentOutput(address, amount)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid output address, not a valid taddr.");
            }
        }

        // Build the transaction
        auto maybe_tx = builder_.Build();
        if (!maybe_tx) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build transaction.");
        }
        tx_ = maybe_tx.get();

        // Send the transaction
        // TODO: Use CWallet::CommitTransaction instead of sendrawtransaction
        auto signedtxn = EncodeHexTx(tx_);
        if (!testmode) {
            JSONRPCRequest request;
            UniValue params = UniValue(UniValue::VARR);
            params.push_back(signedtxn);
            request.params = params;
            UniValue sendResultValue = sendrawtransaction(request);
            if (sendResultValue.isNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "sendrawtransaction did not return an error or a txid.");
            }

            auto txid = sendResultValue.get_str();

            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("txid", txid));
            set_result(o);
        } else {
            // Test mode does not send the transaction to the network.
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("test", 1));
            o.push_back(Pair("txid", tx_.GetHash().ToString()));
            o.push_back(Pair("hex", signedtxn));
            set_result(o);
        }

        return true;
    }
    /**
     * END SCENARIO #0
     */

    /**
     * SCENARIO #1
     *
     * taddr -> taddrs
     *
     * There are no zaddrs or joinsplits involved.
     */
    if (isPureTaddrOnlyTx) {
        add_taddr_outputs_to_tx();

        CAmount funds = selectedUTXOAmount;
        CAmount fundsSpent = t_outputs_total + minersFee;
        CAmount change = funds - fundsSpent;

        if (change > 0) {
            add_taddr_change_output_to_tx(change);

            LogPrint("vrpc", "%s: transparent change in transaction output (amount=%s)\n",
                     getId(),
                     FormatMoney(change)
                    );
        }

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("rawtxn", EncodeHexTx(tx_)));
        sign_send_raw_transaction(obj);
        return true;
    }
    /**
     * END SCENARIO #1
     */


    // Prepare raw transaction to handle JoinSplits
    CMutableTransaction mtx(tx_);
    crypto_sign_keypair(joinSplitPubKey_.begin(), joinSplitPrivKey_);
    tx_ = CTransaction(mtx);

    // Copy zinputs and zoutputs to more flexible containers
    if (isfromtaddr_) {
        add_taddr_outputs_to_tx();

        CAmount funds = selectedUTXOAmount;
        CAmount fundsSpent = t_outputs_total + minersFee + z_outputs_total;
        CAmount change = funds - fundsSpent;

        if (change > 0) {
            if (selectedUTXOCoinbase) {
                assert(isSingleZaddrOutput);
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                                       "Change %s not allowed. When shielding coinbase funds, the wallet does not "
                                       "allow any change as there is currently no way to specify a change address "
                                       "in v_sendmany.", FormatMoney(change)));
            } else {
                add_taddr_change_output_to_tx(change);
                LogPrint("vrpc", "%s: transparent change in transaction output (amount=%s)\n",
                         getId(),
                         FormatMoney(change)
                        );
            }
        }

        return true;
    }
    /**
     * END SCENARIO #2
     */



    /**
     * SCENARIO #3
     *
     * zaddr -> taddrs
     *       -> zaddrs
     *
     * Send to zaddrs by chaining JoinSplits together and immediately consuming any change
     * Send to taddrs by creating dummy z outputs and accumulating value in a change note
     * which is used to set vpub_new in the last chained joinsplit.
     */
    return true;
}


/**
 * Sign and send a raw transaction.
 * Raw transaction as hex string should be in object field "rawtxn"
 */
void AsyncRPCOperation_sendmany::sign_send_raw_transaction(UniValue obj)
{
    // Sign the raw transaction
    UniValue rawtxnValue = find_value(obj, "rawtxn");
    if (rawtxnValue.isNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for raw transaction");
    }
    std::string rawtxn = rawtxnValue.get_str();

    JSONRPCRequest jsonRequest;
    jsonRequest.params = UniValue(UniValue::VARR);
    jsonRequest.params.push_back(rawtxn);

    UniValue signResultValue = signrawtransaction(jsonRequest);
    UniValue signResultObject = signResultValue.get_obj();
    UniValue completeValue = find_value(signResultObject, "complete");
    bool complete = completeValue.get_bool();
    if (!complete) {
        // TODO: #1366 Maybe get "errors" and print array vErrors into a string
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Failed to sign transaction");
    }

    UniValue hexValue = find_value(signResultObject, "hex");
    if (hexValue.isNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for signed transaction");
    }
    std::string signedtxn = hexValue.get_str();

    // Send the signed transaction
    if (!testmode) {
        jsonRequest.params.clear();
        jsonRequest.params.setArray();
        jsonRequest.params.push_back(signedtxn);
        UniValue sendResultValue = sendrawtransaction(jsonRequest);
        if (sendResultValue.isNull()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Send raw transaction did not return an error or a txid.");
        }

        std::string txid = sendResultValue.get_str();

        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("txid", txid));
        set_result(o);
    } else {
        // Test mode does not send the transaction to the network.

        CDataStream stream(ParseHex(signedtxn), SER_NETWORK, PROTOCOL_VERSION);
        CTransactionRef ptx;
        stream >> ptx;

        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("test", 1));
        o.push_back(Pair("txid", ptx->GetHash().ToString()));
        o.push_back(Pair("hex", signedtxn));
        set_result(o);
    }

    // Keep the signed transaction so we can hash to the same txid
    CDataStream stream(ParseHex(signedtxn), SER_NETWORK, PROTOCOL_VERSION);
    CTransactionRef ptx;
    stream >> ptx;
    tx_ = *ptx;
}


bool AsyncRPCOperation_sendmany::find_utxos(bool fAcceptCoinbase = false)
{
    std::set<CTxDestination> destinations;
    destinations.insert(fromtaddr_);
    vector<COutput> vecOutputs;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true, ONLY_NOT10000IFMN, fAcceptCoinbase);

    BOOST_FOREACH(const COutput & out, vecOutputs) {
        if (!out.fSpendable) {
            continue;
        }

        if (out.nDepth < mindepth_) {
            continue;
        }

        if (destinations.size()) {
            CTxDestination address;
            if (!ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address)) {
                continue;
            }

            if (IsGuiMode()) {
                if (pwalletMain->GetAddressCategory(fromtaddr_) & KeyCategoryHD) {
                    if (!(pwalletMain->GetAddressCategory(address) & KeyCategoryHD))
                        continue;
                } else {
                    if (!destinations.count(address))
                        continue;
                }
            } else {
                if (!destinations.count(address))
                    continue;
            }
        }

        // By default we ignore coinbase outputs
        bool isCoinbase = out.tx->IsCoinBase();
        if (isCoinbase && fAcceptCoinbase == false) {
            continue;
        }

        CAmount nValue = out.tx->tx->vout[out.i].nValue;
        SendManyInputUTXO utxo(out.tx->GetHash(), out.i, nValue, isCoinbase, out.tx->tx->vout[out.i].nFlag);
        t_inputs_.push_back(utxo);
    }

    // sort in ascending order, so smaller utxos appear first
    std::sort(t_inputs_.begin(), t_inputs_.end(), [](SendManyInputUTXO i, SendManyInputUTXO j) -> bool {
        return ( std::get<2>(i) < std::get<2>(j));
    });

    return t_inputs_.size() > 0;
}

bool AsyncRPCOperation_sendmany::find_utxos_in_selected(bool fAcceptCoinbase)
{
    std::vector<SendManyInputUTXO> vOutpoints;
    if (!HasSelected_tAddr())
        return false;

    this->ListSelected(vOutpoints);
    for (auto outpoint : vOutpoints) {
        bool bCoinbase = std::get<3>(outpoint);
        if (bCoinbase && (fAcceptCoinbase == false))
            continue;
        t_inputs_.push_back(outpoint);
    }

    if (t_inputs_.empty()) {
        return false;
    }

    // sort in descending order, so big notes appear first
    std::sort(t_inputs_.begin(), t_inputs_.end(), [](SendManyInputUTXO i, SendManyInputUTXO j) -> bool {
        return ( std::get<2>(i) < std::get<2>(j));
    });

    return true;
}


bool AsyncRPCOperation_sendmany::find_unspent_notes()
{
    std::vector<SaplingNoteEntry> saplingEntries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes(saplingEntries, fromaddress_, mindepth_);
    }

    // If using the TransactionBuilder, we only want Sapling notes.
    // If not using it, we only want Sprout notes.
    // TODO: Refactor `GetFilteredNotes()` so we only fetch what we need.
    if (!isUsingBuilder_) {
        saplingEntries.clear();
    }

    for (auto entry : saplingEntries) {
        z_sapling_inputs_.push_back(entry);
        std::string data(entry.memo.begin(), entry.memo.end());
        LogPrint("vrpcunsafe", "%s: found unspent Sapling note (txid=%s, vShieldedSpend=%d, amount=%s, memo=%s)\n",
                 getId(),
                 entry.op.hash.ToString().substr(0, 10),
                 entry.op.n,
                 FormatMoney(entry.note.value()),
                 HexStr(data).substr(0, 10));
    }

    if (z_sapling_inputs_.empty()) {
        return false;
    }

    // sort in descending order, so big notes appear first
    std::sort(z_sapling_inputs_.begin(), z_sapling_inputs_.end(),
    [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
        return i.note.value() > j.note.value();
    });

    return true;
}

bool AsyncRPCOperation_sendmany::find_unspent_notes_in_selected()
{
    std::vector<SaplingNoteEntry> saplingEntries;

    if (HasSelected()) {
        this->ListSelected(saplingEntries);
    } else {
        return false;
    }
    for (auto entry : saplingEntries) {
        z_sapling_inputs_.push_back(entry);
        std::string data(entry.memo.begin(), entry.memo.end());
        LogPrint("vrpcunsafe", "%s: found unspent Sapling note (txid=%s, vShieldedSpend=%d, amount=%s, memo=%s)\n",
                 getId(),
                 entry.op.hash.ToString().substr(0, 10),
                 entry.op.n,
                 FormatMoney(entry.note.value()),
                 HexStr(data).substr(0, 10));
    }

    if (z_sapling_inputs_.empty()) {
        return false;
    }

    // sort in descending order, so big notes appear first
    std::sort(z_sapling_inputs_.begin(), z_sapling_inputs_.end(),
    [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
        return i.note.value() > j.note.value();
    });
    return true;
}

void AsyncRPCOperation_sendmany::add_taddr_outputs_to_tx()
{

    CMutableTransaction rawTx(tx_);

    for (SendManyRecipient& r : t_outputs_) {
        std::string outputAddress = std::get<0>(r);
        CAmount nAmount = std::get<1>(r);

        CTxDestination address = DecodeDestination(outputAddress);
        if (!IsValidDestination(address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid output address, not a valid taddr.");
        }

        CScript scriptPubKey = GetScriptForDestination(address);

        // TODO: flag should be set
        CTxOut out(nAmount, CTxOut::NORMAL, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    tx_ = CTransaction(rawTx);
}

void AsyncRPCOperation_sendmany::add_taddr_change_output_to_tx(CAmount amount)
{

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();
    CReserveKey keyChange(pwalletMain);
    CPubKey vchPubKey;
    bool ret = keyChange.GetReservedKey(vchPubKey);
    if (!ret) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Could not generate a taddr to use as a change address"); // should never fail, as we just unlocked
    }
    CScript scriptPubKey = GetScriptForDestination(vchPubKey.GetID());
    // TODO: flag should be set
    CTxOut out(amount, CTxOut::NORMAL, scriptPubKey);

    CMutableTransaction rawTx(tx_);
    rawTx.vout.push_back(out);
    tx_ = CTransaction(rawTx);
}

std::array<unsigned char, ZC_MEMO_SIZE> AsyncRPCOperation_sendmany::get_memo_from_hex_string(std::string s)
{
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0x00}};

    std::vector<unsigned char> rawMemo = ParseHex(s.c_str());

    // If ParseHex comes across a non-hex char, it will stop but still return results so far.
    size_t slen = s.length();
    if (slen % 2 != 0 || (slen > 0 && rawMemo.size() != slen / 2)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo must be in hexadecimal format");
    }

    if (rawMemo.size() > ZC_MEMO_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Memo size of %d is too big, maximum allowed is %d", rawMemo.size(), ZC_MEMO_SIZE));
    }

    // copy vector into boost array
    int lenMemo = rawMemo.size();
    for (int i = 0; i < ZC_MEMO_SIZE && i < lenMemo; i++) {
        memo[i] = rawMemo[i];
    }
    return memo;
}

/**
 * Override getStatus() to append the operation's input parameters to the default status object.
 */
UniValue AsyncRPCOperation_sendmany::getStatus() const
{
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }

    UniValue obj = v.get_obj();
    obj.push_back(Pair("method", "v_sendmany"));
    obj.push_back(Pair("params", contextinfo_ ));
    return obj;
}

bool AsyncRPCOperation_sendmany::IsGuiMode()
{
    return isGuiMode;
}

void AsyncRPCOperation_sendmany::SetGuiMode(bool _isGuiMode)
{
    isGuiMode = _isGuiMode;
}


bool AsyncRPCOperation_sendmany::HasSelected() const
{
    return (z_vSelectedInputs.size() > 0);
}

bool AsyncRPCOperation_sendmany::HasSelected_tAddr() const
{
    return (t_vSelectedInputs.size() > 0);
}

bool AsyncRPCOperation_sendmany::IsSelected(const SaplingNoteEntry& noteEntry) const
{
    bool bFind = false;
    vector<SaplingNoteEntry>::const_iterator itor;
    for (itor = z_vSelectedInputs.begin(); itor != z_vSelectedInputs.end(); itor++) {
        if ((itor->op.hash == noteEntry.op.hash) && (itor->op.n == noteEntry.op.n)) {
            bFind = true;
            break;
        }
    }
    return bFind;
}

bool AsyncRPCOperation_sendmany::IsSelected(const SendManyInputUTXO& output) const
{
    bool bFind = false;
    uint256 txidMatch = std::get<0>(output);
    int nVoutIndex = std::get<1>(output);
    for (const SendManyInputUTXO& t : t_vSelectedInputs) {
        uint256 txid = std::get<0>(t);
        int vout = std::get<1>(t);
        if ((txid == txidMatch) && (vout == nVoutIndex)) {
            bFind = true;
            break;
        }
    }
    return bFind;
}

void AsyncRPCOperation_sendmany::Select(const SaplingNoteEntry& noteEntry)
{
    z_vSelectedInputs.push_back(noteEntry);
}

void AsyncRPCOperation_sendmany::Select(const SendManyInputUTXO& output)
{
    t_vSelectedInputs.push_back(output);
}

void AsyncRPCOperation_sendmany::UnSelect(const SaplingNoteEntry& noteEntry)
{
    vector<SaplingNoteEntry>::const_iterator itor;
    for (itor = z_vSelectedInputs.begin(); itor != z_vSelectedInputs.end(); itor++) {
        if ((itor->op.hash == noteEntry.op.hash) && (itor->op.n == noteEntry.op.n)) {
            z_vSelectedInputs.erase(itor);
            break;
        }
    }
}

void AsyncRPCOperation_sendmany::UnSelect(const SendManyInputUTXO& output)
{
    uint256 txidMatch = std::get<0>(output);
    int nVoutIndex = std::get<1>(output);
    vector<SendManyInputUTXO>::const_iterator itor;
    for (itor = t_vSelectedInputs.begin(); itor != t_vSelectedInputs.end(); itor++) {
        uint256 txid = std::get<0>(*itor);
        int vout = std::get<1>(*itor);
        if ((txid == txidMatch) && (vout == nVoutIndex)) {
            t_vSelectedInputs.erase(itor);
            break;
        }
    }
}

void AsyncRPCOperation_sendmany::UnSelectAll()
{
    z_vSelectedInputs.clear();
}

void AsyncRPCOperation_sendmany::UnSelectAll_tAddr()
{
    t_vSelectedInputs.clear();
}

void AsyncRPCOperation_sendmany::ListSelected(std::vector<SaplingNoteEntry>& vNoteEntrys) const
{
    vNoteEntrys.assign(z_vSelectedInputs.begin(), z_vSelectedInputs.end());
}

void AsyncRPCOperation_sendmany::ListSelected(std::vector<SendManyInputUTXO>& vOutpoints) const
{
    vOutpoints.assign(t_vSelectedInputs.begin(), t_vSelectedInputs.end());
}

