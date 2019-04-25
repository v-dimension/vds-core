// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_VALIDATIONINTERFACE_H
#define VDS_VALIDATIONINTERFACE_H

#include <primitives/transaction.h> // CTransaction(Ref)

#include <boost/signals2/signal.hpp>
#include <boost/shared_ptr.hpp>

#include "vds/IncrementalMerkleTree.hpp"

class CBlock;
struct CBlockLocator;
class CBlockIndex;
class CLNBlock;
class CLNBlockIndex;
class CConnman;
class CReserveScript;
class CValidationInterface;
class CValidationState;
class uint256;
class CScheduler;
class CTxMemPool;
class CAd;
enum class MemPoolRemovalReason;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();
/**
 * Pushes a function to callback onto the notification queue, guaranteeing any
 * callbacks generated prior to now are finished when the function is called.
 *
 * Be very careful blocking on func to be called if any locks are held -
 * validation interface clients may not be able to make progress as they often
 * wait for things like cs_main, so blocking until func is called with cs_main
 * will result in a deadlock (that DEBUG_LOCKORDER will miss).
 */
void CallFunctionInValidationInterfaceQueue(std::function<void ()> func);
/**
 * This is a synonym for the following, which asserts certain locks are not
 * held:
 *     std::promise<void> promise;
 *     CallFunctionInValidationInterfaceQueue([&promise] {
 *         promise.set_value();
 *     });
 *     promise.get_future().wait();
 */
void SyncWithValidationInterfaceQueue();

class CValidationInterface
{
protected:
    virtual void AcceptedBlockHeader(const CBlockIndex* pindexNew) {}
    /**
     * Notifies listeners of a transaction having been added to mempool.
     *
     * Called on a background thread.
     */
    virtual void TransactionAddedToMempool(const CTransactionRef& ptxn) {}
    /**
     * Notifies listeners of a transaction leaving mempool.
     *
     * This only fires for transactions which leave mempool because of expiry,
     * size limiting, reorg (changes in lock times/coinbase maturity), or
     * replacement. This does not include any transactions which are included
     * in BlockConnectedDisconnected either in block->vtx or in txnConflicted.
     *
     * Called on a background thread.
     */
    virtual void TransactionRemovedFromMempool(const CTransactionRef& ptx) {}

    virtual void NotifyHeaderTip(const CBlockIndex* pindexNew, bool fInitialDownload) {}
    virtual void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) {}
    virtual void SyncTransaction(const CTransactionRef& tx, const CBlockIndex* pblock, int posInBlock) {}
    virtual void NotifyTransactionLock(const CTransaction& tx) {}
    virtual void ChainTip(const CBlockIndex* pindex, const CBlock* pblock, SaplingMerkleTree saplingTree, bool added) {}
    virtual void SetBestChain(const CBlockLocator& locator) {}
    virtual bool UpdatedTransaction(const uint256& hash)
    {
        return false;
    }
    virtual void Inventory(const uint256& hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBlockTime) {}
    virtual void BlockChecked(const CBlock&, const CValidationState&) {}
    virtual void ResetRequestCount(const uint256& hash) {}
    virtual void NotifyContractReceived(const uint256& hash) {}
    virtual void NotifyAdReceived(const uint256& hash, const CAd& ad) {}
    virtual void UpdatedLNBlockTip(const CLNBlockIndex* pindexNew, const CLNBlockIndex* pindexFork, bool fInitialDownload) {}
    virtual void LNBlockChecked(const CLNBlock& block, const CValidationState& state) {}

    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct MainSignalsInstance;
class CMainSignals
{
private:
    std::unique_ptr<MainSignalsInstance> m_internals;

    friend void RegisterValidationInterface(CValidationInterface*);
    friend void UnregisterValidationInterface(CValidationInterface*);
    friend void UnregisterAllValidationInterfaces();
    friend void CallFunctionInValidationInterfaceQueue(std::function<void ()> func);

    void MempoolEntryRemoved(CTransactionRef tx, MemPoolRemovalReason reason);

public:
    /** Register a CScheduler to give callbacks which should run in the background (may only be called once) */
    void RegisterBackgroundSignalScheduler(CScheduler& scheduler);
    /** Unregister a CScheduler to give callbacks which should run in the background - these callbacks will now be dropped! */
    void UnregisterBackgroundSignalScheduler();
    /** Call any remaining callbacks on the calling thread */
    void FlushBackgroundCallbacks();

    size_t CallbacksPending();

    /** Register with mempool to call TransactionRemovedFromMempool callbacks */
    void RegisterWithMempoolSignals(CTxMemPool& pool);
    /** Unregister with mempool */
    void UnregisterWithMempoolSignals(CTxMemPool& pool);

    void AcceptedBlockHeader(const CBlockIndex*);
    void NotifyHeaderTip(const CBlockIndex*, bool fInitialDownload);
    void UpdatedBlockTip(const CBlockIndex*, const CBlockIndex*, bool fInitialDownload);
    void SyncTransaction(const CTransactionRef&, const CBlockIndex*, int posInBlock);
    void TransactionAddedToMempool(const CTransactionRef&);
    void NotifyTransactionLock(const CTransaction&);
    void UpdatedTransaction(const uint256&);
    void ChainTip(const CBlockIndex*, const CBlock*, SaplingMerkleTree, bool);
    void SetBestChain(const CBlockLocator&);
    void Inventory(const uint256&);
    void Broadcast(int64_t nBestBlockTime);
    void BlockChecked(const CBlock&, const CValidationState&);
    void ScriptForMining(boost::shared_ptr<CReserveScript>& );
    void BlockFound(const uint256&);
    void NotifyContractReceived(const uint256&);
    void NotifyAdReceived(const uint256& hash, const CAd& ad);
    void UpdatedLNBlockTip(const CLNBlockIndex* pindexNew, const CLNBlockIndex* pindexFork, bool fInitialDownload);
    void LNBlockChecked(const CLNBlock& block, const CValidationState& state);
};

CMainSignals& GetMainSignals();

#endif // VDS_VALIDATIONINTERFACE_H
