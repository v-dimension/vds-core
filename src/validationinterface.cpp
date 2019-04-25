// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"
#include <txmempool.h>
#include <scheduler.h>
#include <sync.h>
#include <validation.h>

#include <list>
#include <atomic>
#include <future>

struct MainSignalsInstance {
    /** Notifies listeners of accepted block header */
    boost::signals2::signal<void (const CBlockIndex*)> AcceptedBlockHeader;
    /** Notifies listeners of updated block header tip */
    boost::signals2::signal<void (const CBlockIndex*, bool fInitialDownload)> NotifyHeaderTip;
    /** Notifies listeners of updated block chain tip */
    boost::signals2::signal<void (const CBlockIndex*, const CBlockIndex*, bool fInitialDownload)> UpdatedBlockTip;
    /** Notifies listeners of updated transaction data (transaction, and optionally the block it is found in. */
    boost::signals2::signal<void (const CTransactionRef&, const CBlockIndex*, int posInBlock)> SyncTransaction;
    /** Notifies listeners of transaction added to mempool **/
    boost::signals2::signal<void (const CTransactionRef&)> TransactionAddedToMempool;
    /** Notifies listeners of transaction removed from mempool **/
    boost::signals2::signal<void (const CTransactionRef&)> TransactionRemovedFromMempool;
    /** Notifies listeners of an updated transaction lock without new data. */
    boost::signals2::signal<void (const CTransaction&)> NotifyTransactionLock;
    /** Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible). */
    boost::signals2::signal<bool (const uint256&)> UpdatedTransaction;
    /** Notifies listeners of a change to the tip of the active block chain. */
    boost::signals2::signal<void (const CBlockIndex*, const CBlock*, SaplingMerkleTree, bool)> ChainTip;
    /** Notifies listeners of a new active block chain. */
    boost::signals2::signal<void (const CBlockLocator&)> SetBestChain;
    /** Notifies listeners about an inventory item being seen on the network. */
    boost::signals2::signal<void (const uint256&)> Inventory;
    /** Tells listeners to broadcast their data. */
    boost::signals2::signal<void (int64_t nBestBlockTime)> Broadcast;
    /** Notifies listeners of a block validation result */
    boost::signals2::signal<void (const CBlock&, const CValidationState&)> BlockChecked;
    /** Notifies listeners that a block has been successfully mined */
    boost::signals2::signal<void (const uint256&)> BlockFound;
    /** Notifies listeners that a block has been successfully mined */
    boost::signals2::signal<void (const uint256&)> NotifyContractReceived;
    boost::signals2::signal<void (const uint256&, const CAd&)> NotifyAdReceived;

    // We are not allowed to assume the scheduler only runs in one thread,
    // but must ensure all callbacks happen in-order, so we end up creating
    // our own queue here :(
    SingleThreadedSchedulerClient m_schedulerClient;

    explicit MainSignalsInstance(CScheduler* pscheduler) : m_schedulerClient(pscheduler) {}
};

static CMainSignals g_signals;

void CMainSignals::RegisterBackgroundSignalScheduler(CScheduler& scheduler)
{
    assert(!m_internals);
    m_internals.reset(new MainSignalsInstance(&scheduler));
}

void CMainSignals::UnregisterBackgroundSignalScheduler()
{
    m_internals.reset(nullptr);
}

void CMainSignals::FlushBackgroundCallbacks()
{
    if (m_internals) {
        m_internals->m_schedulerClient.EmptyQueue();
    }
}

void CMainSignals::MempoolEntryRemoved(CTransactionRef ptx, MemPoolRemovalReason reason)
{
    if (reason != MemPoolRemovalReason::BLOCK && reason != MemPoolRemovalReason::CONFLICT) {
        m_internals->m_schedulerClient.AddToProcessQueue([ptx, this] {
            m_internals->TransactionRemovedFromMempool(ptx);
        });
    }
}

size_t CMainSignals::CallbacksPending()
{
    if (!m_internals) return 0;
    return m_internals->m_schedulerClient.CallbacksPending();
}

void CMainSignals::RegisterWithMempoolSignals(CTxMemPool& pool)
{
    pool.NotifyEntryRemoved.connect(boost::bind(&CMainSignals::MempoolEntryRemoved, this, _1, _2));
}

void CMainSignals::UnregisterWithMempoolSignals(CTxMemPool& pool)
{
    pool.NotifyEntryRemoved.disconnect(boost::bind(&CMainSignals::MempoolEntryRemoved, this, _1, _2));
}

void CMainSignals::AcceptedBlockHeader(const CBlockIndex* pindexNew)
{
    m_internals->m_schedulerClient.AddToProcessQueue([pindexNew, this] {
        m_internals->AcceptedBlockHeader(pindexNew);
    });
}

void CMainSignals::NotifyHeaderTip(const CBlockIndex* pindexNew, bool fInitialDownload)
{
    m_internals->m_schedulerClient.AddToProcessQueue([pindexNew, fInitialDownload, this] {
        m_internals->NotifyHeaderTip(pindexNew, fInitialDownload);
    });
}

void CMainSignals::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
{
    // Dependencies exist that require UpdatedBlockTip events to be delivered in the order in which
    // the chain actually updates. One way to ensure this is for the caller to invoke this signal
    // in the same critical section where the chain is updated

    m_internals->m_schedulerClient.AddToProcessQueue([pindexNew, pindexFork, fInitialDownload, this] {
        m_internals->UpdatedBlockTip(pindexNew, pindexFork, fInitialDownload);
    });
}

void CMainSignals::TransactionAddedToMempool(const CTransactionRef& ptx)
{
    m_internals->m_schedulerClient.AddToProcessQueue([ptx, this] {
        m_internals->TransactionAddedToMempool(ptx);
    });
}

void CMainSignals::SyncTransaction(const CTransactionRef& tx, const CBlockIndex* pindexNew, int posInBlock)
{
    m_internals->m_schedulerClient.AddToProcessQueue([tx, pindexNew, posInBlock, this] {
        m_internals->SyncTransaction(tx, pindexNew, posInBlock);
    });
}

void CMainSignals::NotifyTransactionLock(const CTransaction& tx)
{
    m_internals->m_schedulerClient.AddToProcessQueue([tx, this] {
        m_internals->NotifyTransactionLock(tx);
    });
}

void CMainSignals::UpdatedTransaction(const uint256& txid)
{
    m_internals->m_schedulerClient.AddToProcessQueue([txid, this] {
        m_internals->UpdatedTransaction(txid);
    });
}


void CMainSignals::ChainTip(const CBlockIndex* pindexNew, const CBlock* pblock, SaplingMerkleTree tree, bool added)
{
    m_internals->ChainTip(pindexNew, pblock, tree, added);
}

void CMainSignals::SetBestChain(const CBlockLocator& locator)
{
    m_internals->m_schedulerClient.AddToProcessQueue([locator, this] {
        m_internals->SetBestChain(locator);
    });
}

void CMainSignals::Inventory(const uint256& hash)
{
    m_internals->m_schedulerClient.AddToProcessQueue([hash, this] {
        m_internals->Inventory(hash);
    });
}

void CMainSignals::BlockChecked(const CBlock& block, const CValidationState& state)
{
    m_internals->BlockChecked(block, state);
}

void CMainSignals::Broadcast(int64_t nBestBlockTime)
{
    m_internals->Broadcast(nBestBlockTime);
}

void CMainSignals::BlockFound(const uint256& hash)
{
    m_internals->m_schedulerClient.AddToProcessQueue([hash, this] {
        m_internals->BlockFound(hash);
    });
}

void CMainSignals::NotifyContractReceived(const uint256& txid)
{
    m_internals->m_schedulerClient.AddToProcessQueue([txid, this] {
        m_internals->NotifyContractReceived(txid);
    });
}

void CMainSignals::NotifyAdReceived(const uint256& hash, const CAd& ad)
{
    m_internals->m_schedulerClient.AddToProcessQueue([hash, ad, this] {
        m_internals->NotifyAdReceived(hash, ad);
    });
}

CMainSignals& GetMainSignals()
{
    return g_signals;
}


void RegisterValidationInterface(CValidationInterface* pwalletIn)
{
    g_signals.m_internals->AcceptedBlockHeader.connect(boost::bind(&CValidationInterface::AcceptedBlockHeader, pwalletIn, _1));
    g_signals.m_internals->NotifyHeaderTip.connect(boost::bind(&CValidationInterface::NotifyHeaderTip, pwalletIn, _1, _2));
    g_signals.m_internals->TransactionAddedToMempool.connect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, _1));
    g_signals.m_internals->TransactionRemovedFromMempool.connect(boost::bind(&CValidationInterface::TransactionRemovedFromMempool, pwalletIn, _1));
    g_signals.m_internals->UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1, _2, _3));
    g_signals.m_internals->SyncTransaction.connect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.m_internals->NotifyContractReceived.connect(boost::bind(&CValidationInterface::NotifyContractReceived, pwalletIn, _1));
    g_signals.m_internals->NotifyTransactionLock.connect(boost::bind(&CValidationInterface::NotifyTransactionLock, pwalletIn, _1));
    g_signals.m_internals->UpdatedTransaction.connect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.m_internals->ChainTip.connect(boost::bind(&CValidationInterface::ChainTip, pwalletIn, _1, _2, _3, _4));
    g_signals.m_internals->SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.m_internals->Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.m_internals->Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1));
    g_signals.m_internals->BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.m_internals->BlockFound.connect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.m_internals->NotifyAdReceived.connect(boost::bind(&CValidationInterface::NotifyAdReceived, pwalletIn, _1, _2));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn)
{
    g_signals.m_internals->BlockFound.disconnect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.m_internals->TransactionAddedToMempool.disconnect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, _1));
    g_signals.m_internals->TransactionRemovedFromMempool.disconnect(boost::bind(&CValidationInterface::TransactionRemovedFromMempool, pwalletIn, _1));
    g_signals.m_internals->BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.m_internals->Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1));
    g_signals.m_internals->Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.m_internals->NotifyContractReceived.disconnect(boost::bind(&CValidationInterface::NotifyContractReceived, pwalletIn, _1));
    g_signals.m_internals->ChainTip.disconnect(boost::bind(&CValidationInterface::ChainTip, pwalletIn, _1, _2, _3, _4));
    g_signals.m_internals->SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.m_internals->UpdatedTransaction.disconnect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.m_internals->NotifyTransactionLock.disconnect(boost::bind(&CValidationInterface::NotifyTransactionLock, pwalletIn, _1));
    g_signals.m_internals->SyncTransaction.disconnect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.m_internals->UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1, _2, _3));
    g_signals.m_internals->NotifyHeaderTip.disconnect(boost::bind(&CValidationInterface::NotifyHeaderTip, pwalletIn, _1, _2));
    g_signals.m_internals->AcceptedBlockHeader.disconnect(boost::bind(&CValidationInterface::AcceptedBlockHeader, pwalletIn, _1));
    g_signals.m_internals->NotifyAdReceived.disconnect(boost::bind(&CValidationInterface::NotifyAdReceived, pwalletIn, _1, _2));
}

void UnregisterAllValidationInterfaces()
{
    g_signals.m_internals->BlockFound.disconnect_all_slots();
    g_signals.m_internals->TransactionAddedToMempool.disconnect_all_slots();
    g_signals.m_internals->TransactionRemovedFromMempool.disconnect_all_slots();
    g_signals.m_internals->BlockChecked.disconnect_all_slots();
    g_signals.m_internals->Broadcast.disconnect_all_slots();
    g_signals.m_internals->Inventory.disconnect_all_slots();
    g_signals.m_internals->ChainTip.disconnect_all_slots();
    g_signals.m_internals->SetBestChain.disconnect_all_slots();
    g_signals.m_internals->UpdatedTransaction.disconnect_all_slots();
    g_signals.m_internals->NotifyContractReceived.disconnect_all_slots();
    g_signals.m_internals->NotifyTransactionLock.disconnect_all_slots();
    g_signals.m_internals->SyncTransaction.disconnect_all_slots();
    g_signals.m_internals->UpdatedBlockTip.disconnect_all_slots();
    g_signals.m_internals->NotifyHeaderTip.disconnect_all_slots();
    g_signals.m_internals->AcceptedBlockHeader.disconnect_all_slots();
    g_signals.m_internals->NotifyAdReceived.disconnect_all_slots();
}

void CallFunctionInValidationInterfaceQueue(std::function<void ()> func)
{
    g_signals.m_internals->m_schedulerClient.AddToProcessQueue(std::move(func));
}

void SyncWithValidationInterfaceQueue()
{
    AssertLockNotHeld(cs_main);
    // Block until the validation queue drains
    std::promise<void> promise;
    CallFunctionInValidationInterfaceQueue([&promise] {
        promise.set_value();
    });
    promise.get_future().wait();
}



