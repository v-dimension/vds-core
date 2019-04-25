// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activemasternode.h"
#include "checkpoints.h"
#include "validation.h"
#include "masternode.h"
#include "masternode-payments.h"
#include "masternode-sync.h"
#include "masternodeman.h"
#include "netfulfilledman.h"
#include "ui_interface.h"
#include "util.h"
#include "init.h"

class CMasternodeSync;
CMasternodeSync masternodeSync;

void CMasternodeSync::Fail()
{
    nTimeLastFailure = GetTime();
    nRequestedMasternodeAssets = MASTERNODE_SYNC_FAILED;
}

void CMasternodeSync::Reset()
{
    nRequestedMasternodeAssets = MASTERNODE_SYNC_INITIAL;
    nRequestedMasternodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastBumped = GetTime();
    nTimeLastFailure = 0;
}

void CMasternodeSync::BumpAssetLastTime(std::string strFuncName)
{
    if (IsSynced() || IsFailed()) return;
    nTimeLastBumped = GetTime();
    LogPrint("mnsync", "CMasternodeSync::BumpAssetLastTime -- %s\n", strFuncName);
}

std::string CMasternodeSync::GetAssetName()
{
    switch (nRequestedMasternodeAssets) {
    case (MASTERNODE_SYNC_INITIAL):
        return "MASTERNODE_SYNC_INITIAL";
    case (MASTERNODE_SYNC_WAITING):
        return "MASTERNODE_SYNC_WAITING";
    case (MASTERNODE_SYNC_LIST):
        return "MASTERNODE_SYNC_LIST";
    case (MASTERNODE_SYNC_MNW):
        return "MASTERNODE_SYNC_MNW";
    case (MASTERNODE_SYNC_FAILED):
        return "MASTERNODE_SYNC_FAILED";
    case MASTERNODE_SYNC_FINISHED:
        return "MASTERNODE_SYNC_FINISHED";
    default:
        return "UNKNOWN";
    }
}

void CMasternodeSync::SwitchToNextAsset(CConnman& connman)
{
    switch (nRequestedMasternodeAssets) {
    case (MASTERNODE_SYNC_FAILED):
        throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
        break;
    case (MASTERNODE_SYNC_INITIAL):
        ClearFulfilledRequests(connman);
        nRequestedMasternodeAssets = MASTERNODE_SYNC_WAITING;
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
        break;
    case (MASTERNODE_SYNC_WAITING):
        ClearFulfilledRequests(connman);
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
        nRequestedMasternodeAssets = MASTERNODE_SYNC_LIST;
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
        break;
    case (MASTERNODE_SYNC_LIST):
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
        nRequestedMasternodeAssets = MASTERNODE_SYNC_MNW;
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
        break;
    case (MASTERNODE_SYNC_MNW):
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
        nRequestedMasternodeAssets = MASTERNODE_SYNC_FINISHED;
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
        uiInterface.NotifyAdditionalDataSyncProgressChanged(1);
        //try to activate our masternode if possible
        activeMasternode.ManageState(connman);

        // TODO: Find out whether we can just use LOCK instead of:
        // TRY_LOCK(cs_vNodes, lockRecv);
        // if(lockRecv) { ... }

        connman.ForEachNode(CConnman::AllNodes, [](CNode * pnode) {
            netfulfilledman.AddFulfilledRequest(pnode->addr, "full-sync");
        });
        LogPrint("mnsync", "CMasternodeSync::SwitchToNextAsset -- Sync has finished\n");

        break;
    }
    nRequestedMasternodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    BumpAssetLastTime("CMasternodeSync::SwitchToNextAsset");
}

std::string CMasternodeSync::GetSyncStatus()
{
    switch (masternodeSync.nRequestedMasternodeAssets) {
    case MASTERNODE_SYNC_INITIAL:
        return _("Synchroning blockchain...");
    case MASTERNODE_SYNC_WAITING:
        return _("Synchronization pending...");
    case MASTERNODE_SYNC_LIST:
        return _("Synchronizing masternodes...");
    case MASTERNODE_SYNC_MNW:
        return _("Synchronizing masternode payments...");
    case MASTERNODE_SYNC_FAILED:
        return _("Synchronization failed");
    case MASTERNODE_SYNC_FINISHED:
        return _("Synchronization finished");
    default:
        return "";
    }
}

void CMasternodeSync::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if (IsSynced() || IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrint("mnsync", "SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->id);
    }
}

void CMasternodeSync::ClearFulfilledRequests(CConnman& connman)
{
    // TODO: Find out whether we can just use LOCK instead of:
    // TRY_LOCK(cs_vNodes, lockRecv);
    // if(!lockRecv) return;

    connman.ForEachNode(CConnman::AllNodes, [](CNode * pnode) {
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "spork-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "masternode-list-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "masternode-payment-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "full-sync");
    });
}

void CMasternodeSync::ProcessTick(CConnman& connman)
{
    static int nTick = 0;
    if (nTick++ % MASTERNODE_SYNC_TICK_SECONDS != 0) return;

    // reset the sync process if the last call to this function was more than 60 minutes ago (client was in sleep mode)
    static int64_t nTimeLastProcess = GetTime();
    if (GetTime() - nTimeLastProcess > 60 * 60) {
        LogPrint("mnsync", "CMasternodeSync::HasSyncFailures -- WARNING: no actions for too long, restarting sync...\n");
        Reset();
        SwitchToNextAsset(connman);
        nTimeLastProcess = GetTime();
        return;
    }
    nTimeLastProcess = GetTime();

    // reset sync status in case of any other sync failure
    if (IsFailed()) {
        if (nTimeLastFailure + (1 * 60) < GetTime()) { // 1 minute cooldown after failed sync
            LogPrint("mnsync", "CMasternodeSync::HasSyncFailures -- WARNING: failed to sync, trying again...\n");
            Reset();
            SwitchToNextAsset(connman);
        }
        return;
    }

    // gradually request the rest of the votes after sync finished
    if (IsSynced()) {
//        std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();
//        connman.ReleaseNodeVector(vNodesCopy);
        return;
    }

    // Calculate "progress" for LOG reporting / GUI notification
    double nSyncProgress = double(nRequestedMasternodeAttempt + (nRequestedMasternodeAssets - 1) * 8) / (8 * 4);
    LogPrint("mnsync", "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d nRequestedMasternodeAttempt %d nSyncProgress %f\n", nTick, nRequestedMasternodeAssets, nRequestedMasternodeAttempt, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);

    std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();

    BOOST_FOREACH(CNode * pnode, vNodesCopy) {
        // Don't try to sync any data from outbound "masternode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "masternode" connection
        // initiated from another node, so skip it too.
        if ((fMasterNode && pnode->fInbound)) continue;

        // QUICK MODE (REGTEST ONLY!)
        if (Params().NetworkIDString() == CBaseChainParams::REGTEST) {
            if (nRequestedMasternodeAttempt < 4) {
                mnodeman.DsegUpdate(pnode, connman);
            } else if (nRequestedMasternodeAttempt < 6) {
                int nMnCount = mnodeman.CountMasternodes();
                connman.PushMessage(pnode, NetMsgType::MASTERNODEPAYMENTSYNC, nMnCount); //sync payment votes
            } else {
                nRequestedMasternodeAssets = MASTERNODE_SYNC_FINISHED;
                activeMasternode.ManageState(connman);
            }
            nRequestedMasternodeAttempt++;
            connman.ReleaseNodeVector(vNodesCopy);
            return;
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if (netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrint("mnsync", "CMasternodeSync::ProcessTick -- disconnecting from recently synced peer %d\n", pnode->id);
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC

            if (!netfulfilledman.HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // always get sporks first, only request once from each peer
                netfulfilledman.AddFulfilledRequest(pnode->addr, "spork-sync");
                LogPrint("mnsync", "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d -- requesting sporks from peer %d\n", nTick, nRequestedMasternodeAssets, pnode->id);
            }

            // INITIAL TIMEOUT

            if (nRequestedMasternodeAssets == MASTERNODE_SYNC_WAITING) {
                if (GetTime() - nTimeLastBumped > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    // At this point we know that:
                    // a) there are peers (because we are looping on at least one of them);
                    // b) we waited for at least MASTERNODE_SYNC_TIMEOUT_SECONDS since we reached
                    //    the headers tip the last time (i.e. since we switched from
                    //     MASTERNODE_SYNC_INITIAL to MASTERNODE_SYNC_WAITING and bumped time);
                    // c) there were no blocks (UpdatedBlockTip, NotifyHeaderTip) or headers (AcceptedBlockHeader)
                    //    for at least MASTERNODE_SYNC_TIMEOUT_SECONDS.
                    // We must be at the tip already, let's move to the next asset.
                    SwitchToNextAsset(connman);
                }
            }

            // MNLIST : SYNC MASTERNODE LIST FROM OTHER CONNECTED CLIENTS

            if (nRequestedMasternodeAssets == MASTERNODE_SYNC_LIST) {
                LogPrint("masternode", "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedMasternodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                if (GetTime() - nTimeLastBumped > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrint("mnsync", "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d -- timeout\n", nTick, nRequestedMasternodeAssets);
                    if (nRequestedMasternodeAttempt == 0) {
                        LogPrint("mnsync", "CMasternodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without masternode list, fail here and try later
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "masternode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "masternode-list-sync");

                if (pnode->nVersion < mnpayments.GetMinMasternodePaymentsProto()) continue;
                nRequestedMasternodeAttempt++;

                mnodeman.DsegUpdate(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // MNW : SYNC MASTERNODE PAYMENT VOTES FROM OTHER CONNECTED CLIENTS

            if (nRequestedMasternodeAssets == MASTERNODE_SYNC_MNW) {
                LogPrint("mnpayments", "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedMasternodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                // This might take a lot longer than MASTERNODE_SYNC_TIMEOUT_SECONDS due to new blocks,
                // but that should be OK and it should timeout eventually.
                if (GetTime() - nTimeLastBumped > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrint("mnsync", "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d -- timeout\n", nTick, nRequestedMasternodeAssets);
                    if (nRequestedMasternodeAttempt == 0) {
                        LogPrint("mnsync", "CMasternodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // probably not a good idea to proceed without winner list
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // check for data
                // if mnpayments already has enough blocks and votes, switch to the next asset
                // try to fetch data from at least two peers though
                if (nRequestedMasternodeAttempt > 1 && mnpayments.IsEnoughData()) {
                    LogPrint("mnsync", "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d -- found enough data\n", nTick, nRequestedMasternodeAssets);
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "masternode-payment-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "masternode-payment-sync");

                if (pnode->nVersion < mnpayments.GetMinMasternodePaymentsProto()) continue;
                nRequestedMasternodeAttempt++;

                // ask node for all payment votes it has (new nodes will only return votes for future payments)
                connman.PushMessage(pnode, NetMsgType::MASTERNODEPAYMENTSYNC, mnpayments.GetStorageLimit());
                // ask node for missing pieces only (old nodes will not be asked)
                mnpayments.RequestLowDataPaymentBlocks(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // GOVOBJ : SYNC GOVERNANCE ITEMS FROM OUR PEERS

        }
    }
    // looped through all nodes, release them
    connman.ReleaseNodeVector(vNodesCopy);
}

void CMasternodeSync::AcceptedBlockHeader(const CBlockIndex* pindexNew)
{
    LogPrint("mnsync", "CMasternodeSync::AcceptedBlockHeader -- pindexNew->nHeight: %d\n", pindexNew->nHeight);

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block header arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::AcceptedBlockHeader");
    }
}

void CMasternodeSync::NotifyHeaderTip(const CBlockIndex* pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint("mnsync", "CMasternodeSync::NotifyHeaderTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::NotifyHeaderTip");
    }
}

void CMasternodeSync::UpdatedBlockTip(const CBlockIndex* pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint("mnsync", "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::UpdatedBlockTip");
    }

    if (fInitialDownload) {
        // switched too early
        if (IsBlockchainSynced()) {
            Reset();
        }

        // no need to check any further while still in IBD mode
        return;
    }

    // Note: since we sync headers first, it should be ok to use this
    static bool fReachedBestHeader = false;
    bool fReachedBestHeaderNew = pindexNew->GetBlockHash() == pindexBestHeader->GetBlockHash();

    if (fReachedBestHeader && !fReachedBestHeaderNew) {
        // Switching from true to false means that we previousely stuck syncing headers for some reason,
        // probably initial timeout was not enough,
        // because there is no way we can update tip not having best header
        Reset();
        fReachedBestHeader = false;
        return;
    }

    fReachedBestHeader = fReachedBestHeaderNew;

    LogPrint("mnsync", "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d pindexBestHeader->nHeight: %d fInitialDownload=%d fReachedBestHeader=%d\n",
             pindexNew->nHeight, pindexBestHeader->nHeight, fInitialDownload, fReachedBestHeader);

    if (!IsBlockchainSynced() && fReachedBestHeader) {
        // Reached best header while being in initial mode.
        // We must be at the tip already, let's move to the next asset.
        SwitchToNextAsset(connman);
    }
}

void ThreadCheckMasternodeSync(CConnman& connman)
{
    if (fLiteMode) return; // disable all vds specific functionality

    static bool fOneThread;
    if (fOneThread) return;
    fOneThread = true;

    // Make this thread recognisable as the MasternodeSync thread
    RenameThread("masternode-ps");

    unsigned int nTick = 0;

    while (true) {
        MilliSleep(1000);
        //MilliSleep(10000000); //only for debug

        // try to sync from all available nodes, one step at a time
        masternodeSync.ProcessTick(connman);

        if (masternodeSync.IsBlockchainSynced() && !ShutdownRequested()) {

            nTick++;
            // gmnanonman.SendAllMessages();


            // make sure to check all masternodes first
            mnodeman.Check();

            // check if we should activate or ping every few minutes,
            // slightly postpone first run to give net thread a chance to connect to some peers
//            if(nTick % MASTERNODE_MIN_MNP_SECONDS == 15)
//                activeMasternode.ManageState(connman);

            if (nTick % 10 == 0)
                activeMasternode.ManageState(connman);


            if (nTick % 60 == 0) {
                mnodeman.ProcessMasternodeConnections(connman);
                mnodeman.CheckAndRemove(connman);
                mnpayments.CheckAndRemove();
                //instantsend.CheckAndRemove();
            }
            if (fMasterNode && (nTick % (10 * 60) == 0)) {  // TODO: 60 for normal
                mnodeman.DoFullVerificationStep(connman);
            }
        }
    }
}

