// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <queue>
#include <math.h>
#include "clue.h"
#include "cluedb.h"
#include "key_io.h"
#include "serialize.h"
#include "validation.h"
#include <boost/sort/sort.hpp>

CClueCountItem::CClueCountItem(const CClueCountItem& src) : nInvitees(src.nInvitees), nChildren(src.nChildren)
{

}

uint32_t CClueCountItem::childrenCount(bool fInvite) const
{
    return fInvite ? nInvitees : nChildren;
}

CClue::CClue(const std::string& address_, const uint256& txid_, const std::string& inviter_, const std::string& parent_) :
    txid(txid_)
{
    address = DecodeDestination(address_);
    inviter = DecodeDestination(inviter_);
    if (parent_.size() == 0)
        SetTxDestinationNull(parent);
    else
        parent = DecodeDestination(parent_);
}

CClue::CClue(const CTxDestination& address_, const uint256& txid_, const CTxDestination& inviter_, const CTxDestination& parent_):
    txid(txid_),
    address(address_),
    inviter(inviter_),
    parent(parent_)
{
}

CClue::CClue(const CClue& src) :
    txid(src.txid)
{
    address = src.address;
    inviter = src.inviter;
    parent = src.parent;
}

bool CClue::isValid() const
{
    if (address == inviter || address == parent)
        return false;

    if (txid.IsNull() && IsNullTxDestination(inviter) && IsNullTxDestination(parent))
        return false;

    return true;
}

void CClue::SetNull()
{
    address = CNoDestination();
    inviter = CNoDestination();
    parent = CNoDestination();
    txid.SetNull();
}

std::string CClue::toString() const
{
    std::string str;
    str.append("[ addr: " + EncodeDestination(address));
    str.append(", inviter: " + EncodeDestination(inviter));
    str.append(", inDirectParent: " + EncodeDestination(parent));
    str.append(", txid: " + txid.ToString() + "]");
    return str;
}

CTxDestination CClueViewCache::FindClueAbleAddress(const CTxDestination& address, const uint32_t depth) const
{
    std::queue<CTxDestination> queueDest;
    queueDest.push(address);
    uint64_t maxSteps = (1 - pow(Params().ClueChildrenWidth(), depth)) / (1 - Params().ClueChildrenWidth());
    uint64_t nSteps = 0;
    std::vector<CTxDestination> vClueAble;
    vClueAble.clear();
    while (queueDest.size() && maxSteps > 0) {
        CTxDestination root = queueDest.front();
        queueDest.pop();
        maxSteps--;
        nSteps++;
        if (!HaveClue(root) && root != address)
            return CNoDestination();
        if (ChildrenSize(root) < Params().ClueChildrenWidth()) {
            if (nSteps == 1)
                return root;
            vClueAble.push_back(root);
            if (vClueAble.size() >= 12)
                break;
        }

        for (const CTxDestination& dest : cacheClue[root].vChildren)
            queueDest.push(dest);
    }
    if (vClueAble.size() == 0)
        return CNoDestination();

    nSteps = ChildrenSize(address, true);
    int pos = nSteps % vClueAble.size();
    return vClueAble[pos];
    return CNoDestination();
}

uint256 CClueViewCache::GetBestBlock() const
{
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CClueViewCache::SetBestBlock(const uint256& hashBlockIn)
{
    hashBlock = hashBlockIn;
}

bool CClueViewCache::HaveClue(const CTxDestination& dest) const
{
    if (cacheClue.find(dest) != cacheClue.end()) {
        if (cacheClue[dest].flags & CClueEntry::TRUNC && !(cacheClue[dest].flags & CClueEntry::NEW)) { // Truncated not add again.
            return false;
        }
        return true;
    }
    CClue clue;
    if (!base->GetClue(dest, clue)) {
        return false;
    }

    CClueEntry entry(clue);
    cacheClue[dest] = entry;

    base->GetChildren(dest, cacheClue[dest].vInvitees, true);
    base->GetChildren(dest, cacheClue[dest].vChildren, false);

    return true;
}

bool CClueViewCache::AddRoot(const CClue& clue)
{
    LogPrint("clue", "%s address=%s, parent=%s, inviter=%s\n", __func__, EncodeDestination(clue.address).c_str(), EncodeDestination(clue.parent).c_str(), EncodeDestination(clue.inviter).c_str());
    if (HaveClue(clue.address))
        return false;
    if (!IsNullTxDestination(clue.inviter))
        return false;
    if (!IsNullTxDestination(clue.parent))
        return false;

    cacheClue.insert(std::make_pair(clue.address, CClueEntry(clue)));

    if (cacheClue[clue.address].flags & CClueEntry::TRUNC) {
        cacheClue[clue.address].flags ^= CClueEntry::TRUNC;
    }
    cacheClue[clue.address].flags |= CClueEntry::NEW;
    cacheClue[clue.address].MarkDirty();
    return true;
}

bool CClueViewCache::AddClue(const CClue& clue)
{
    LogPrint("clue", "%s address=%s, parent=%s, inviter=%s\n", __func__, EncodeDestination(clue.address).c_str(), EncodeDestination(clue.parent).c_str(), EncodeDestination(clue.inviter).c_str());
    if (HaveClue(clue.address))
        return false;
    if (!HaveClue(clue.inviter))
        return false;
    if (!HaveClue(clue.parent))
        return false;

    if (cacheClue[clue.parent].vChildren.size() >= Params().ClueChildrenWidth())
        return false;

    cacheClue.insert(std::make_pair(clue.address, CClueEntry(clue)));
    cacheClue[clue.inviter].vInvitees.insert(clue.address);
    cacheClue[clue.inviter].MarkDirty();

    cacheClue[clue.parent].vChildren.insert(clue.address);
    cacheClue[clue.parent].MarkDirty();

    cacheClue[clue.address].flags |= CClueEntry::NEW;
    cacheClue[clue.address].MarkDirty();
    return true;
}

bool CClueViewCache::GetClue(const CTxDestination& dest, CClue& clue)
{
    if (HaveClue(dest)) {
        clue = cacheClue[dest].clue;
        return true;
    }
    return false;
}

bool CClueViewCache::IsConflict(const CTxDestination& dest, const uint256& txid) const
{
    if (!HaveClue(dest))
        return false;
    return (cacheClue[dest].clue.txid != txid);
}

bool CClueViewCache::GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite)
{
    if (IsNullTxDestination(dest)) return false;
    if (HaveClue(dest)) {
        parent = fInvite ? cacheClue[dest].clue.inviter : cacheClue[dest].clue.parent;
        if (IsNullTxDestination(cacheClue[dest].clue.inviter)
                && IsNullTxDestination(cacheClue[dest].clue.parent)
                && !cacheClue[dest].clue.txid.IsNull()) /* this is root */
            return true;
        return (parent.type() != typeid(CNoDestination));
    }
    return false;
}

bool CClueViewCache::GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite)
{
    CTxDestination parent;
    if (!GetParent(dest, parent, fInvite))
        return false;
    if (IsNullTxDestination(parent))
        return true;
    vParents.push_back(parent);
    if (vParents.size() >= Params().ClueChildrenDepth())
        return true;
    return GetParents(parent, vParents, fInvite);
}

uint32_t CClueViewCache::ChildrenSize(const CTxDestination& dest, const bool fInvite) const
{
    if (HaveClue(dest)) {
        return fInvite ? cacheClue[dest].vInvitees.size() : cacheClue[dest].vChildren.size();
    }
    return 0;
}

bool CClueViewCache::GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite)
{
    if (!HaveClue(dest))
        return false;

    children = fInvite ? cacheClue[dest].vInvitees : cacheClue[dest].vChildren;
    return false;
}

bool CClueViewCache::IsChildOf(const CTxDestination& dest, const CTxDestination& parent, const bool fInvite) const
{
    if (!HaveClue(parent))
        return false;

    const std::set<CTxDestination>& vChildren = fInvite ? cacheClue[parent].vInvitees : cacheClue[parent].vChildren;

    if (vChildren.find(dest) != vChildren.end())
        return true;
    return false;
}

bool CClueViewCache::DeleteClue(const CTxDestination& dest)
{
    LogPrint("clue", "%s %s\n", __func__, EncodeDestination(dest));
    if (!HaveClue(dest))
        return true;

    CClueEntry& entry = cacheClue[dest];
    // all children is invalid.
    entry.MarkDirty();
    entry.flags |= CClueEntry::TRUNC;
    for (const CTxDestination& child : entry.vInvitees)
        DeleteClue(child);
    for (const CTxDestination& child : entry.vChildren)
        DeleteClue(child);

    // parents should remove this.
    if (!HaveClue(entry.clue.inviter)) {
        return false;
    }

    cacheClue[entry.clue.inviter].vInvitees.erase(dest);
    cacheClue[entry.clue.inviter].MarkDirty();

    if (!HaveClue(entry.clue.parent)) {
        return false;
    }

    cacheClue[entry.clue.parent].vChildren.erase(dest);
    cacheClue[entry.clue.parent].MarkDirty();

    return true;
}

bool CClueViewCache::EraseClue(const CTxDestination& dest)
{
    if (cacheClue.find(dest) != cacheClue.end())
        cacheClue.erase(dest);
    return true;
}

bool CClueViewCache::BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn)
{
    for (CClueMap::iterator it = mapClue.begin(); it != mapClue.end();) {
        if (it->second.flags & CClueEntry::DIRTY) {
            CClueMap::iterator itUs = cacheClue.find(it->first);
            if (itUs == cacheClue.end()) {
                // parent does not have this clue.
                // absolutly this may only happen in new clue add.
                CClueEntry& entry = cacheClue[it->first];
                entry.clue = std::move(it->second.clue);
                entry.vInvitees = std::move(it->second.vInvitees);
                entry.vChildren = std::move(it->second.vChildren);
                entry.flags = it->second.flags;
            } else {
                // parent and cache are dirty.
                // we use cache.
                cacheClue[it->first].clue = std::move(it->second.clue);
                cacheClue[it->first].vInvitees = std::move(it->second.vInvitees);
                cacheClue[it->first].vChildren = std::move(it->second.vChildren);
                cacheClue[it->first].flags = it->second.flags;
            }
        }
        CClueMap::iterator itOld = it++;
        mapClue.erase(itOld);
    }

    for (SeasonRankMap::iterator it = mapSeason.begin(); it != mapSeason.end();) {
        if (it->second.flags & CSeasonStat::DIRTY) {
            SeasonRankMap::iterator itUs = cacheRank.find(it->first);
            if (itUs == cacheRank.end()) {
                CSeasonStat& entry = cacheRank[it->first];
                entry.vTopRank = std::move(it->second.vTopRank);
                entry.nTotalClue = it->second.nTotalClue;
                entry.flags = it->second.flags;

                for (CRankItemMap::iterator it1 = it->second.mRankItems.begin(); it1 != it->second.mRankItems.end();) {
                    CRankItem& item = entry.mRankItems[it1->first];
                    item.dWeight = it1->second.dWeight;
                    item.nInvitees = it1->second.nInvitees;
                    item.nValue = it1->second.nValue;
                    item.flags = it1->second.flags;

                    CRankItemMap::iterator it1Old = it1++;
                    mapSeason[it->first].mRankItems.erase(it1Old);
                }
            } else {
                cacheRank[it->first].vTopRank = std::move(it->second.vTopRank);
                cacheRank[it->first].flags = it->second.flags;
                cacheRank[it->first].nTotalClue = it->second.nTotalClue;

                for (CRankItemMap::iterator it1 = it->second.mRankItems.begin(); it1 != it->second.mRankItems.end();) {
                    CRankItemMap::iterator it1Us = cacheRank[it->first].mRankItems.find(it1->first);
                    if (it1Us == cacheRank[it->first].mRankItems.end()) {
                        CRankItem& item = cacheRank[it->first].mRankItems[it1->first];
                        item.dWeight = it1->second.dWeight;
                        item.nInvitees = it1->second.nInvitees;
                        item.nValue = it1->second.nValue;
                        item.flags = it1->second.flags;

                    } else {
                        cacheRank[it->first].mRankItems[it1->first].dWeight = it1->second.dWeight;
                        cacheRank[it->first].mRankItems[it1->first].nInvitees = it1->second.nInvitees;
                        cacheRank[it->first].mRankItems[it1->first].nValue = it1->second.nValue;
                        cacheRank[it->first].mRankItems[it1->first].flags = it1->second.flags;
                    }
                    CRankItemMap::iterator it1Old = it1++;
                    mapSeason[it->first].mRankItems.erase(it1Old);
                }
            }
        }
        SeasonRankMap::iterator itOld = it++;
        mapSeason.erase(itOld);
    }

    hashBlock = hashBlockIn;
    return true;
}


bool CTopRank::operator < (const CTopRank& b)
{
    if (item.dWeight < b.item.dWeight)
        return false;
    else if (item.dWeight > b.item.dWeight)
        return true;
    if (item.nInvitees < b.item.nInvitees)
        return false;
    else if (item.nInvitees > b.item.nInvitees)
        return true;
    if (address < b.address)
        return false;
    return true;
}

bool CClueViewCache::Flush()
{
    // rank cacheRank
    for (SeasonRankMap::iterator it = cacheRank.begin(); it != cacheRank.end(); it++) {
        cacheRank[it->first].vTopRank.sort();
        if (cacheRank[it->first].vTopRank.size() > 100) {
            cacheRank[it->first].vTopRank.resize(100);
        }
        for (const auto& item : cacheRank[it->first].vTopRank) {
            assert(item.item.nInvitees <= ChildrenSize(item.address, true));
        }
        cacheRank[it->first].flags = CSeasonStat::DIRTY;
    }
    bool fOk = base->BatchWrite(cacheClue, cacheRank, hashBlock);
    cacheClue.clear();
    cacheRank.clear();
    return fOk;
}

bool CClueViewCache::GetParentTree(const CTxDestination& address, CClueFamilyTree& tree, const bool fInvite, const uint32_t uDepth) const
{
    bool fIsRoot = IsClueRoot(address);
    if (!HaveClue(address)) {
        if (!fIsRoot) {
            LogPrint("clue", "%s is not clued\n", EncodeDestination(address));
            return false;
        }
    }

    CTxDestination firstaddr = (fInvite ? FindClueAbleAddress(address, uDepth) : address);
    if ((IsNullTxDestination(firstaddr) || !HaveClue(firstaddr)) && !fIsRoot) {
        LogPrint("clue", "%s is not clued\n", EncodeDestination(firstaddr));
        return false;
    }

    CTxDestination parent = CNoDestination();
    if (cacheClue.find(firstaddr) == cacheClue.end())
        tree.add(firstaddr, 0);
    else {
        tree.add(firstaddr, cacheClue[firstaddr].vChildren.size());
        parent = cacheClue[firstaddr].clue.parent;
    }

    while (!IsNullTxDestination(parent) && HaveClue(parent) && tree.size() < uDepth) {
        tree.add(parent, cacheClue[parent].vChildren.size());
        parent = cacheClue[parent].clue.parent;
    }
    return true;
}

bool CClueViewCache::GetSeasonRank(int nSeason, std::list<CTopRank>& vRank)
{
    if (cacheRank.find(nSeason) == cacheRank.end()) {
        std::list<CTopRank> vRankt;
        if (!base->GetSeasonRank(nSeason, vRankt)) {
            return false;
        }
        cacheRank[nSeason].vTopRank = vRankt;
    }
    vRank = cacheRank[nSeason].vTopRank;
    return true;
}

CAmount CClueViewCache::GetTotalClue(int nSeason)
{
    if (cacheRank.find(nSeason) == cacheRank.end()) {
        std::list<CTopRank> vRankt;
        if (!base->GetSeasonRank(nSeason, vRankt))
            return 0;
        cacheRank[nSeason].vTopRank = vRankt;

        cacheRank[nSeason].nTotalClue = base->GetTotalClue(nSeason);
    }
    if (cacheRank[nSeason].nTotalClue == 0) {
        cacheRank[nSeason].nTotalClue = base->GetTotalClue(nSeason);
    }
    return cacheRank[nSeason].nTotalClue;
}

bool CClueViewCache::GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item)
{
    if (cacheRank.find(nSeason) == cacheRank.end()) {
        std::list<CTopRank> vRank;
        if (!base->GetSeasonRank(nSeason, vRank)) {
            return false;
        }
        cacheRank[nSeason].vTopRank = vRank;
    }
    if ( cacheRank[nSeason].nTotalClue == 0)
        cacheRank[nSeason].nTotalClue = base->GetTotalClue(nSeason);
    if (cacheRank[nSeason].mRankItems.find(dest) == cacheRank[nSeason].mRankItems.end()) {
        CRankItem item;
        if (!base->GetRankItem(dest, nSeason, item))
            return false;
        cacheRank[nSeason].mRankItems[dest] = item;
    }
    item = cacheRank[nSeason].mRankItems[dest];
    return true;
}

bool CClueViewCache::AddRankItem(const CTxDestination& dest, int nSeason, const CRankItem& item)
{
    CRankItem tmp;
    GetRankItem(dest, nSeason, tmp);

    CSeasonStat& stat = cacheRank[nSeason];
    if (stat.mRankItems.find(dest) != stat.mRankItems.end()) {
        if (!(stat.mRankItems[dest].flags & CRankItem::TRUNC))
            assert(stat.nTotalClue > 0);
        stat.mRankItems[dest] += item;
        if (stat.mRankItems[dest].flags & CRankItem::TRUNC)
            stat.mRankItems[dest].flags ^= CRankItem::TRUNC;
        stat.mRankItems[dest].flags |= CRankItem::DIRTY;
        stat.nTotalClue += item.nValue;
        bool fInRank = false;
        for (std::list<CTopRank>::iterator it = stat.vTopRank.begin(); it != stat.vTopRank.end(); it++) {
            if (it->address == dest) {
                fInRank = true;
                it->item += item;
            }
        }
        if (!fInRank)
            stat.vTopRank.push_back(CTopRank(dest, stat.mRankItems[dest]));
        stat.flags |= CSeasonStat::DIRTY;
    } else {
        stat.mRankItems[dest] = item;
        stat.mRankItems[dest].flags |= CRankItem::DIRTY;
        stat.mRankItems[dest].flags |= CRankItem::NEW;
        stat.nTotalClue += item.nValue;
        bool fInRank = false;
        for (std::list<CTopRank>::iterator it = stat.vTopRank.begin(); it != stat.vTopRank.end(); it++) {
            if (it->address == dest) {
                fInRank = true;
                it->item += item;
            }
        }
        if (!fInRank)
            stat.vTopRank.push_back(CTopRank(dest, stat.mRankItems[dest]));
        stat.flags |= CSeasonStat::DIRTY;
    }
    return true;
}

bool CClueViewCache::DeleteRankItem(const CTxDestination& dest, int nSeason)
{
    // delete from rankitem
    // delete from rank
    CRankItem tmp;
    GetRankItem(dest, nSeason, tmp);

    CSeasonStat& stat = cacheRank[nSeason];
    if (stat.mRankItems.find(dest) != stat.mRankItems.end()) {
        stat.mRankItems[dest].SetNull();
        stat.mRankItems[dest].flags |= CRankItem::TRUNC;
        stat.mRankItems[dest].flags |= CRankItem::DIRTY;
        bool fInRank = false;
        for (std::list<CTopRank>::iterator it = stat.vTopRank.begin(); it != stat.vTopRank.end(); it++) {
            if (it->address == dest) {
                fInRank = true;
                std::list<CTopRank>::iterator itOld = it++;
                stat.vTopRank.erase(itOld);
                break;
            }
        }
        stat.flags |= CSeasonStat::DIRTY;
    } else {
        bool fInRank = false;
        for (std::list<CTopRank>::iterator it = stat.vTopRank.begin(); it != stat.vTopRank.end(); it++) {
            if (it->address == dest) {
                fInRank = true;
                std::list<CTopRank>::iterator itOld = it++;
                stat.vTopRank.erase(itOld);
                break;
            }
        }
        if (fInRank)
            stat.flags |= CSeasonStat::DIRTY;
    }
    return true;
}

uint256 CClueView::GetBestBlock() const
{
    return uint256();
}

bool CClueView::HaveClue(const CTxDestination& dest) const
{
    return false;
}

bool CClueView::AddClue(const CClue& clue)
{
    return false;
}

bool CClueView::GetClue(const CTxDestination& dest, CClue& clue)
{
    return false;
}

bool CClueView::IsConflict(const CTxDestination& dest, const uint256& txid) const
{
    return false;
}

bool CClueView::GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite)
{
    return false;
}

bool CClueView::GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite)
{
    return false;
}

uint32_t CClueView::ChildrenSize(const CTxDestination& dest, const bool fInvite) const
{
    return 0;
}

bool CClueView::GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite)
{
    return false;
}

bool CClueView::IsChildOf(const CTxDestination& dest, const CTxDestination& parent, const bool fInvite) const
{
    return false;
}

bool CClueView::DeleteClue(const CTxDestination& dest)
{
    return false;
}

bool CClueView::EraseClue(const CTxDestination& dest)
{
    return false;
}

bool CClueView::BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn)
{
    return false;
}

bool CClueView::Flush()
{
    return false;
}

bool CClueView::GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item)
{
    return false;
}

bool CClueView::AddRankItem(const CTxDestination& dest, int nSeason, const CRankItem& item)
{
    return false;
}

bool CClueView::DeleteRankItem(const CTxDestination& dest, int nSeason)
{
    return false;
}

CAmount CClueView::GetTotalClue(int nSeason)
{
    return 0;
}

bool CClueView::GetSeasonRank(int nSeason, std::list<CTopRank>& vRank)
{
    return false;
}

uint256 CClueViewBacked::GetBestBlock() const
{
    return base->GetBestBlock();
}

bool CClueViewBacked::HaveClue(const CTxDestination& dest) const
{
    return base->HaveClue(dest);
}

bool CClueViewBacked::AddClue(const CClue& clue)
{
    return base->AddClue(clue);
}

bool CClueViewBacked::GetClue(const CTxDestination& dest, CClue& clue)
{
    return base->GetClue(dest, clue);
}

bool CClueViewBacked::IsConflict(const CTxDestination& dest, const uint256& txid) const
{
    return base->IsConflict(dest, txid);
}

bool CClueViewBacked::GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite)
{
    return base->GetParent(dest, parent, fInvite);
}

bool CClueViewBacked::GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite)
{
    return base->GetParents(dest, vParents, fInvite);
}

uint32_t CClueViewBacked::ChildrenSize(const CTxDestination& dest, const bool fInvite) const
{
    return base->ChildrenSize(dest, fInvite);
}

bool CClueViewBacked::GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite)
{
    return base->GetChildren(dest, children, fInvite);
}

bool CClueViewBacked::IsChildOf(const CTxDestination& dest, const CTxDestination& parent, const bool fInvite) const
{
    return base->IsChildOf(dest, parent, fInvite);
}

bool CClueViewBacked::DeleteClue(const CTxDestination& dest)
{
    return base->DeleteClue(dest);
}

bool CClueViewBacked::EraseClue(const CTxDestination& dest)
{
    return base->EraseClue(dest);
}

bool CClueViewBacked::BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn)
{
    return base->BatchWrite(mapClue, mapSeason, hashBlockIn);
}

void CClueViewBacked::SetBackend(CClueView& viewIn)
{
    base = &viewIn;
}

bool CClueViewBacked::GetSeasonRank(int nSeason, std::list<CTopRank>& vRank)
{
    return base->GetSeasonRank(nSeason, vRank);
}

bool CClueViewBacked::GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item)
{
    return base->GetRankItem(dest, nSeason, item);
}

bool CClueViewBacked::AddRankItem(const CTxDestination& dest, int nSeason, const CRankItem& item)
{
    return base->AddRankItem(dest, nSeason, item);
}

CAmount CClueViewBacked::GetTotalClue(int nSeason)
{
    return base->GetTotalClue(nSeason);
}

bool CClueViewBacked::DeleteRankItem(const CTxDestination& dest, int nSeason)
{
    return base->DeleteRankItem(dest, nSeason);
}
