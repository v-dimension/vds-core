// Copyright (c) 2017-2020 The Vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cluedb.h"
#include "serialize.h"
#include "validation.h"
#include "util.h"
#include <key_io.h>
#include <boost/concept_check.hpp>
#include <validation.h>
#include <utilstrencodings.h>

using namespace std;

#define CLUE_TABLE_CLUE             'a'
#define CLUE_TABLE_CHILD_INVITE     'b'
#define CLUE_TABLE_CHILD_TREE       'c'
#define CLUE_TABLE_CHILD_COUNT      'd'
#define CLUE_TABLE_BEST_BLOCK       'B'

#define CLUE_RANK_ITEM              'r'
#define CLUE_RANK_TOP               'R'
#define CLUE_RANK_TOTAL             't'
//clue table: key = address, value = clue
#define CLUE_KEY_ADDR(address) make_pair(CLUE_TABLE_CLUE, address)

//children count table: key = parent addres, value CClueCountItem
#define CLUE_KEY_CHILD_COUNT(address) make_pair(CLUE_TABLE_CHILD_COUNT, address)

#define CLUE_KEY_CHILD(address, fInvite, count) std::make_pair(std::make_pair( fInvite ? CLUE_TABLE_CHILD_INVITE : CLUE_TABLE_CHILD_TREE, address), count)

#define CLUE_KEY_RANK_ITEM(nSeason, address) std::make_pair(std::make_pair(CLUE_RANK_ITEM, nSeason), address)


CClueLevelInfo::CClueLevelInfo() : childrenCount(0)
{
    SetTxDestinationNull(address);
}

CClueLevelInfo::CClueLevelInfo(const CClueLevelInfo& src) : childrenCount(src.childrenCount),
    address(src.address)
{
}

CClueLevelInfo::CClueLevelInfo(const CTxDestination& address, const uint32_t childrenCount)
{
    this->childrenCount = childrenCount;
    this->address = address;
}

CClueViewDB::CClueViewDB(size_t nCacheSize, bool fMemory, bool fWipe):
    db(GetDataDir() / "clues", nCacheSize, fMemory, fWipe)
{
}

uint256 CClueViewDB::GetBestBlock() const
{
    uint256 hashBestChain;
    if (!db.Read(CLUE_TABLE_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

bool CClueViewDB::HaveClue(const CTxDestination& dest) const
{
    return db.Exists(CLUE_KEY_ADDR(dest));
}

bool CClueViewDB::GetClue(const CTxDestination& dest, CClue& clue)
{
    return db.Read(CLUE_KEY_ADDR(dest), clue);
}

bool CClueViewDB::GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite)
{
    CClue clue;
    if (db.Read(CLUE_KEY_ADDR(dest), clue)) {
        parent = (fInvite ? clue.inviter : clue.parent);
        return true;
    }
    return false;
}

bool CClueViewDB::GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite)
{
    return false;
}

uint32_t CClueViewDB::ChildrenSize(const CTxDestination& dest, const bool fInvite) const
{
    CClueCountItem item;
    if (db.Read(CLUE_KEY_CHILD_COUNT(dest), item))
        return fInvite ? item.nInvitees : item.nChildren;
    return 0;
}

bool CClueViewDB::GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite)
{
    CClueCountItem item;
    if (!db.Read(CLUE_KEY_CHILD_COUNT(dest), item))
        return false;
    uint32_t count = fInvite ? item.nInvitees : item.nChildren;
    for (uint32_t i = 0; i < count; i++) {
        CTxDestination child;
        if (db.Read(CLUE_KEY_CHILD(dest, fInvite, i), child)) {
            children.insert(child);
        }
    }
    if (children.size() != count)
        return error("Fatal: children does not match count item.");
    return true;
}

bool CClueViewDB::IsChildOf(const CTxDestination& child, const CTxDestination& parent, const bool fInvite) const
{
    CClueCountItem item;
    if (!db.Read(CLUE_KEY_CHILD_COUNT(parent), item))
        return false;
    uint32_t count = fInvite ? item.nInvitees : item.nChildren;
    for (uint32_t i = 0; i < count; i++) {
        CTxDestination tmpchild;
        if (db.Read(CLUE_KEY_CHILD(parent, fInvite, i), tmpchild)) {
            if (tmpchild == child)
                return true;
        }
    }

    return false;
}

bool CClueViewDB::BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn)
{
    CDBBatch batch(this->db);
    uint32_t count = 0;
    for (CClueMap::iterator it = mapClue.begin(); it != mapClue.end();) {
        if (it->second.flags & CClueEntry::DIRTY) {
            const CClue& clue = it->second.clue;
            const std::set<CTxDestination>& vInvitees = it->second.vInvitees;
            const std::set<CTxDestination>& vChildren = it->second.vChildren;
            if (it->second.flags & CClueEntry::TRUNC) {
                batch.Erase(CLUE_KEY_ADDR(clue.address));

                for (uint32_t i = 0; i < vInvitees.size(); i++ )
                    batch.Erase(CLUE_KEY_CHILD(clue.address, true, i));

                for (uint32_t i = 0; i < vChildren.size(); i++ )
                    batch.Erase(CLUE_KEY_CHILD(clue.address, false, i));

                batch.Erase(CLUE_KEY_CHILD_COUNT(clue.address));
            } else {
                batch.Write(CLUE_KEY_ADDR(clue.address), clue);

                uint32_t i = 0;
                for (std::set<CTxDestination>::const_iterator itchild = vInvitees.begin(); itchild != vInvitees.end(); i++, itchild++ )
                    batch.Write(CLUE_KEY_CHILD(clue.address, true, i), *itchild);

                i = 0;
                for (std::set<CTxDestination>::const_iterator itchild = vChildren.begin(); i < vChildren.size() && itchild != vChildren.end(); i++, itchild++ )
                    batch.Write(CLUE_KEY_CHILD(clue.address, false, i), *itchild);

                CClueCountItem item(vInvitees.size(), vChildren.size());
                batch.Write(CLUE_KEY_CHILD_COUNT(clue.address), item);
            }
        }
        CClueMap::iterator itOld = it++;
        count ++;
        mapClue.erase(itOld);

    }

    for (SeasonRankMap::iterator it = mapSeason.begin(); it != mapSeason.end();) {
        if (it->second.flags & CSeasonStat::DIRTY) {
            // write all rank items.
            for (CRankItemMap::iterator it1 = it->second.mRankItems.begin(); it1 != it->second.mRankItems.end();) {
                if (it1->second.flags & CRankItem::TRUNC) {
                    batch.Erase(CLUE_KEY_RANK_ITEM(it->first, it1->first));
                } else {
                    if (it1->second.flags & CRankItem::DIRTY) {
                        batch.Write(CLUE_KEY_RANK_ITEM(it->first, it1->first), it1->second);
                    }
                }
                CRankItemMap::iterator it1old = it1++;
                it->second.mRankItems.erase(it1old);
            }
            batch.Write(std::make_pair(CLUE_RANK_TOP, it->first), it->second.vTopRank);
            if (it->second.nTotalClue >= 0)
                batch.Write(std::make_pair(CLUE_RANK_TOTAL, it->first), it->second.nTotalClue);
            // write rank
        }
        SeasonRankMap::iterator itold = it++;
        mapSeason.erase(itold);
    }
    if (!hashBlockIn.IsNull())
        batch.Write(CLUE_TABLE_BEST_BLOCK, hashBlockIn);
    return db.WriteBatch(batch);
}

bool CClueViewDB::GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item)
{
    return db.Read(CLUE_KEY_RANK_ITEM(nSeason, dest), item);
}

bool CClueViewDB::GetSeasonRank(int nSeason, std::list<CTopRank>& vRank)
{
    return db.Read(std::make_pair(CLUE_RANK_TOP, nSeason), vRank);
}

CAmount CClueViewDB::GetTotalClue(int nSeason)
{
    CAmount a;
    if (!db.Read(std::make_pair(CLUE_RANK_TOTAL, nSeason), a))
        return 0;
    return a;
}

bool CClueViewDB::Flush()
{
    return false;
}
