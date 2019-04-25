// Copyright (c) 2017-2020 The Vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_CLUEDB_H
#define VDS_CLUEDB_H

#include "dbwrapper.h"
#include "base58.h"
#include "uint256.h"
#include <boost/multiprecision/cpp_int.hpp>
#include "txdestinationtool.h"
#include "clue.h"



class CClueLevelInfo
{
public:
    CTxDestination address;
    uint32_t childrenCount;

    CClueLevelInfo();
    CClueLevelInfo(const CClueLevelInfo& src);
    CClueLevelInfo(const CTxDestination& address, const uint32_t childrenCount);
    virtual ~CClueLevelInfo() {}

    CClueLevelInfo& operator = (const CClueLevelInfo& src)
    {
        address = src.address;
        childrenCount = src.childrenCount;
        return *this;
    }
};

class CClueFamilyTree
{
public:
    std::list<CClueLevelInfo> parentTree;

private:
    friend class CClueCountItem;
public:
    CClueFamilyTree() {}

    void insertParent(const CTxDestination& parent, const uint32_t childrenCount)
    {
        if (parentTree.size()  && parentTree.front().address == parent)
            return;

        parentTree.push_front(CClueLevelInfo(parent, childrenCount));
    }

    void add(const CTxDestination& parent, const uint32_t childrenCount)
    {
        parentTree.push_back(CClueLevelInfo(parent, childrenCount));
    }

    void clear()
    {
        parentTree.clear();
    }

    size_t size()
    {
        return parentTree.size();
    }

    std::list<CClueLevelInfo>::iterator begin()
    {
        return parentTree.begin();
    }

    std::list<CClueLevelInfo>::iterator end()
    {
        return parentTree.end();
    }
};

class CClueViewDB: public CClueView
{
protected:
    CDBWrapper db;

public:
    CClueViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    uint256 GetBestBlock() const override;

    /** functions overide CClueView **/
    bool HaveClue(const CTxDestination& dest) const override;

    bool GetClue(const CTxDestination& dest, CClue& clue) override;

    bool GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite = false) override;

    bool GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite = false) override;

    uint32_t ChildrenSize(const CTxDestination& dest, const bool fInvite = false) const override;

    bool GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite = false) override;

    bool IsChildOf(const CTxDestination& dest, const CTxDestination& parent, const bool fInvite) const;

    bool BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn) override;

    /** functions for statistic **/
    bool GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item) override;

    bool GetSeasonRank(int nSeason, std::list<CTopRank>& vRank) override;
    CAmount GetTotalClue(int nSeason) override;

    bool Flush() override;
};

#endif // VDS_CLUEDB_H
