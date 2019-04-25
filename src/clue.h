// Copyright (c) 2014-2019 The vds Core developers

#ifndef VDS_CLUE_H
#define VDS_CLUE_H

#include <pubkey.h>
#include "txdestinationtool.h"
#include <uint256.h>
#include <serialize.h>
#include <vector>
#include <map>

#define FAMILY_TREE_MAX_LEVEL 12


class CClue
{
public:
    uint256 txid;

    CTxDestination address;
    CTxDestination inviter;         //logical parent node, this node may not be the physic parent
    CTxDestination parent;        //physical parent node, this node was direct physic parent, but may be different with logic parent.

public:
    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(txid);
        READWRITE(address);
        READWRITE(inviter);
        READWRITE(parent);
    }

    CClue(const std::string& address_, const uint256& txid_, const std::string& inviter, const std::string& parent = "");
    CClue(const CTxDestination& address_, const uint256& txid_, const CTxDestination& inviter, const CTxDestination& parent = CNoDestination());

    CClue(const CClue& src);

    CClue()
    {
        SetNull();
    }

    bool isParentOf(const CClue& child, const bool fInvite) const
    {
        return fInvite ? address == child.inviter : address == child.parent;
    }

    bool isValid() const;

    void SetNull();

    std::string toString() const;

    CClue& operator = (const CClue& src)
    {
        txid = src.txid;
        address = src.address;
        inviter = src.inviter;
        parent = src.parent;
        return *this;
    }
};

struct CClueCountItem {
public:
    uint32_t nInvitees;    // count of logical children.
    uint32_t nChildren;  // cout of physical children.

    CClueCountItem() : nChildren(0), nInvitees(0)
    {
    }

    CClueCountItem(const uint32_t nDirectIn, const uint32_t nIndirectIn) :
        nChildren(nIndirectIn), nInvitees(nDirectIn)
    {
    }

    virtual ~CClueCountItem()
    {
    }

    CClueCountItem(const CClueCountItem& src);
    uint32_t childrenCount(bool fInvite = false) const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nInvitees);
        READWRITE(nChildren);
    }

    CClueCountItem& operator = (CClueCountItem& item)
    {
        nInvitees = item.nInvitees;
        nChildren = item.nChildren;
        return *this;
    }
};


struct CRankItem {
public:
    CAmount nValue;
    int32_t nInvitees;
    double dWeight;

    unsigned char flags;
    enum {
        DIRTY = (1 << 0), // updated.
        FRESH = (1 << 1), // no any update.
        TRUNC = (1 << 2), // this is invalid.
        TEMP = (1 << 3),  // this is for temporary
        NEW = (1 << 4),   // for add
    };

    CRankItem(): nValue(0), nInvitees(0), dWeight(0) {}
    virtual ~CRankItem() {};

    void SetNull()
    {
        nValue = 0;
        nInvitees = 0;
        dWeight = 0;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nValue);
        READWRITE(nInvitees);
        READWRITE(dWeight);
    }

    void operator +=(const CRankItem& item)
    {
        nValue += item.nValue;
        nInvitees += item.nInvitees;
        dWeight += item.dWeight;
    }
};

class CClueEntry
{
public:
    CClue clue;
    std::set<CTxDestination> vInvitees;
    std::set<CTxDestination> vChildren;

    unsigned char flags;
    enum {
        DIRTY = (1 << 0), // updated.
        FRESH = (1 << 1), // no any update.
        TRUNC = (1 << 2), // this is invalid.
        TEMP = (1 << 3),  // this is for temporary
        NEW = (1 << 4),   // for add
    };

    CClueEntry()
    {
        clue.SetNull();
        vInvitees.clear();
        vChildren.clear();
        flags = FRESH;
    };

    void MarkDirty()
    {
        flags |= CClueEntry::DIRTY;
    };

    CClueEntry(const CClue& clueIn): clue(clueIn), flags(CClueEntry::FRESH) {};
};



typedef std::map<CTxDestination, CClueEntry> CClueMap;

typedef std::map<CTxDestination, CRankItem> CRankItemMap;

struct CTopRank {
    CTxDestination address;
    CRankItem item;

    CTopRank()
    {
        SetNull();
    }

    void SetNull()
    {
        address = CNoDestination();
        item.SetNull();
    }

    CTopRank(const CTxDestination& addressIn, const CRankItem& itemIn):
        address(addressIn), item(itemIn) {}

    bool operator < (const CTopRank& b);

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(address);
        READWRITE(item);
    }
};

struct CSeasonStat {
public:
    std::list<CTopRank> vTopRank;
    CRankItemMap mRankItems;
    CAmount nTotalClue;

    unsigned char flags;
    enum {
        DIRTY = (1 << 0), // updated.
        FRESH = (1 << 1), // no any update.
        TRUNC = (1 << 2), // this is invalid.
        TEMP = (1 << 3),  // this is for temporary
        NEW = (1 << 4),   // for add
    };

    CSeasonStat()
    {
        vTopRank.clear();
        mRankItems.clear();
        nTotalClue = 0;
        flags = FRESH;
    };

    void MarkDirty()
    {
        flags |= CClueEntry::DIRTY;
    };
};

typedef std::map<int, CSeasonStat> SeasonRankMap;

/**
  * this file provide a cache view class for clue
  * this cache view is for clue check.
  * */

class CClueView
{
public:
    //! Retrieve the block hash whose state this CCoinsView currently represents
    virtual uint256 GetBestBlock() const;

    virtual bool HaveClue(const CTxDestination& dest) const;
    virtual bool AddClue(const CClue& clue);
    virtual bool GetClue(const CTxDestination& dest, CClue& clue);

    virtual bool IsConflict(const CTxDestination& dest, const uint256& txid) const;

    virtual bool GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite = false);
    virtual bool GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite = false);
    virtual uint32_t ChildrenSize(const CTxDestination& dest, const bool fInvite = false) const;

    virtual bool GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite = false);
    virtual bool IsChildOf(const CTxDestination& dest, const CTxDestination& parent, const bool fInvite) const;

    virtual bool DeleteClue(const CTxDestination& dest);
    virtual bool EraseClue(const CTxDestination& dest);

    virtual bool BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn);
    virtual bool Flush();

    // For statistic
    virtual bool GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item);
    virtual bool AddRankItem(const CTxDestination& dest, int nSeason, const CRankItem& item);
    virtual bool DeleteRankItem(const CTxDestination& dest, int nSeason);
    virtual CAmount GetTotalClue(int nSeason);

    virtual bool GetSeasonRank(int nSeason, std::list<CTopRank>& vRank);

    virtual ~CClueView() {};
};


class CClueFamilyTree;

class CClueViewBacked: public CClueView
{
protected:
    CClueView* base;

public:
    CClueViewBacked(CClueView* baseIn): base(baseIn) {};

    uint256 GetBestBlock() const override;

    bool HaveClue(const CTxDestination& dest) const override;
    bool AddClue(const CClue& clue) override;
    bool GetClue(const CTxDestination& dest, CClue& clue) override;

    bool IsConflict(const CTxDestination& dest, const uint256& txid) const override;

    bool GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite = false) override;
    bool GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite = false) override;

    uint32_t ChildrenSize(const CTxDestination& dest, const bool fInvite = false) const override;
    bool GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite = false)override;
    bool IsChildOf(const CTxDestination& dest, const CTxDestination& parent, const bool fInvite) const override;

    bool DeleteClue(const CTxDestination& dest) override;
    bool EraseClue(const CTxDestination& dest) override;

    bool BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn) override;
    void SetBackend(CClueView& viewIn);

    bool GetSeasonRank(int nSeason, std::list<CTopRank>& vRank) override;
    bool GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item) override;
    bool AddRankItem(const CTxDestination& dest, int nSeason, const CRankItem& item) override;
    CAmount GetTotalClue(int nSeason) override;
    bool DeleteRankItem(const CTxDestination& dest, int nSeason) override;
};

class CClueViewCache: public CClueViewBacked
{
protected:
    mutable uint256 hashBlock;
    mutable CClueMap cacheClue;
    mutable SeasonRankMap cacheRank;

private:
    CTxDestination FindClueAbleAddress(const CTxDestination& address, const uint32_t depth = FAMILY_TREE_MAX_LEVEL) const;

public:
    CClueViewCache(CClueView* baseIn): CClueViewBacked(baseIn) {};

    uint256 GetBestBlock() const override;
    void SetBestBlock(const uint256& hashBlock);

    bool HaveClue(const CTxDestination& dest) const override;
    bool AddRoot(const CClue& clue);
    bool AddClue(const CClue& clue) override;
    bool GetClue(const CTxDestination& dest, CClue& clue) override;

    bool IsConflict(const CTxDestination& dest, const uint256& txid) const;

    bool GetParent(const CTxDestination& dest, CTxDestination& parent, const bool fInvite = false) override;
    bool GetParents(const CTxDestination& dest, std::vector<CTxDestination>& vParents, const bool fInvite = false) override;

    uint32_t ChildrenSize(const CTxDestination& dest, const bool fInvite = false) const override;
    bool GetChildren(const CTxDestination& dest, std::set<CTxDestination>& children, const bool fInvite = false)override;
    bool IsChildOf(const CTxDestination& dest, const CTxDestination& parent, const bool fInvite) const override;

    bool DeleteClue(const CTxDestination& dest) override;
    bool EraseClue(const CTxDestination& dest) override;

    bool BatchWrite(CClueMap& mapClue, SeasonRankMap& mapSeason, const uint256& hashBlockIn) override;

    bool Flush() override;

    bool GetParentTree(const CTxDestination& address, CClueFamilyTree& tree, const bool fInvite = true, const uint32_t uDepth = FAMILY_TREE_MAX_LEVEL) const ;

    bool GetSeasonRank(int nSeason, std::list<CTopRank>& vRank);
    CAmount GetTotalClue(int nSeason) override;
    bool GetRankItem(const CTxDestination& dest, int nSeason, CRankItem& item) override;
    bool AddRankItem(const CTxDestination& dest, int nSeason, const CRankItem& item) override;
    bool DeleteRankItem(const CTxDestination& dest, int nSeason) override;
};

#endif // VDS_CLUE_H
