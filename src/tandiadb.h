#ifndef TANDIADB_H
#define TANDIADB_H

#include "dbwrapper.h"
#include "base58.h"
#include "amount.h"
#include "serialize.h"

class uint160;


struct Propsal {
    CScript addrScript;
    int64_t nVotes;

    Propsal()
    {
        addrScript = CScript();
        nVotes = 0;
    };
    Propsal(const CScript _scriptIn, const int64_t _nVotesIn): addrScript(_scriptIn), nVotes(_nVotesIn) {};
    bool operator < (Propsal& p)
    {
        return nVotes < p.nVotes;
    };

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(addrScript);
        READWRITE(nVotes);
    };
};

struct Vote {
    uint160 keyid;
    uint256 txid;
    bool fVoted;

    Vote(): keyid(uint160()), txid(uint256()), fVoted(false) {};
    Vote(const uint160& _keyidIn, const uint256& _txidIn, const bool& _fVotedIn): keyid(uint160(_keyidIn)), txid(uint256(_txidIn)), fVoted(_fVotedIn) {};
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(keyid);
        READWRITE(txid);
        READWRITE(fVoted);
    };
};

class CTandiaRank
{
public:
    int nPeriod;

    std::list<Propsal> lTandiaRank;

public:
    CTandiaRank() {};
    CTandiaRank(int _nPeriod): nPeriod(_nPeriod) {};

    CTandiaRank(const CTandiaRank& rank)
    {
        *(this) = rank;
    };

    int GetPeriod() const
    {
        return nPeriod;
    };

    int GetRankOrder(const CScript& script) const;

    bool UpdatePropsal(const CScript& script, const int votes);

    std::list<Propsal> GetTandiaPropsals()
    {
        return lTandiaRank;
    };

    int addNewPropsal(const Propsal& propsal);

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(lTandiaRank);
    }

};

class CTandia
{
private:
    std::map<int, CTandiaRank> mapTandiaRank;

public:
    CTandia() {};

    bool GetTandiaAddresses(const int nHeight, std::list<Propsal>& outRank);

    bool IsVoted(const int nHeight, const uint256& txid, const uint160& addrId) const;
    bool IsConflict(const int nHeight, const uint256& txid, const uint160& addrId) const;

    bool IsTandia(const int nHeight, const CTxDestination& dest) const;

    bool ReadPropsal(const int nPeriod, const CScript& scriptPubKey, Propsal& propsal) const;

    bool WritePropsal(const int nPeriod, const Propsal& propsal);

    bool UpdatePropsal(const int nHeight, const Propsal& propsal);

    bool ListPropsals(const int nHeight, const size_t start, const size_t end, std::list<Propsal>& lPropsals) const;

    bool GetPropsals(const int nHeight, std::list<Propsal>& lPropsals) const;

    bool AddPropsal(const int nHeight, const CScript& scriptPubKey, const int64_t& nVotes);

    bool AcceptVote(const int nHeight, const CScript& scriptPubKey, const CScript& scriptPropsal, const uint256& txid);

    bool UndoVote(const int nHeight, const CScript& scriptPubKey, const CScript& scriptPropsal, const uint256& txid);

private:
    uint160 ScriptPubKeyToUint160(const CScript& script);
};

class CTandiaDB : public CDBWrapper
{
private:
    std::map<int, size_t> mPropsalSize;


public:
    CTandiaDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    size_t GetPropsalSize(const int nPeriod);

    bool WritePropsalIndex(const int nPeriod, const size_t nIndex, const Propsal& propsal);

    int ReadPropsalIndex(const int nPeriod, const CScript& scriptPubkey) const;

    bool WritePropsal(const int nPeriod, const Propsal& propsal);

    bool ReadPropsal(const int nPeriod, const size_t nIndex, Propsal& propsal);

    bool UpdatePropsal(const int nPeriod, const size_t nIndex, const Propsal& propsal);

    bool ReadPropsals(const int nPeriod, std::list<Propsal>& vPropsals);

    bool ReadPropsals(const int nPeriod, const size_t start, const size_t end, std::list<Propsal>& vPropsals);

    bool IncreasePropsalSize(const int nPeriod);

    bool DecreasePropsalSize(const int nPeriod);

    size_t GetPropsalSize(const int nPeriod) const;

    bool ReadRanking(CTandiaRank& rank);

    bool WriteRanking(const CTandiaRank& rank);

    bool IsVoted(const int nPeriod, const uint160& dest) const;

    bool ReadVote(const int nPeriod, Vote& vote);

    bool WriteVote(const int nPeriod, const Vote& vote);

    bool EraseVote(const int nPeriod, const uint160& dest);

};

extern CTandiaDB* pTandiaDb;

extern CTandia* pTandia;

#endif // TANDIADB_H
