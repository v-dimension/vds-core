#include "tandiadb.h"
#include "chainparams.h"
#include "assert.h"
#include "validation.h"

static const char DB_TANDIA_VOTE = 'V';
static const char DB_TANDIA_RANK = 'R';
static const char DB_TANDIA_PROPSAL = 'P';
static const char DB_TANDIA_PROPSAL_SIZE = 'S';
static const char DB_TANDIA_PROPSAL_INDEX = 'I';

CTandiaDB* pTandiaDb = NULL;
CTandia* pTandia = NULL;

bool CTandia::GetTandiaAddresses(const int nHeight, std::list<Propsal>& outRank)
{
    // if height smaller than the first tandia period, there's no any tandia address.
    int nPeriod = GetTandiaPeriod(nHeight);
    if (nPeriod < 0) {
        outRank.resize(0);
        return false;
    }

    assert(pTandiaDb != NULL);

    if (mapTandiaRank.find(nPeriod) == mapTandiaRank.end()) {
        CTandiaRank rank(nPeriod);
        if (pTandiaDb->ReadRanking(rank))
            mapTandiaRank[nPeriod] = rank;
    }
    outRank = mapTandiaRank[nPeriod].GetTandiaPropsals();

    return true;
}

bool CTandia::IsVoted(const int nHeight, const uint256& txid, const uint160& addrId) const
{
    int nPeriod = GetTandiaPeriod(nHeight);

    if (!pTandiaDb->IsVoted(nPeriod, addrId))
        return false;

    return true;
}

bool CTandia::IsConflict(const int nHeight, const uint256& txid, const uint160& addrId) const
{
    int nPeriod = GetTandiaPeriod(nHeight);

    Vote vote{addrId, uint256(), false};
    if (!pTandiaDb->ReadVote(nPeriod, vote))
        return false;

    // here should check txid
    if (txid != vote.txid) {
        return true;
    }

    return false;
}

bool CTandia::ReadPropsal(const int nPeriod, const CScript& scriptPubKey, Propsal& propsal) const
{
    int nIndex = pTandiaDb->ReadPropsalIndex(nPeriod, scriptPubKey);
    if (nIndex < 0)
        return false;

    return pTandiaDb->ReadPropsal(nPeriod, nIndex, propsal);
}

bool CTandia::WritePropsal(const int nPeriod, const Propsal& propsal)
{
    return pTandiaDb->WritePropsal(nPeriod, propsal);
}

bool CTandia::ListPropsals(const int nHeight, const size_t start, const size_t end, std::list<Propsal>& lPropsals) const
{
    int nPeriod = GetTandiaPeriod(nHeight);
    return pTandiaDb->ReadPropsals(nPeriod, start, end, lPropsals);
}

bool CTandia::GetPropsals(const int nHeight, std::list<Propsal>& lPropsals) const
{
    int nPeriod = GetTandiaPeriod(nHeight);
    return pTandiaDb->ReadPropsals(nPeriod, lPropsals);
}

bool CTandia::AddPropsal(const int nHeight, const CScript& scriptPubKey, const int64_t& nVotes)
{
    int nPeriod = GetTandiaPeriod(nHeight) ;
    if (pTandiaDb->Exists(std::make_pair(DB_TANDIA_PROPSAL, nPeriod)))
        return false;
    Propsal propsal(scriptPubKey, nVotes);
    return pTandiaDb->WritePropsal(nPeriod, propsal);
}

bool CTandia::UpdatePropsal(const int nHeight, const Propsal& propsal)
{
    int nPeriod = GetTandiaPeriod(nHeight) ;
    if (!pTandiaDb->Exists(std::make_pair(DB_TANDIA_PROPSAL, nPeriod)))
        return false;
    int nIndex = pTandiaDb->ReadPropsalIndex(nPeriod, propsal.addrScript);
    if (nIndex < 0)
        return false;
    return pTandiaDb->UpdatePropsal(nPeriod, nIndex, propsal);
}


bool CTandia::AcceptVote(const int nHeight, const CScript& scriptPubKey, const CScript& scriptPropsal, const uint256& txid)
{
    int nPeriod = GetTandiaPeriod(nHeight);

    uint160 id = ScriptPubKeyToUint160(scriptPubKey);
    if (id.IsNull())
        return false;

    if (IsVoted(nHeight, txid, id )) {
        if (IsConflict(nHeight, txid, id))
            return false;
    }

    Vote vote(id, txid, true);
    pTandiaDb->WriteVote(nPeriod, vote);

    Propsal propsal(scriptPropsal, 0);
    ReadPropsal(nPeriod, scriptPropsal, propsal);

    if (!IsVoted(nHeight, txid, id))
        propsal.nVotes += 1;

    WritePropsal(nPeriod, propsal);

    if (mapTandiaRank[nPeriod].GetRankOrder(scriptPropsal) >= 0)
        mapTandiaRank[nPeriod].UpdatePropsal(scriptPropsal, propsal.nVotes);
    else
        mapTandiaRank[nPeriod].addNewPropsal(propsal);

    pTandiaDb->WriteRanking(mapTandiaRank[nPeriod]);

    return true;
}

bool CTandia::UndoVote(const int nHeight, const CScript& scriptPubKey, const CScript& scriptPropsal, const uint256& txid)
{
    int nPeriod = GetTandiaPeriod(nHeight);
    uint160 id = ScriptPubKeyToUint160(scriptPubKey);
    if (id.IsNull()) return false;

    if (!IsVoted(nHeight, txid, id ))
        return false;

    if (!pTandiaDb->EraseVote(nPeriod, id))
        return false;

    Propsal propsal(scriptPropsal, 0);
    ReadPropsal(nPeriod, scriptPropsal, propsal);
    propsal.nVotes -= 1;
    if (!UpdatePropsal(nPeriod, propsal))
        return false;

    if (mapTandiaRank[nPeriod].GetRankOrder(scriptPropsal) >= 0)
        mapTandiaRank[nPeriod].UpdatePropsal(scriptPropsal, propsal.nVotes);
    else
        mapTandiaRank[nPeriod].addNewPropsal(propsal);

    pTandiaDb->WriteRanking(mapTandiaRank[nPeriod]);
    return true;
}

int CTandiaRank::GetRankOrder(const CScript& script) const
{
    int i = 0;
    for (std::list<Propsal>::const_iterator it = lTandiaRank.begin(); it != lTandiaRank.end(); it++, i++) {
        if (it->addrScript == script)
            return i;
    }
    return -1;
}

bool CTandiaRank::UpdatePropsal(const CScript& script, const int votes)
{
    if (GetRankOrder(script) < 0)
        return false;
    for (std::list<Propsal>::iterator it = lTandiaRank.begin(); it != lTandiaRank.end(); it++) {
        if (it->addrScript == script) {
            it->nVotes = votes;
            break;
        }
    }
    lTandiaRank.sort();
    return true;
}

int CTandiaRank::addNewPropsal(const Propsal& propsal)
{
    if (lTandiaRank.size() == 0) {
        lTandiaRank.push_front(propsal);
        return 0;
    }
    int i = 0;
    for (std::list<Propsal>::const_iterator it = lTandiaRank.begin(); it != lTandiaRank.end(); it++, i++) {
        if (it->nVotes < propsal.nVotes) {
            lTandiaRank.insert(it, propsal);
            break;
        }
    }

    if (lTandiaRank.size() > MAX_TANDIA_LIMIT) {
        lTandiaRank.resize(MAX_TANDIA_LIMIT);
    }
    return (i < MAX_TANDIA_LIMIT) ? i : -1;
}

uint160 CTandia::ScriptPubKeyToUint160(const CScript& script)
{
    CTxDestination dest;
    txnouttype type;
    ExtractDestination(script, dest, &type);
    if (type != TX_SCRIPTHASH && type != TX_PUBKEYHASH && type != TX_PUBKEY)
        return uint160();

    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (keyID) {
        return *(uint160*)keyID;
    }

    const CScriptID* scriptID = boost::get<CScriptID>(&dest);
    if (scriptID) {
        return *(uint160*)scriptID;
    }

    return uint160();
}

CTandiaDB::CTandiaDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "tandia", nCacheSize, fMemory, fWipe)
{

}

size_t CTandiaDB::GetPropsalSize(const int nPeriod)
{
    if (mPropsalSize.find(nPeriod) != mPropsalSize.end())
        return mPropsalSize[nPeriod];
    size_t size;
    if (!Read(std::make_pair(DB_TANDIA_PROPSAL_SIZE, nPeriod), size))
        return 0;
    mPropsalSize[nPeriod] = size;
    return size;
}

bool CTandiaDB::WritePropsalIndex(const int nPeriod, const size_t nIndex, const Propsal& propsal)
{
    return Write(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL_INDEX, nPeriod), propsal.addrScript), nIndex);
}

int CTandiaDB::ReadPropsalIndex(const int nPeriod, const CScript& scriptPubkey) const
{
    int nIndex;
    if (Read(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL_INDEX, nPeriod), scriptPubkey), nIndex))
        return nIndex;
    return -1;
}

bool CTandiaDB::WritePropsal(const int nPeriod, const Propsal& propsal)
{
    if (Write(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL, nPeriod), GetPropsalSize(nPeriod)), propsal)) {
        if (WritePropsalIndex(nPeriod, GetPropsalSize(nPeriod), propsal))
            return IncreasePropsalSize(nPeriod);
        else
            Erase(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL, nPeriod), GetPropsalSize(nPeriod)));
    }
    return false;
}


bool CTandiaDB::ReadPropsal(const int nPeriod, const size_t nIndex, Propsal& propsal)
{
    if (Exists(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL, nPeriod), nIndex))) {
        if (Read(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL, nPeriod), nIndex), propsal)) {
            return true;
        }
    }
    return false;
}

bool CTandiaDB::UpdatePropsal(const int nPeriod, const size_t nIndex, const Propsal& propsal)
{
    if (Exists(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL, nPeriod), nIndex))) {
        if (propsal.nVotes > 0) {
            if (Write(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL, nPeriod), nIndex), propsal)) {
                return true;
            }
        } else {
            Erase(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL, nPeriod), nIndex));
            Erase(std::make_pair(std::make_pair(DB_TANDIA_PROPSAL_INDEX, nPeriod), propsal.addrScript));
            return DecreasePropsalSize(nPeriod);
        }
    }
    return false;
}

bool CTandiaDB::ReadPropsals(const int nPeriod, std::list<Propsal>& vPropsals)
{
    for (size_t i = 0; i < GetPropsalSize(nPeriod); i++) {
        Propsal propsal;
        if (ReadPropsal(nPeriod, i, propsal))
            vPropsals.push_back(propsal);
    }
    return true;
}


bool CTandiaDB::ReadPropsals(const int nPeriod, const size_t start, const size_t end, std::list<Propsal>& vPropsals)
{
    size_t nEnd = std::min(end, GetPropsalSize(nPeriod));
    for (size_t i = start; i < nEnd; i++) {
        Propsal propsal;
        if (ReadPropsal(nPeriod, i, propsal))
            vPropsals.push_back(propsal);
    }
    return true;
}


bool CTandiaDB::IncreasePropsalSize(const int nPeriod)
{
    mPropsalSize[nPeriod] += 1;
    return Write(std::make_pair(DB_TANDIA_PROPSAL_SIZE, nPeriod), mPropsalSize[nPeriod]);
}

bool CTandiaDB::DecreasePropsalSize(const int nPeriod)
{
    mPropsalSize[nPeriod] -= 1;
    assert(mPropsalSize[nPeriod] >= 0);
    return Write(std::make_pair(DB_TANDIA_PROPSAL_SIZE, nPeriod), mPropsalSize[nPeriod]);
}

bool CTandiaDB::ReadRanking(CTandiaRank& rank)
{
    return Read(std::make_pair(DB_TANDIA_RANK, rank.GetPeriod()), rank);
}

bool CTandiaDB::WriteRanking(const CTandiaRank& rank)
{
    return Write(std::make_pair(DB_TANDIA_RANK, rank.GetPeriod()), rank);
}

bool CTandiaDB::IsVoted(const int nPeriod, const uint160& addrId) const
{
    return Exists(std::make_pair(std::make_pair(DB_TANDIA_VOTE, nPeriod), addrId));
}

bool CTandiaDB::ReadVote(const int nPeriod, Vote& vote)
{
    return Read(std::make_pair(std::make_pair(DB_TANDIA_VOTE, nPeriod), vote.keyid), vote);
}


bool CTandiaDB::WriteVote(const int nPeriod, const Vote& vote)
{
    return Write(std::make_pair(std::make_pair(DB_TANDIA_VOTE, nPeriod), vote.keyid), vote);
}

bool CTandiaDB::EraseVote(const int nPeriod, const uint160& addrId)
{
    return Erase(std::make_pair(std::make_pair(DB_TANDIA_VOTE, nPeriod), addrId));
}


