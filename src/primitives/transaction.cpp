// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include "librustzcash.h"

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0, 10), n);
}

std::string SaplingOutPoint::ToString() const
{
    return strprintf("SaplingOutPoint(%s, %u)", hash.ToString().substr(0, 10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0, 24));
    if (nSequence != std::numeric_limits<unsigned int>::max())
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

std::string COutPoint::ToStringShort() const
{
    return strprintf("%s-%u", hash.ToString().substr(0, 64), n);
}

CTxOut::CTxOut(const CAmount& nValueIn, uint8_t nFlagIn, CScript scriptPubKeyIn, uint256 dataHashIn)
{
    nValue = nValueIn;
    nFlag = nFlagIn;
    scriptPubKey = scriptPubKeyIn;
    dataHash = dataHashIn;
}

uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, nFlag=%u, scriptPubKey=%s)", nValue / COIN, nValue % COIN, nFlag, scriptPubKey.ToString().substr(0, 30));
}

CMutableTransaction::CMutableTransaction() :
    nVersion(CTransaction::MIN_CURRENT_VERSION),
    nFlag(CTransaction::NORMAL_TX),
    nExpiryHeight(0),
    nLockTime(0),
    valueBalance(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) :
    nVersion(tx.nVersion),
    nFlag(tx.nFlag),
    nExpiryHeight(tx.nExpiryHeight),
    vin(tx.vin),
    vout(tx.vout),
    nLockTime(tx.nLockTime),
    valueBalance(tx.valueBalance),
    vShieldedSpend(tx.vShieldedSpend),
    vShieldedOutput(tx.vShieldedOutput),
    bindingSig(tx.bindingSig)
{

}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

CTransaction::CTransaction() :
    nVersion(CTransaction::MIN_CURRENT_VERSION),
    nFlag(CTransaction::NORMAL_TX),
    nExpiryHeight(0),
    vin(),
    vout(),
    nLockTime(0),
    valueBalance(0),
    vShieldedSpend(),
    vShieldedOutput(),
    bindingSig(),
    hash(),
    m_witness_hash() { }

CTransaction::CTransaction(const CMutableTransaction& tx) :
    nVersion(tx.nVersion),
    nFlag(tx.nFlag),
    nExpiryHeight(tx.nExpiryHeight),
    vin(tx.vin),
    vout(tx.vout),
    nLockTime(tx.nLockTime),
    valueBalance(tx.valueBalance),
    vShieldedSpend(tx.vShieldedSpend),
    vShieldedOutput(tx.vShieldedOutput),
    bindingSig(tx.bindingSig)
{
    *const_cast<uint256*>(&hash) = ComputeHash();
    *const_cast<uint256*>(&m_witness_hash) = ComputeWitnessHash();
}

CTransaction::CTransaction(CMutableTransaction&& tx) :
    nVersion(tx.nVersion),
    nFlag(tx.nFlag),
    vin(std::move(tx.vin)),
    vout(std::move(tx.vout)),
    nLockTime(tx.nLockTime),
    nExpiryHeight(tx.nExpiryHeight),
    valueBalance(tx.valueBalance),
    vShieldedSpend(std::move(tx.vShieldedSpend)),
    vShieldedOutput(std::move(tx.vShieldedOutput)),
    bindingSig(std::move(tx.bindingSig))
{
    *const_cast<uint256*>(&hash) = ComputeHash();
    *const_cast<uint256*>(&m_witness_hash) = ComputeWitnessHash();
}

CTransaction& CTransaction::operator=(const CTransaction& tx)
{
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<uint8_t*>(&nFlag) = tx.nFlag;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint32_t*>(&nExpiryHeight) = tx.nExpiryHeight;
    *const_cast<CAmount*>(&valueBalance) = tx.valueBalance;
    *const_cast<std::vector<SpendDescription>*>(&vShieldedSpend) = tx.vShieldedSpend;
    *const_cast<std::vector<OutputDescription>*>(&vShieldedOutput) = tx.vShieldedOutput;
    *const_cast<binding_sig_t*>(&bindingSig) = tx.bindingSig;
    *const_cast<uint256*>(&hash) = tx.GetHash();
    *const_cast<uint256*>(&m_witness_hash) = tx.GetWitnessHash();
    return *this;
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it) {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }

    if (valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -valueBalance;

        if (!MoneyRange(-valueBalance) || !MoneyRange(nValueOut)) {
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
        }
    }

    return nValueOut;
}

CAmount CTransaction::GetValueOutWithExclude(const std::vector<uint8_t> vTypeExclude) const
{
    for (std::vector<uint8_t>::const_iterator itType(vTypeExclude.begin()); itType != vTypeExclude.end(); ++itType) {
        if (((*itType) < CTxOut::NORMAL) || ((*itType) > CTxOut::BID))
            throw std::runtime_error("CTransaction::GetValueOut(): type exclude range error");
    }

    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it) {
        if (find(vTypeExclude.begin(), vTypeExclude.end(), it->nFlag) != vTypeExclude.end()) {
            continue;
        }
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }

    if (valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -valueBalance;

        if (!MoneyRange(-valueBalance) || !MoneyRange(nValueOut)) {
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
        }
    }

    return nValueOut;
}

CAmount CTransaction::GetShieldedValueIn() const
{
    CAmount nValue = 0;

    if (valueBalance >= 0) {
        // NB: positive valueBalance "gives" money to the transparent value pool just as inputs do
        nValue += valueBalance;

        if (!MoneyRange(valueBalance) || !MoneyRange(nValue)) {
            throw std::runtime_error("CTransaction::GetShieldedValueIn(): value out of range");
        }
    }

    return nValue;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it) {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, flag=%u, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u, valueBalance=%u, vShieldedSpend.size=%u, vShieldedOutput.size=%u)\n",
                     GetHash().ToString().substr(0, 10),
                     nVersion,
                     nFlag,
                     vin.size(),
                     vout.size(),
                     nLockTime,
                     nExpiryHeight,
                     valueBalance,
                     vShieldedSpend.size(),
                     vShieldedOutput.size());
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, flag=%u, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u, valueBalance=%u, vShieldedSpend.size=%u, vShieldedOutput.size=%u)\n",
                     GetHash().ToString().substr(0, 10),
                     nVersion,
                     nFlag,
                     vin.size(),
                     vout.size(),
                     nLockTime,
                     nExpiryHeight,
                     valueBalance,
                     vShieldedSpend.size(),
                     vShieldedOutput.size());
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}

///////////////////////////////////////////////////////////// qtum
bool CTransaction::HasCreateOrCall() const
{
    for (const CTxOut& v : vout) {
        if (v.scriptPubKey.HasOpCreate() || v.scriptPubKey.HasOpCall()) {
            return true;
        }
    }
    return false;
}

bool CTransaction::HasOpSpend() const
{
    for (const CTxIn& i : vin) {
        if (i.scriptSig.HasOpSpend()) {
            return true;
        }
    }
    return false;
}
/////////////////////////////////////////////////////////////
