// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdestinationtool.h"
#include <base58.h>

class TxDestinationNullVisitor : public boost::static_visitor<bool>
{
public:
    TxDestinationNullVisitor() {}

    bool operator()(const CNoDestination& dest) const
    {
        return true;
    }
    bool operator()(const CScriptID& dest) const
    {
        return dest.IsNull();
    }

    bool operator()(const CKeyID& dest) const
    {
        return dest.IsNull();
    }

    bool operator()(const WitnessV0ScriptHash& dest) const
    {
        return dest.IsNull();
    }

    bool operator()(const WitnessV0KeyHash& dest) const
    {
        return dest.IsNull();
    }

    bool operator()(const WitnessUnknown& dest) const
    {
        return true;
    }
};

class TxDestinationSetNullVisitor : public boost::static_visitor<void>
{
public:
    TxDestinationSetNullVisitor() {}
    void operator()(CNoDestination& dest) const
    {
    }
    void operator()(CScriptID& dest) const
    {
        dest.SetNull();
    }

    void operator()(CKeyID& dest) const
    {
        dest.SetNull();
    }

    void operator()(WitnessV0ScriptHash& dest) const
    {
        dest.SetNull();
    }

    void operator()(WitnessV0KeyHash& dest) const
    {
        dest.SetNull();
    }

    void operator()(WitnessUnknown& dest) const
    {
    }
};


bool IsNullTxDestination(const CTxDestination& t)
{
    return boost::apply_visitor(TxDestinationNullVisitor(), t);
}

void SetTxDestinationNull(CTxDestination& t)
{
    boost::apply_visitor(TxDestinationSetNullVisitor(), t);
}
