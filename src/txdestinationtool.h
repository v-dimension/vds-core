// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXDESTINATIONTOOL_H
#define TXDESTINATIONTOOL_H

#include "script/standard.h"

bool IsNullTxDestination(const CTxDestination& t);
void SetTxDestinationNull(CTxDestination& t);

template <typename Stream>
class CTxDestinationSerialVisitor : public boost::static_visitor<bool>
{
private:
    Stream* s;
public:
    CTxDestinationSerialVisitor(Stream* ss) : s(ss)
    {
    }


    bool operator()(const CNoDestination& id) const
    {
        *s << (uint8_t)2;
        return true;
    }

    bool operator()(const CKeyID& id) const
    {
        *s << (uint8_t)1;
        *s << id;
        return true;
    }

    bool operator()(const CScriptID& id) const
    {
        *s << (uint8_t)0;
        *s << id;
        return true;
    }

    bool operator()(const WitnessV0ScriptHash& id) const
    {
        *s << (uint8_t)3;
        *s << id;
        return true;
    }

    bool operator()(const WitnessV0KeyHash& id) const
    {
        *s << (uint8_t)4;
        *s << id;
        return true;
    }

    bool operator()(const WitnessUnknown& id) const
    {
        *s << (uint8_t)5;
        *s << id;
        return true;
    }
};

template <typename Stream, typename T, typename A, typename V, typename K, typename C, typename N>
void Serialize(Stream& s, const boost::variant<T, A, V, K, C, N>& v)
{
    SerialTxDestiniation(s, v);
}

template <typename Stream, typename T, typename A, typename V, typename K, typename C, typename N>
void Unserialize(Stream& s, boost::variant<T, A, V, K, C, N>& v)
{
    UnSerialTxDestiniation(s, v);
}

template <typename Stream>
void SerialTxDestiniation(Stream& s, const CTxDestination& dest)
{
    boost::apply_visitor(CTxDestinationSerialVisitor<Stream>(&s), dest);
}

template <typename Stream>
void UnSerialTxDestiniation(Stream& s, CTxDestination& dest)
{
    uint8_t type;
    s >> type;
    if (type == 0) {
        CScriptID sid;
        s >> sid;
        dest = sid;
        return;
    } else if (type == 1) {
        CKeyID kid;
        s >> kid;
        dest = kid;
        return;
    } else if (type == 3) {
        WitnessV0ScriptHash wshash;
        s >> wshash;
        dest = wshash;
        return;
    } else if (type == 4) {
        WitnessV0KeyHash wkhash;
        s >> wkhash;
        dest = wkhash;
        return;
    } else if (type == 5) {
        WitnessUnknown wukhash;
        s >> wukhash;
        dest = wukhash;
        return;
    } else {
        dest = CNoDestination();
    }
}


#endif // TXDESTINATIONTOOL_H
