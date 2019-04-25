// Copyright (c) 2014-2019 The vds Core developers

#ifndef CONTRACT_H
#define CONTRACT_H

#include "tinyformat.h"
#include "contractabi.h"
#include "cpp-ethereum/libdevcrypto/Common.h"
#include "serialize.h"
#include "uint256.h"

class CContract
{
private:
    ContractABI mabi;
public:
    std::string name;
    std::string abi;
    uint160 contractAddress;
    std::string desc;

public:
    CContract() {};
    CContract(const std::string& _name, const std::string& _abi,
              const uint160& _contractAddress, const std::string _desc = "")
    {
        name = _name;
        abi = _abi;
        contractAddress = _contractAddress;
        desc = _desc;
        mabi.loads(abi);
    };

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(abi);
        READWRITE(contractAddress);
        READWRITE(desc);
        if (ser_action.ForRead())
            mabi.loads(abi);
    }

    ContractABI GetABI()  const
    {
        ContractABI mabi;
        mabi.loads(abi);
        return mabi;
    };

    std::string ToString() const
    {
        return strprintf("name: %s\nABI: %s\n ContractAddress: %s\n,Desc: %s\n",
                         name, abi, contractAddress.GetHex(), desc);
    };
};

#endif /* CONTRACT_H */

