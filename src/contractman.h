// Copyright (c) 2014-2019 The vds Core developers

#ifndef CONTRACTMAN_H
#define CONTRACTMAN_H

#include <string>
#include <map>
#include <unordered_map>
#include <vector>

#include "uint256.h"
#include "contract.h"
#include "amount.h"
#include "boost/filesystem/path.hpp"
#include "cpp-ethereum/libdevcrypto/Common.h"
#include "qtum/qtumstate.h"
#include "base58.h"
#include "util.h"
#include "clientversion.h"

#include <boost/filesystem.hpp>
class CContractMan
{
private:
    std::map<uint160, CContract> mapContracts;
    boost::filesystem::path pathContract;

    bool WriteContracts();

public:
    CContractMan()
    {
        pathContract = GetDataDir() / "contract.dat";
    };
    bool InitContracts();

    bool AddContract(const std::string& name, const uint160& contractAddress,
                     const std::string& abi, const std::string& desc);

    bool RemoveContract(const uint160& contractAddress);

    std::vector<ResultExecute> CallContract(const uint160& addrContract, std::vector<unsigned char> opcode,
                                            const dev::Address& sender, uint64_t gasLimit);

    bool GetContractInfo(const uint160& addrContract, CContract& contract);
    bool HasContract(const uint160& addrContract) const;
};

extern CContractMan* pContractman;
#endif /* CONTRACTMAN_H */

