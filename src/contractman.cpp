// Copyright (c) 2014-2019 The vds Core developers

#include "contractman.h"
#include "contractabi.h"
#include "contract.h"
#include "streams.h"
#include "validation.h"
#include "boost/foreach.hpp"
#include "cpp-ethereum/libdevcrypto/Common.h"

CContractMan* pContractman = nullptr;
/**
 * write contracts to flat database
 * @return
 */
bool CContractMan::WriteContracts()
{
    // Generate random temporary filename
    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string tmpfn = strprintf("contracts.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssContracts(SER_DISK, CLIENT_VERSION);
    ssContracts << mapContracts;
    uint256 hash = Hash(ssContracts.begin(), ssContracts.end());
    ssContracts << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = GetDataDir() / tmpfn;
    FILE* file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: Failed to open file %s", __func__, pathTmp.string());

    // Write and commit header, data
    try {
        fileout << ssContracts;
    } catch (const std::exception& e) {
        return error("%s: Serialize or I/O error - %s", __func__, e.what());
    }
    FileCommit(fileout.Get());
    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if (!RenameOver(pathTmp, pathContract))
        return error("%s: Rename-into-place failed", __func__);

    return true;
}
/**
 * load Contracts from flat database to mapContracts
 * @return
 */
bool CContractMan::InitContracts()
{
    // open input file, and associate with CAutoFile
    FILE* file = fopen(pathContract.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: Failed to open file %s", __func__, pathContract.string());

    // use file size to size memory buffer
    uint64_t fileSize = boost::filesystem::file_size(pathContract);
    uint64_t dataSize = 0;
    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
        dataSize = fileSize - sizeof(uint256);
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char*)&vchData[0], dataSize);
        filein >> hashIn;
    } catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();

    CDataStream ssContracts(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssContracts.begin(), ssContracts.end());
    if (hashIn != hashTmp)
        return error("%s: Checksum mismatch, data corrupted", __func__);

    ssContracts >> mapContracts;
    return true;
}

/**
 * Process Contract call
 * @param addrContract
 * @param opcode
 * @param sender
 * @param gasLimit
 * @return
 */
std::vector<ResultExecute> CContractMan::CallContract(const uint160& addrContract, std::vector<unsigned char> opcode,
        const dev::Address& sender, uint64_t gasLimit)
{
    return ::CallContract(dev::Address(addrContract.GetHex()), opcode, sender, gasLimit);
}

bool CContractMan::AddContract(const std::string& name, const uint160& contractAddress,
                               const std::string& abi, const std::string& desc)
{
    if (mapContracts.find(contractAddress) != mapContracts.end())
        return false;

    CContract contract(name, abi, contractAddress, desc);
    mapContracts[contractAddress] = contract;
    return WriteContracts();
}

bool CContractMan::RemoveContract(const uint160& contractAddress)
{
    if (mapContracts.find(contractAddress) == mapContracts.end())
        return false;
    mapContracts.erase(contractAddress);
    return WriteContracts();
}

bool CContractMan::GetContractInfo(const uint160& addrContract, CContract& contract)
{
    if (mapContracts.find(addrContract) != mapContracts.end()) {
        contract = mapContracts[addrContract];
        return true;
    }
    return false;
}

bool CContractMan::HasContract(const uint160& addrContract) const
{
    if (mapContracts.find(addrContract) != mapContracts.end())
        return true;
    return false;
}
