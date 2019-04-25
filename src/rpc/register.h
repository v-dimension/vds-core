// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_RPCREGISTER_H
#define VDS_RPCREGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void RegisterBlockchainRPCCommands(CRPCTable& tableRPC);
/** Register P2P networking RPC commands */
void RegisterNetRPCCommands(CRPCTable& tableRPC);
/** Register miscellaneous RPC commands */
void RegisterMiscRPCCommands(CRPCTable& tableRPC);
/** Register raw transaction RPC commands */
void RegisterRawTransactionRPCCommands(CRPCTable& tableRPC);
/** Register MasterNode RPC commands */
void RegisterMasterNodeRPCCommands(CRPCTable& t);
/** Register Advertisement RPC commands */
void RegisterAdRPCCommands(CRPCTable& t);

static inline void RegisterAllCoreRPCCommands(CRPCTable& t)
{
    RegisterBlockchainRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterMiscRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);
    RegisterMasterNodeRPCCommands(t);
    RegisterAdRPCCommands(t);
}

#endif
