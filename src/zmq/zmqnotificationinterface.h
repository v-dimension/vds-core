// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_ZMQ_ZMQNOTIFICATIONINTERFACE_H
#define VDS_ZMQ_ZMQNOTIFICATIONINTERFACE_H

#include "validationinterface.h"
#include <primitives/transaction.h>
#include <string>
#include <map>

class CBlockIndex;
class CZMQAbstractNotifier;

class CZMQNotificationInterface : public CValidationInterface
{
public:
    virtual ~CZMQNotificationInterface();

    static CZMQNotificationInterface* CreateWithArguments(const std::map<std::string, std::string>& args);

protected:
    bool Initialize();
    void Shutdown();

    // CValidationInterface
    void SyncTransaction(const CTransactionRef& tx, const CBlockIndex* pblock, int posInBlock);
    void UpdatedBlockTip(const CBlockIndex* pindex);

private:
    CZMQNotificationInterface();

    void* pcontext;
    std::list<CZMQAbstractNotifier*> notifiers;
};

#endif // VDS_ZMQ_ZMQNOTIFICATIONINTERFACE_H
