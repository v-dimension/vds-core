// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"

#include "util.h"
#include "utilstrencodings.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif


namespace NetMsgType
{
const char* VERSION = "version";
const char* VERACK = "verack";
const char* ADDR = "addr";
const char* INV = "inv";
const char* GETDATA = "getdata";
const char* MERKLEBLOCK = "merkleblock";
const char* GETBLOCKS = "getblocks";
const char* GETHEADERS = "getheaders";
const char* TX = "tx";
const char* HEADERS = "headers";
const char* BLOCK = "block";
const char* GETADDR = "getaddr";
const char* MEMPOOL = "mempool";
const char* PING = "ping";
const char* PONG = "pong";
const char* ALERT = "alert";
const char* NOTFOUND = "notfound";
const char* FILTERLOAD = "filterload";
const char* FILTERADD = "filteradd";
const char* FILTERCLEAR = "filterclear";
const char* REJECT = "reject";
const char* SENDHEADERS = "sendheaders";
// vds message types
//const char *TXLOCKREQUEST="ix";
const char* TXLOCKVOTE = "txlvote";
const char* MASTERNODEPAYMENTVOTE = "mnw";
const char* MASTERNODEPAYMENTSYNC = "mnget";
const char* MASTERNODE_PAYMENT_BLOCK = "mnb";
const char* MNANNOUNCE = "mnb";
const char* MNPING = "mnp";
const char* DSACCEPT = "dsa";
const char* DSVIN = "dsi";
const char* DSFINALTX = "dsf";
const char* DSSIGNFINALTX = "dss";
const char* DSCOMPLETE = "dsc";
const char* DSSTATUSUPDATE = "dssu";
const char* DSTX = "dstx";
const char* DSQUEUE = "dsq";
const char* DSEG = "dseg";
const char* SYNCSTATUSCOUNT = "ssc";
const char* MNGOVERNANCESYNC = "govsync";
const char* MNGOVERNANCEOBJECT = "govobj";
const char* MNGOVERNANCEOBJECTVOTE = "govobjvote";
const char* MNVERIFY = "mnv";

// Message for SPV
const char* GETTX = "getx";
const char* STX = "stx";
const char* GETTX2 = "getx2";
const char* STX2 = "stx2";
const char* GETADMSG = "getadsg";
const char* AD_MSG = "admsg";
const char* GETAD = "getad";
const char* GETADLIST = "getadls";
const char* GETBIDLIST = "getbidls";
const char* BIDLIST = "bidls";
const char* AD = "ad";
const char* GETCLUE = "getcl";
const char* CLUE = "cl";
const char* CALLCONTRACT = "cctr";
const char* CONTRACTRESULT = "ctrslt";
const char* GETVIB = "getvib";
const char* VIBINFO = "vibinfo";
const char* GETVIBQUEUE = "getvibqueue";
const char* VIBQUEUE = "vibqueue";

const char* IM = "im";
const char* GETTXS = "gettxs";
const char* CLUE_PRE_CREATE_TREE = "clprecreate";
const char* PRE_CREATE_CLUE = "precreatecl";
const char* GETTOPCLUELIST = "gettopcllist";
const char* TOPCLUELIST  = "topclist";
const char* GETLUCKYNODES = "getluckynode";
const char* LUCKYNODES = "luckynodes";
const char* GETVCOUNT = "gvcount";
const char* VCOUNT = "vcount";
const char* GETCLUETOPRECORD = "gcluetoprec";
const char* CLUETOPRECORD = "clurtoprec";

//group
const char* CREATEGROUP = "creategroup";
const char* CREATEGROUPACK = "crtgroupack";
const char* SETBASEINFO = "setbaseinfo";
const char* SETBASEINFOACK = "stbinfoack";
const char* ADDMEMBER = "addmember";
const char* ADDMEMBERACK = "addmemberack";
const char* REFUSEMEMBER = "refmember";
const char* REFUSEMEMBERACK = "refmemberack";
const char* REMOVEMEMBER = "rmvmember";
const char* REMOVEMEMBERACK = "rmvmemberack";
const char* INCREASEMAX = "incmax";
const char* INCREASEMAXACK = "incmaxack";
const char* PERSONADDGROUP = "psnaddgroup";
const char* PERSONADDGROUPACK = "psnaddgrack";
const char* PERSONCANCELGROUP = "psncancel";
const char* PERSONCANCELGROUPACK = "psncancelack";
const char* PERSONEXITGROUP = "psnexitg";
const char* PERSONEXITGROUPACK = "psnexitgack";
const char* SETGROUPNAME = "setgname";
const char* SETGROUPNAMEACK = "setgnameack";
const char* SETGROUPANNOUN = "setgann";
const char* SETGORUPANNOUNACK = "setgannack";
const char* SETGROUPRULE = "setgrule";
const char* SETGROUPRULEACK = "setgruleack";
const char* SETOTCPERCENT = "setotcp";
const char* SETOTCPERCENTACK = "setotcpack";
const char* SETGROUPFEE = "setgfee";
const char* SETGROUPFEEACK = "setgfeeack";
const char* SETGFEEOTCPERCENT = "setgfotcp";
const char* SETGFEEOTCPERCENTACK = "setgfotcpack";
const char* SETOTCPERCENTCURRENCY = "setotcc";
const char* SETOTCPERCENTCURRENCYACK = "setotccack";
const char* SETCURRENCY = "setcurrency";
const char* SETCURRENCYACK = "setcack";
const char* SETSTARTOTC = "setsotc";
const char* SETSTARTOTCACK = "setotcack";
const char* ISGROUPADDR = "isgpaddr";
const char* ISGROUPADDRACK = "isgpaddrack";
//otc
const char* CREATEOTC = "createotc";
const char* CREATEOTCACK = "createotcack";
const char* PAYVOLUMANDFEE = "pandf";
const char* PAYVOLUMANDFEEACK = "pandfack";
const char* PAYFEE = "payfee";
const char* PAYFEEACK = "payfeeack";
const char* APPROVE = "approve";
const char* APPROVEACK = "approveack";
const char* JUDGE = "judge";
const char* JUDGEACK = "judgeack";
const char* CANCEL = "cancel";
const char* CANCELACK = "cancelack";
const char* GETOTCTRANSSTATUS = "gotcstatus";
const char* GETOTCTRANSSTATUSACK = "gotcstatack";
const char* ADDR_ADD         = "addra";
const char* ADDR_UPDATE      = "addru";
const char* ADDR_DELETE      = "addrd";

const char* GETSERVICEPORT = "getservport";
const char* SERVICEPORT = "serviceport";

const char* INQUIRYCONTRACT = "inqcontact";
const char* INQUIRYCONTRACTACK = "iqconactack";

// lightnode
const char* LNODE = "ln";
const char* LNBLOCK = "lnblock";
const char* GETLNBLOCKS = "getlnblocks";
const char* SENDLNHEADERS = "sendlnhdrs";
const char* GETLNHEADERS = "getlnhdrs";
const char* LNHEADERS = "lnheaders";
};

static const char* ppszTypeName[] = {
    "ERROR", // Should never occur
    NetMsgType::TX,
    NetMsgType::BLOCK,
    "filtered block", // Should never occur
    // vds message types
    // NOTE: include non-implmented here, we must keep this list in sync with enum in protocol.h
    //NetMsgType::TXLOCKREQUEST,
    NetMsgType::TXLOCKVOTE,
    NetMsgType::MASTERNODEPAYMENTVOTE,
    NetMsgType::MASTERNODE_PAYMENT_BLOCK,
    NetMsgType::MNANNOUNCE,
    NetMsgType::MNPING,
    NetMsgType::DSTX,
    NetMsgType::MNGOVERNANCEOBJECT,
    NetMsgType::MNGOVERNANCEOBJECTVOTE,
    NetMsgType::MNVERIFY,

    // Message for SPV
    NetMsgType::GETTX,
    NetMsgType::STX,
    NetMsgType::GETTX2,
    NetMsgType::STX2,
    NetMsgType::GETTXS,

    // ad
    NetMsgType::GETADMSG,
    NetMsgType::AD_MSG,
    NetMsgType::GETAD,
    NetMsgType::GETADLIST,
    NetMsgType::GETBIDLIST,
    NetMsgType::BIDLIST,
    NetMsgType::AD,

    // clue
    NetMsgType::GETCLUE,
    NetMsgType::CLUE,
    NetMsgType::CLUE_PRE_CREATE_TREE,
    NetMsgType::PRE_CREATE_CLUE,
    NetMsgType::GETTOPCLUELIST,
    NetMsgType::TOPCLUELIST,
    NetMsgType::GETLUCKYNODES,
    NetMsgType::LUCKYNODES,
    NetMsgType::GETVCOUNT,
    NetMsgType::VCOUNT,
    NetMsgType::GETCLUETOPRECORD,
    NetMsgType::CLUETOPRECORD,
    NetMsgType::GETOTCTRANSSTATUS,
    NetMsgType::GETOTCTRANSSTATUSACK,

    // contract
    NetMsgType::CALLCONTRACT,
    NetMsgType::CONTRACTRESULT,
    NetMsgType::INQUIRYCONTRACT,
    NetMsgType::INQUIRYCONTRACTACK,

    // vib
    NetMsgType::GETVIB,
    NetMsgType::VIBINFO,
    NetMsgType::GETVIBQUEUE,
    NetMsgType::VIBQUEUE,

    //group
    NetMsgType::CREATEGROUP,
    NetMsgType::CREATEGROUPACK,
    NetMsgType::SETBASEINFO,
    NetMsgType::SETBASEINFOACK,
    NetMsgType::ADDMEMBER,
    NetMsgType::ADDMEMBERACK,
    NetMsgType::REFUSEMEMBER,
    NetMsgType::REFUSEMEMBERACK,
    NetMsgType::REMOVEMEMBER,
    NetMsgType::REMOVEMEMBERACK,
    NetMsgType::INCREASEMAX,
    NetMsgType::INCREASEMAXACK,
    NetMsgType::PERSONADDGROUP,
    NetMsgType::PERSONADDGROUPACK,
    NetMsgType::PERSONCANCELGROUP,
    NetMsgType::PERSONCANCELGROUPACK,
    NetMsgType::PERSONEXITGROUP,
    NetMsgType::PERSONEXITGROUPACK,
    NetMsgType::SETGROUPNAME,
    NetMsgType::SETGROUPNAMEACK,
    NetMsgType::SETGROUPANNOUN,
    NetMsgType::SETGORUPANNOUNACK,
    NetMsgType::SETGROUPRULE,
    NetMsgType::SETGROUPRULEACK,
    NetMsgType::SETOTCPERCENT,
    NetMsgType::SETOTCPERCENTACK,
    NetMsgType::SETGROUPFEE,
    NetMsgType::SETGROUPFEEACK,
    NetMsgType::SETGFEEOTCPERCENT,
    NetMsgType::SETGFEEOTCPERCENTACK,
    NetMsgType::SETOTCPERCENTCURRENCY,
    NetMsgType::SETOTCPERCENTCURRENCYACK,
    NetMsgType::SETCURRENCY,
    NetMsgType::SETCURRENCYACK,
    NetMsgType::SETSTARTOTC,
    NetMsgType::SETSTARTOTCACK,
    NetMsgType::ISGROUPADDR,
    NetMsgType::ISGROUPADDRACK,
    //otc
    NetMsgType::CREATEOTC,
    NetMsgType::CREATEOTCACK,
    NetMsgType::PAYVOLUMANDFEE,
    NetMsgType::PAYVOLUMANDFEEACK,
    NetMsgType::PAYFEE,
    NetMsgType::PAYFEEACK,
    NetMsgType::APPROVE,
    NetMsgType::APPROVEACK,
    NetMsgType::JUDGE,
    NetMsgType::JUDGEACK,
    NetMsgType::CANCEL,
    NetMsgType::CANCELACK,

    // lightnode
    NetMsgType::LNODE,
    NetMsgType::LNBLOCK,
    NetMsgType::GETLNBLOCKS,
    NetMsgType::SENDLNHEADERS,
    NetMsgType::GETLNHEADERS,
    NetMsgType::LNHEADERS,

    //additional address message
    NetMsgType::ADDR_ADD,
    NetMsgType::ADDR_UPDATE,
    NetMsgType::ADDR_DELETE,
    NetMsgType::GETSERVICEPORT,
    NetMsgType::SERVICEPORT,
};

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {
    NetMsgType::VERSION,
    NetMsgType::VERACK,
    NetMsgType::ADDR,
    NetMsgType::INV,
    NetMsgType::GETDATA,
    NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS,
    NetMsgType::GETHEADERS,
    NetMsgType::TX,
    NetMsgType::HEADERS,
    NetMsgType::BLOCK,
    NetMsgType::GETADDR,
    NetMsgType::MEMPOOL,
    NetMsgType::PING,
    NetMsgType::PONG,
    NetMsgType::ALERT,
    NetMsgType::NOTFOUND,
    NetMsgType::FILTERLOAD,
    NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR,
    NetMsgType::REJECT,
    NetMsgType::SENDHEADERS,
    // vds message types
    // NOTE: do NOT include non-implmented here, we want them to be "Unknown command" in ProcessMessage()
    //NetMsgType::TXLOCKREQUEST,
    NetMsgType::TXLOCKVOTE,
    NetMsgType::MASTERNODEPAYMENTVOTE,
    NetMsgType::MASTERNODE_PAYMENT_BLOCK,
    NetMsgType::MASTERNODEPAYMENTSYNC,
    NetMsgType::MNANNOUNCE,
    NetMsgType::MNPING,
    NetMsgType::DSACCEPT,
    NetMsgType::DSVIN,
    NetMsgType::DSFINALTX,
    NetMsgType::DSSIGNFINALTX,
    NetMsgType::DSCOMPLETE,
    NetMsgType::DSSTATUSUPDATE,
    NetMsgType::DSTX,
    NetMsgType::DSQUEUE,
    NetMsgType::DSEG,
    NetMsgType::SYNCSTATUSCOUNT,
    NetMsgType::MNGOVERNANCESYNC,
    NetMsgType::MNGOVERNANCEOBJECT,
    NetMsgType::MNGOVERNANCEOBJECTVOTE,
    NetMsgType::MNVERIFY,

    // Message for SPV
    NetMsgType::GETTX,
    NetMsgType::STX,
    NetMsgType::GETTX2,
    NetMsgType::STX2,
    NetMsgType::GETADMSG,
    NetMsgType::AD_MSG,
    NetMsgType::GETAD,
    NetMsgType::GETADLIST,
    NetMsgType::GETBIDLIST,
    NetMsgType::BIDLIST,
    NetMsgType::AD,
    NetMsgType::GETCLUE,
    NetMsgType::CLUE,
    NetMsgType::CLUE_PRE_CREATE_TREE,
    NetMsgType::PRE_CREATE_CLUE,
    NetMsgType::GETTOPCLUELIST,
    NetMsgType::TOPCLUELIST,
    NetMsgType::GETLUCKYNODES,
    NetMsgType::LUCKYNODES,
    NetMsgType::GETVCOUNT,
    NetMsgType::VCOUNT,
    NetMsgType::CALLCONTRACT,
    NetMsgType::CONTRACTRESULT,
    NetMsgType::INQUIRYCONTRACT,
    NetMsgType::INQUIRYCONTRACTACK,

    NetMsgType::GETVIB,
    NetMsgType::VIBINFO,

    NetMsgType::GETCLUETOPRECORD,
    NetMsgType::CLUETOPRECORD,

    //group
    NetMsgType::CREATEGROUP,
    NetMsgType::CREATEGROUPACK,
    NetMsgType::SETBASEINFO,
    NetMsgType::SETBASEINFOACK,
    NetMsgType::ADDMEMBER,
    NetMsgType::ADDMEMBERACK,
    NetMsgType::REFUSEMEMBER,
    NetMsgType::REFUSEMEMBERACK,
    NetMsgType::REMOVEMEMBER,
    NetMsgType::REMOVEMEMBERACK,
    NetMsgType::INCREASEMAX,
    NetMsgType::INCREASEMAXACK,
    NetMsgType::PERSONADDGROUP,
    NetMsgType::PERSONADDGROUPACK,
    NetMsgType::PERSONCANCELGROUP,
    NetMsgType::PERSONCANCELGROUPACK,
    NetMsgType::PERSONEXITGROUP,
    NetMsgType::PERSONEXITGROUPACK,
    NetMsgType::SETGROUPNAME,
    NetMsgType::SETGROUPNAMEACK,
    NetMsgType::SETGROUPANNOUN,
    NetMsgType::SETGORUPANNOUNACK,
    NetMsgType::SETGROUPRULE,
    NetMsgType::SETGROUPRULEACK,
    NetMsgType::SETOTCPERCENT,
    NetMsgType::SETOTCPERCENTACK,
    NetMsgType::SETGROUPFEE,
    NetMsgType::SETGROUPFEEACK,
    NetMsgType::SETGFEEOTCPERCENT,
    NetMsgType::SETGFEEOTCPERCENTACK,
    NetMsgType::SETOTCPERCENTCURRENCY,
    NetMsgType::SETOTCPERCENTCURRENCYACK,
    NetMsgType::SETCURRENCY,
    NetMsgType::SETCURRENCYACK,
    NetMsgType::SETSTARTOTC,
    NetMsgType::SETSTARTOTCACK,
    NetMsgType::ISGROUPADDR,
    NetMsgType::ISGROUPADDRACK,
    //otc
    NetMsgType::CREATEOTC,
    NetMsgType::CREATEOTCACK,
    NetMsgType::PAYVOLUMANDFEE,
    NetMsgType::PAYVOLUMANDFEEACK,
    NetMsgType::PAYFEE,
    NetMsgType::PAYFEEACK,
    NetMsgType::APPROVE,
    NetMsgType::APPROVEACK,
    NetMsgType::JUDGE,
    NetMsgType::JUDGEACK,
    NetMsgType::CANCEL,
    NetMsgType::CANCELACK,

    // lightnode
    NetMsgType::LNODE,
    NetMsgType::LNBLOCK,
    NetMsgType::GETLNBLOCKS,
    NetMsgType::SENDLNHEADERS,
    NetMsgType::GETLNHEADERS,
    NetMsgType::LNHEADERS,

    //additional address message
    NetMsgType::ADDR_ADD,
    NetMsgType::ADDR_UPDATE,
    NetMsgType::ADDR_DELETE,
    NetMsgType::GETSERVICEPORT,
    NetMsgType::SERVICEPORT,
};

const static std::vector<std::string> allNetMessageTypesVec(allNetMessageTypes, allNetMessageTypes + ARRAYLEN(allNetMessageTypes));

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    nMessageSize = -1;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsValid(const MessageStartChars& pchMessageStartIn) const
{
    // Check start string
    if (memcmp(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE) != 0)
        return false;

    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++) {
        if (*p1 == 0) {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        } else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE) {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand(), nMessageSize);
        return false;
    }

    return true;
}



CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, ServiceFlags nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NONE;
    nTime = 100000000;
}

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(int typeIn, const uint256& hashIn)
{
    type = typeIn;
    hash = hashIn;
}

CInv::CInv(const std::string& strType, const uint256& hashIn)
{
    unsigned int i;
    for (i = 1; i < ARRAYLEN(ppszTypeName); i++) {
        if (strType == ppszTypeName[i]) {
            type = i;
            break;
        }
    }
    if (i == ARRAYLEN(ppszTypeName))
        throw std::out_of_range(strprintf("CInv::CInv(string, uint256): unknown type '%s'", strType));
    hash = hashIn;
}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

bool operator==(const CInv& a, const CInv& b)
{
    return (a.type == b.type && a.hash == b.hash);
}

bool CInv::IsKnownType() const
{
    return (type >= 1 && type < (int)ARRAYLEN(ppszTypeName));
}

const char* CInv::GetCommand() const
{
    if (!IsKnownType())
        throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    return ppszTypeName[type];
}

std::string CInv::ToString() const
{
    try {
        return strprintf("%s %s", GetCommand(), hash.ToString());
    } catch (const std::out_of_range&) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

const std::vector<std::string>& getAllNetMessageTypes()
{
    return allNetMessageTypesVec;
}
