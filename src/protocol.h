// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef VDS_PROTOCOL_H
#define VDS_PROTOCOL_H

#include "netaddress.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <stdint.h>
#include <string>

#define MESSAGE_START_SIZE 4

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

    CMessageHeader(const MessageStartChars& pchMessageStartIn);
    CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid(const MessageStartChars& messageStart) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(FLATDATA(pchChecksum));
    }

    // TODO: make private (improves encapsulation)
public:
    enum {
        COMMAND_SIZE = 12,
        MESSAGE_SIZE_SIZE = 4,
        CHECKSUM_SIZE = 4,

        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
        HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
    };
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    uint32_t nMessageSize;
    uint8_t pchChecksum[CHECKSUM_SIZE];
};

/**
 * Bitcoin protocol message types. When adding new message types, don't forget
 * to update allNetMessageTypes in protocol.cpp.
 */
namespace NetMsgType
{

/**
 * The version message provides information about the transmitting node to the
 * receiving node at the beginning of a connection.
 * @see https://bitcoin.org/en/developer-reference#version
 */
extern const char* VERSION;
/**
 * The verack message acknowledges a previously-received version message,
 * informing the connecting node that it can begin to send other messages.
 * @see https://bitcoin.org/en/developer-reference#verack
 */
extern const char* VERACK;
/**
 * The addr (IP address) message relays connection information for peers on the
 * network.
 * @see https://bitcoin.org/en/developer-reference#addr
 */
extern const char* ADDR;

/**
 * The inv message (inventory message) transmits one or more inventories of
 * objects known to the transmitting peer.
 * @see https://bitcoin.org/en/developer-reference#inv
 */
extern const char* INV;
/**
 * The getdata message requests one or more data objects from another node.
 * @see https://bitcoin.org/en/developer-reference#getdata
 */
extern const char* GETDATA;
/**
 * The merkleblock message is a reply to a getdata message which requested a
 * block using the inventory type MSG_MERKLEBLOCK.
 * @since protocol version 70001 as described by BIP37.
 * @see https://bitcoin.org/en/developer-reference#merkleblock
 */
extern const char* MERKLEBLOCK;
/**
 * The getblocks message requests an inv message that provides block header
 * hashes starting from a particular point in the block chain.
 * @see https://bitcoin.org/en/developer-reference#getblocks
 */
extern const char* GETBLOCKS;
/**
 * The getheaders message requests a headers message that provides block
 * headers starting from a particular point in the block chain.
 * @since protocol version 31800.
 * @see https://bitcoin.org/en/developer-reference#getheaders
 */
extern const char* GETHEADERS;
/**
 * The tx message transmits a single transaction.
 * @see https://bitcoin.org/en/developer-reference#tx
 */
extern const char* TX;
/**
 * The headers message sends one or more block headers to a node which
 * previously requested certain headers with a getheaders message.
 * @since protocol version 31800.
 * @see https://bitcoin.org/en/developer-reference#headers
 */
extern const char* HEADERS;
/**
 * The block message transmits a single serialized block.
 * @see https://bitcoin.org/en/developer-reference#block
 */
extern const char* BLOCK;
/**
 * The getaddr message requests an addr message from the receiving node,
 * preferably one with lots of IP addresses of other receiving nodes.
 * @see https://bitcoin.org/en/developer-reference#getaddr
 */
extern const char* GETADDR;
/**
 * The mempool message requests the TXIDs of transactions that the receiving
 * node has verified as valid but which have not yet appeared in a block.
 * @since protocol version 60002.
 * @see https://bitcoin.org/en/developer-reference#mempool
 */
extern const char* MEMPOOL;
/**
 * The ping message is sent periodically to help confirm that the receiving
 * peer is still connected.
 * @see https://bitcoin.org/en/developer-reference#ping
 */
extern const char* PING;
/**
 * The pong message replies to a ping message, proving to the pinging node that
 * the ponging node is still alive.
 * @since protocol version 60001 as described by BIP31.
 * @see https://bitcoin.org/en/developer-reference#pong
 */
extern const char* PONG;
/**
 * The alert message warns nodes of problems that may affect them or the rest
 * of the network.
 * @since protocol version 311.
 * @see https://bitcoin.org/en/developer-reference#alert
 */
extern const char* ALERT;
/**
 * The notfound message is a reply to a getdata message which requested an
 * object the receiving node does not have available for relay.
 * @ince protocol version 70001.
 * @see https://bitcoin.org/en/developer-reference#notfound
 */
extern const char* NOTFOUND;
/**
 * The filterload message tells the receiving peer to filter all relayed
 * transactions and requested merkle blocks through the provided filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterload
 */
extern const char* FILTERLOAD;
/**
 * The filteradd message tells the receiving peer to add a single element to a
 * previously-set bloom filter, such as a new public key.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filteradd
 */
extern const char* FILTERADD;
/**
 * The filterclear message tells the receiving peer to remove a previously-set
 * bloom filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterclear
 */
extern const char* FILTERCLEAR;
/**
 * The reject message informs the receiving node that one of its previous
 * messages has been rejected.
 * @since protocol version 70002 as described by BIP61.
 * @see https://bitcoin.org/en/developer-reference#reject
 */
extern const char* REJECT;
/**
 * Indicates that a node prefers to receive new block announcements via a
 * "headers" message rather than an "inv".
 * @since protocol version 70012 as described by BIP130.
 * @see https://bitcoin.org/en/developer-reference#sendheaders
 */
extern const char* SENDHEADERS;

// vds message types
// NOTE: do NOT declare non-implmented here, we don't want them to be exposed to the outside
// TODO: add description
extern const char* TXLOCKREQUEST;
extern const char* TXLOCKVOTE;
extern const char* MASTERNODEPAYMENTVOTE;

extern const char* MASTERNODE_PAYMENT_BLOCK;
extern const char* MASTERNODEPAYMENTSYNC;
extern const char* MNANNOUNCE;
extern const char* MNPING;
extern const char* DSACCEPT;
extern const char* DSVIN;
extern const char* DSFINALTX;
extern const char* DSSIGNFINALTX;
extern const char* DSCOMPLETE;
extern const char* DSSTATUSUPDATE;
extern const char* DSTX;
extern const char* DSQUEUE;
extern const char* DSEG;
extern const char* SYNCSTATUSCOUNT;
extern const char* MNGOVERNANCESYNC;
extern const char* MNGOVERNANCEOBJECT;
extern const char* MNGOVERNANCEOBJECTVOTE;
extern const char* MNVERIFY;

// Message for SPV
extern const char* GETTX;
extern const char* STX;
extern const char* GETTX2;
extern const char* STX2;
extern const char* GETADMSG;
extern const char* AD_MSG;
extern const char* GETAD;
extern const char* GETADLIST;
extern const char* GETBIDLIST;
extern const char* BIDLIST;
extern const char* AD;
extern const char* GETCLUE;
extern const char* CLUE;
extern const char* CALLCONTRACT;
extern const char* CONTRACTRESULT;
extern const char* GETVIB;
extern const char* VIBINFO;
extern const char* GETVIBQUEUE;
extern const char* VIBQUEUE;
extern const char* IM;
extern const char* GETTXS;
extern const char* CLUE_PRE_CREATE_TREE;
extern const char* PRE_CREATE_CLUE;
extern const char* GETTOPCLUELIST;
extern const char* TOPCLUELIST;
extern const char* GETLUCKYNODES;
extern const char* LUCKYNODES;
extern const char* GETVCOUNT;
extern const char* VCOUNT;
extern const char* GETCLUETOPRECORD;
extern const char* CLUETOPRECORD;

//group
extern const char* CREATEGROUP;
extern const char* CREATEGROUPACK;
extern const char* SETBASEINFO;
extern const char* SETBASEINFOACK;
extern const char* ADDMEMBER;
extern const char* ADDMEMBERACK;
extern const char* REFUSEMEMBER;
extern const char* REFUSEMEMBERACK;
extern const char* REMOVEMEMBER;
extern const char* REMOVEMEMBERACK;
extern const char* INCREASEMAX;
extern const char* INCREASEMAXACK;
extern const char* PERSONADDGROUP;
extern const char* PERSONADDGROUPACK;
extern const char* PERSONCANCELGROUP;
extern const char* PERSONCANCELGROUPACK;
extern const char* PERSONEXITGROUP;
extern const char* PERSONEXITGROUPACK;
extern const char* SETGROUPNAME;
extern const char* SETGROUPNAMEACK;
extern const char* SETGROUPANNOUN;
extern const char* SETGORUPANNOUNACK;
extern const char* SETGROUPRULE;
extern const char* SETGROUPRULEACK;
extern const char* SETOTCPERCENT;
extern const char* SETOTCPERCENTACK;
extern const char* SETGROUPFEE;
extern const char* SETGROUPFEEACK;
extern const char* SETGFEEOTCPERCENT;
extern const char* SETGFEEOTCPERCENTACK;
extern const char* SETOTCPERCENTCURRENCY;
extern const char* SETOTCPERCENTCURRENCYACK;
extern const char* SETCURRENCY;
extern const char* SETCURRENCYACK;
extern const char* SETSTARTOTC;
extern const char* SETSTARTOTCACK;
extern const char* INQUIRYCONTRACT;
extern const char* INQUIRYCONTRACTACK;
//otc
extern const char* CREATEOTC;
extern const char* CREATEOTCACK;
extern const char* PAYVOLUMANDFEE;
extern const char* PAYVOLUMANDFEEACK;
extern const char* PAYFEE;
extern const char* PAYFEEACK;
extern const char* APPROVE;
extern const char* APPROVEACK;
extern const char* JUDGE;
extern const char* JUDGEACK;
extern const char* CANCEL;
extern const char* CANCELACK;
extern const char* GETOTCTRANSSTATUS;
extern const char* GETOTCTRANSSTATUSACK;
extern const char* ISGROUPADDR;
extern const char* ISGROUPADDRACK;
extern const char* LNODE;
extern const char* LNBLOCK;
extern const char* GETLNBLOCKS;
extern const char* SENDLNHEADERS;
extern const char* GETLNHEADERS;
extern const char* LNHEADERS;
//additional address message
extern const char* ADDR_ADD;
extern const char* ADDR_UPDATE;
extern const char* ADDR_DELETE;

extern const char* GETSERVICEPORT;
extern const char* SERVICEPORT;
};

/* Get a vector of all valid message types (see above) */
const std::vector<std::string>& getAllNetMessageTypes();

/** nServices flags */
enum ServiceFlags : uint64_t {
    // Nothing
    NODE_NONE = 0,
    // NODE_NETWORK means that the node is capable of serving the block chain. It is currently
    // set by all vds Core nodes, and is unset by SPV clients or other peers that just want
    // network services but don't provide them.
    NODE_NETWORK = (1 << 0),
    // NODE_GETUTXO means the node is capable of responding to the getutxo protocol request.
    // vds Core does not support this but a patch set called Bitcoin XT does.
    // See BIP 64 for details on how this is implemented.
    NODE_GETUTXO = (1 << 1),
    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
    // vds Core nodes used to support this by default, without advertising this bit,
    // but no longer do as of protocol version 70201 (= NO_BLOOM_VERSION)
    NODE_BLOOM = (1 << 2),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // bitcoin-development mailing list. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BIP process.
};

/** A CService with information about it as peer */
class CAddress : public CService
{
public:
    CAddress();
    explicit CAddress(CService ipIn, ServiceFlags nServicesIn);

    void Init();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        int nVersion = s.GetVersion();
        if (ser_action.ForRead())
            Init();
        if (s.GetType() & SER_DISK)
            READWRITE(nVersion);
        if ((s.GetType() & SER_DISK) ||
                (nVersion >= CADDR_TIME_VERSION && !(s.GetType() & SER_GETHASH)))
            READWRITE(nTime);
        uint64_t nServicesInt = nServices;
        READWRITE(nServicesInt);
        nServices = (ServiceFlags)nServicesInt;
        READWRITE(*(CService*)this);
    }

    // TODO: make private (improves encapsulation)
public:
    ServiceFlags nServices;

    // disk and network only
    unsigned int nTime;
};

/** inv message data */
class CInv
{
public:
    CInv();
    CInv(int typeIn, const uint256& hashIn);
    CInv(const std::string& strType, const uint256& hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(type);
        READWRITE(hash);
    }

    friend bool operator<(const CInv& a, const CInv& b);
    friend bool operator == (const CInv& a, const CInv& b);

    bool IsKnownType() const;
    const char* GetCommand() const;
    std::string ToString() const;

    // TODO: make private (improves encapsulation)
public:
    int type;
    uint256 hash;
};

enum {
    MSG_TX = 1,
    MSG_BLOCK,
    // Nodes may always request a MSG_FILTERED_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK,
    // vds message types
    // NOTE: declare non-implmented here, we must keep this enum consistent and backwards compatible
    MSG_TXLOCK_VOTE,
    MSG_MASTERNODE_PAYMENT_VOTE,
    MSG_MASTERNODE_PAYMENT_BLOCK,
    MSG_MASTERNODE_ANNOUNCE,
    MSG_MASTERNODE_PING,
    MSG_DSTX,
    MSG_GOVERNANCE_OBJECT,
    MSG_GOVERNANCE_OBJECT_VOTE,
    MSG_MASTERNODE_VERIFY,

    // Message for SPV
    MSG_GETTX,
    MSG_STX,
    MSG_GETTX2,
    MSG_STX2,
    MSG_GETTXS,

    // ad
    MSG_GETADMSG,
    MSG_AD_MSG,
    MSG_GETAD,
    MSG_GETADLIST,
    MSG_GETBIDLIST,
    MSG_BIDLIST,
    MSG_AD,

    // clue
    MSG_GETCLUE,
    MSG_CLUE,
    MSG_CLUE_PRE_CREATE_TREE,
    MSG_PRE_CREATE_CLUE,
    MSG_GETTOPCLUELIST,
    MSG_TOPCLUELIST,
    MSG_GETLUCKYNODES,
    MSG_LUCKYNODES,
    MSG_GETVCOUNT,
    MSG_VCOUNT,
    MSG_GETCLUETOPRECORD,
    MSG_CLUETOPRECORD,
    MSG_GETOTCTRANSSTATUS,
    MSG_GETOTCTRANSSTATUSACK,

    // contract
    MSG_CALLCONTRACT,
    MSG_CONTRACTRESULT,
    MSG_INQUIRYCONTRACT,
    MSG_INQUIRYCONTRACTACK,

    // vib
    MSG_GETVIB,
    MSG_VIBINFO,
    MSG_GETVIBQUEUE,
    MSG_VIBQUEUE,

    // group
    MSG_CREATEGROUP,
    MSG_CREATEGROUPACK,
    MSG_SETBASEINFO,
    MSG_SETBASEINFOACK,
    MSG_ADDMEMBER,
    MSG_ADDMEMBERACK,
    MSG_REFUSEMEMBER,
    MSG_REFUSEMEMBERACK,
    MSG_REMOVEMEMBER,
    MSG_REMOVEMEMBERACK,
    MSG_INCREASEMAX,
    MSG_INCREASEMAXACK,
    MSG_PERSONADDGROUP,
    MSG_PERSONADDGROUPACK,
    MSG_PERSONCANCELGROUP,
    MSG_PERSONCANCELGROUPACK,
    MSG_PERSONEXITGROUP,
    MSG_PERSONEXITGROUPACK,
    MSG_SETGROUPNAME,
    MSG_SETGROUPNAMEACK,
    MSG_SETGROUPANNOUN,
    MSG_SETGORUPANNOUNACK,
    MSG_SETGROUPRULE,
    MSG_SETGROUPRULEACK,
    MSG_SETOTCPERCENT,
    MSG_SETOTCPERCENTACK,
    MSG_SETGROUPFEE,
    MSG_SETGROUPFEEACK,
    MSG_SETGFEEOTCPERCENT,
    MSG_SETGFEEOTCPERCENTACK,
    MSG_SETOTCPERCENTCURRENCY,
    MSG_SETOTCPERCENTCURRENCYACK,
    MSG_SETCURRENCY,
    MSG_SETCURRENCYACK,
    MSG_SETSTARTOTC,
    MSG_SETSTARTOTCACK,
    MSG_ISGROUPADDR,
    MSG_ISGROUPADDRACK,
    // otc
    MSG_CREATEOTC,
    MSG_CREATEOTCACK,
    MSG_PAYVOLUMANDFEE,
    MSG_PAYVOLUMANDFEEACK,
    MSG_PAYFEE,
    MSG_PAYFEEACK,
    MSG_APPROVE,
    MSG_APPROVEACK,
    MSG_JUDGE,
    MSG_JUDGEACK,
    MSG_CANCEL,
    MSG_CANCELACK,
    // lightnode
    MSG_LIGHTNODE,
    MSG_LNBLOCK,
    MSG_GETLNBLOCK,
    MSG_SENDLNHEADERS,
    MSG_GETLNHEADERS,
    MSG_LNHEADERS,

    MSG_ADDR_ADD,
    MSG_ADDR_UPDATE,
    MSG_ADDR_DELETE,
    MSG_GETSERVICEPORT,
    MSG_SERVICEPORT
};

#endif // VDS_PROTOCOL_H
