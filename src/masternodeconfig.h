
// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SRC_MASTERNODECONFIG_H_
#define SRC_MASTERNODECONFIG_H_

class CMasternodeConfig;
extern CMasternodeConfig masternodeConfig;

class CMasternodeConfig
{

public:

    class CMasternodeEntry
    {

    private:
        std::string alias;
        std::string privKey;
        std::string txHash;
        std::string outputIndex;
    public:

        CMasternodeEntry(std::string alias, std::string privKey, std::string txHash, std::string outputIndex)
        {
            this->alias = alias;
            this->privKey = privKey;
            this->txHash = txHash;
            this->outputIndex = outputIndex;
        }

        const std::string& getAlias() const
        {
            return alias;
        }

        void setAlias(const std::string& alias)
        {
            this->alias = alias;
        }

        const std::string& getOutputIndex() const
        {
            return outputIndex;
        }

        void setOutputIndex(const std::string& outputIndex)
        {
            this->outputIndex = outputIndex;
        }

        const std::string& getPrivKey() const
        {
            return privKey;
        }

        void setPrivKey(const std::string& privKey)
        {
            this->privKey = privKey;
        }

        const std::string& getTxHash() const
        {
            return txHash;
        }

        void setTxHash(const std::string& txHash)
        {
            this->txHash = txHash;
        }

    };

    CMasternodeConfig()
    {
        entries = std::vector<CMasternodeEntry>();
    }

    void clear();
    bool read(std::string& strErr);
    void add(std::string alias, std::string privKey, std::string txHash, std::string outputIndex);

    std::vector<CMasternodeEntry>& getEntries()
    {
        return entries;
    }

    int getCount()
    {
        return (int)entries.size();
    }

private:
    std::vector<CMasternodeEntry> entries;


};


#endif /* SRC_MASTERNODECONFIG_H_ */
