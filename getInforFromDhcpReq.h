#ifndef GET_INFOR_FROM_DHCP_REQ_H
#define GET_INFOR_FROM_DHCP_REQ_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <vector>
#include <cstring>


typedef std::vector<uint8_t> PacketBuffer;
typedef std::map<uint8_t, PacketBuffer> OptionCollection;
typedef std::map<uint8_t, PacketBuffer>::iterator OptionCollectionIt;


enum DHCPMessageType {
    DHCPDISCOVER        =  1,
    DHCPOFFER           =  2,
    DHCPREQUEST         =  3,
    DHCPDECLINE         =  4,
    DHCPACK             =  5,
    DHCPNAK             =  6,
    DHCPRELEASE         =  7,
    DHCPINFORM          =  8,
    DHCPLEASEQUERY      =  10,
    DHCPLEASEUNASSIGNED =  11,
    DHCPLEASEUNKNOWN    =  12,
    DHCPLEASEACTIVE     =  13,
    DHCPBULKLEASEQUERY  =  14,
    DHCPLEASEQUERYDONE  =  15
};

class bufferHandler
{
public:
    bufferHandler(const void* data, size_t len) :
        position_(0), data_(static_cast<const uint8_t*>(data)), len_(len) {}

    size_t getLength() const { return (len_); }
    size_t getPosition() const { return (position_); }
    bool setPosition(size_t position) {
        if (position > len_) {
            return false;
        }
        position_ = position;
        return true;
    }

    bool readUint8(uint8_t &data) {
        if (position_ + sizeof(uint8_t) > len_) {
            return false;
        }
        data = data_[position_];
        position_ += sizeof(uint8_t);
        return true;
    }

    bool readUint16(uint16_t &data) {
        const uint8_t* cp;

        if (position_ + sizeof(uint16_t) > len_) {
            return false;
        }

        cp = &data_[position_];
        data = ((unsigned int)(cp[0])) << 8;
        data |= ((unsigned int)(cp[1]));
        position_ += sizeof(uint16_t);
        return true;
    }

    bool readUint32(uint32_t &data){
        const uint8_t* cp;

        if (position_ + sizeof(uint32_t) > len_) {
            return false;
        }

        cp = &data_[position_];
        data = ((unsigned int)(cp[0])) << 24;
        data |= ((unsigned int)(cp[1])) << 16;
        data |= ((unsigned int)(cp[2])) << 8;
        data |= ((unsigned int)(cp[3]));
        position_ += sizeof(uint32_t);

        return true;
    }

    bool readData(void* data, size_t len) {
        if (position_ + len > len_) {
            return false;
        }

        std::memcpy(data, &data_[position_], len);
        position_ += len;
        return true;
    }



private:
    size_t position_;
    const uint8_t* data_;
    size_t len_;

};




class dhcpReqInfoGet{
public:

    const static size_t MAX_CHADDR_LEN = 16;

    const static size_t MAX_SNAME_LEN = 64;

    const static size_t MAX_FILE_LEN = 128;

    const static size_t DHCPV4_PKT_HDR_LEN = 236;

    const static uint16_t FLAG_BROADCAST_MASK = 0x8000;

    const static uint32_t DHCP_OPTIONS_COOKIE = 0x63825363;

    const static size_t ETH_MAC_LENGTH = 6;

    const static uint8_t OPT_PAD = 0x00;
    const static uint8_t OPT_END = 0xff;
    const static size_t MAX_OPT_LEN = 255;

    dhcpReqInfoGet(){data_.clear();};

    bool inputDhcpReqMsg(uint8_t *buf, uint32_t len);
    uint8_t getOp() const { return (op_); };
    uint8_t getHops() const { return (hops_); };
    uint32_t getXid() const { return (xid_);};
    uint16_t getSecs() const { return (secs_); };
    uint16_t getFlags() const { return (flags_); };
    uint32_t getCiaddr() const { return (ciaddr_); };
    uint32_t getYiaddr() const { return (yiaddr_); };
    uint32_t getSiaddr() const { return (siaddr_); };
    uint32_t getGiaddr() const { return (giaddr_); };

    std::string getCiaddrString() { return convertIPAddress(ciaddr_);};
    std::string getYiaddrString() { return convertIPAddress(yiaddr_);};
    std::string getSiaddrString() { return convertIPAddress(siaddr_);};
    std::string getGiaddrString() { return convertIPAddress(giaddr_);};



    const PacketBuffer getClientMacAddress()const { return (std::vector<uint8_t>(ethMacAddress_, &ethMacAddress_[ETH_MAC_LENGTH])); };
    const PacketBuffer getSname() const { return (std::vector<uint8_t>(sname_, &sname_[MAX_SNAME_LEN])); };
    const PacketBuffer getFile() const { return (std::vector<uint8_t>(file_, &file_[MAX_FILE_LEN])); };
    const PacketBuffer getchaddr() const { return (std::vector<uint8_t>(chaddr_, &chaddr_[MAX_CHADDR_LEN])); };

    bool GetOptMsgByMsgType(uint8_t &msgType, PacketBuffer &optMsg);

    bool GetAluRRUIPAndTopoInfo(std::string &ip, uint8_t &bbuPort, uint8_t &rruId);
     


private:
    bool unpack();
    std::string convertIPAddress(uint32_t &address);
    bool collectOptions(bufferHandler &dhcpBuffer);

    


    PacketBuffer data_;
    uint8_t *pdata_;
    //size_t len_;
    //size_t position_;

    uint8_t op_;
    uint8_t hops_;
    uint32_t xid_;
    uint16_t secs_;
    uint16_t flags_;
    uint32_t ciaddr_;
    uint32_t yiaddr_;
    uint32_t siaddr_;
    uint32_t giaddr_;
    uint8_t sname_[MAX_SNAME_LEN];
    uint8_t file_[MAX_FILE_LEN];
    uint8_t chaddr_[MAX_CHADDR_LEN];
    uint8_t ethMacAddress_[ETH_MAC_LENGTH];

    OptionCollection option_;

};


#endif