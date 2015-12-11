#include "getInforFromDhcpReq.h"
#include <iostream>
#include <sstream>

bool dhcpReqInfoGet::inputDhcpReqMsg(uint8_t *buf, uint32_t len)
{
    if(0 == buf || len < DHCPV4_PKT_HDR_LEN)
    {
        std::cout << "err, invalid input DHCP　packet" << std::endl;
        return false;
    }

    data_.resize(len);
    std::memcpy(&data_[0], buf, len);

    printf("******************************\r\n");
    for(int i = 0; i < len; i++)
    {
        printf("%02x", data_[i]);
    }

    /*pdata_ = reinterpret_cast<uint8_t*>(data_.data());
    position_ = 0;
    len_ = len;*/

    if(!unpack())
    {
        std::cout << "err, unable to unpack"  << std::endl;;
        return false;
    }

    return true;
}

std::string dhcpReqInfoGet::convertIPAddress(uint32_t &address)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = address;
    const char *addr = inet_ntoa(ip_addr);
    std::string str(addr);
    return str;
}

void showOpt(uint8_t optType, uint8_t optLen, uint8_t *optMsg)
{
    printf("subType : %d | ", optType);
    printf("subLen : %d | ", optLen);
    printf("subMsg : ");
    for(int i = 0; i < optLen; i++)
    {
        printf("%02x ", optMsg[i]);
    }
    printf("\r\n");
}

bool dhcpReqInfoGet::collectOptions(bufferHandler &dhcpBuffer)
{
    uint8_t optType = 0;
    uint8_t optLen = 0;
    uint8_t optMsg[MAX_OPT_LEN];
    while(dhcpBuffer.getPosition() < dhcpBuffer.getLength())
    {
        
        bool res = true;

        res = dhcpBuffer.readUint8(optType);
        printf("optType = %d\r\n", optType);
        if(!res || optType > OPT_END)
        {
            return false;
        }

        if(optType == OPT_END || optType == OPT_PAD)
        {
            return true;
        }

        res = dhcpBuffer.readUint8(optLen);
        if(!res || optLen > (dhcpBuffer.getLength() - dhcpBuffer.getPosition()))
        {
            return false;
        }

        memset(optMsg, 0, MAX_OPT_LEN);
        res = dhcpBuffer.readData(&optMsg, optLen);
        if(!res)
        {
            return false;
        }
        showOpt(optType, optLen, optMsg);
        PacketBuffer msg = std::vector<uint8_t>(optMsg, &optMsg[optLen]);
        option_.insert (std::make_pair(optType, msg));
        printf("option_.size = %d\r\n", option_.size());

    }
}

bool dhcpReqInfoGet::GetOptMsgByMsgType(uint8_t &msgType, PacketBuffer &optMsg)
{
    OptionCollectionIt it = option_.find(msgType);
    if(option_.end() != it)
    {
        optMsg = it->second;
        return true;
    }
    return false;
}

bool dhcpReqInfoGet::GetAluRRUIPAndTopoInfo(std::string &ip, uint8_t &bbuPort, uint8_t &rruId)
{
    uint8_t optMsgType = 0x35;//dhcp message type should be 3
    PacketBuffer optMsgTypeMsg;
    if(!GetOptMsgByMsgType(optMsgType, optMsgTypeMsg))
    {
        return false;
    }
    if(0x03 != optMsgTypeMsg[0])
    {
        printf("not a dhcp request message\r\n");
        return false;
    }

    uint8_t optVsiType = 0x2b;//Vendor-specific Information 
    PacketBuffer optVsiMsg;
    if(!GetOptMsgByMsgType(optVsiType, optVsiMsg))
    {
        return false;
    }
    bufferHandler vsiBuffer(&optVsiMsg[0], optVsiMsg.size());
    uint8_t vsiType = 0;
    uint8_t vsiLen = 0;
    uint8_t vsiMsg[MAX_OPT_LEN];
    bool findTopo = false;
    while(vsiBuffer.getPosition() < vsiBuffer.getLength())
    {
        
        bool res = true;

        res = vsiBuffer.readUint8(vsiType);
        
        res = vsiBuffer.readUint8(vsiLen);
        if(!res || vsiLen > (vsiBuffer.getLength() - vsiBuffer.getPosition()))
        {
            return false;
        }

        memset(vsiMsg, 0, MAX_OPT_LEN);
        res = vsiBuffer.readData(&vsiMsg, vsiLen);
        if(!res)
        {
            return false;
        }
        showOpt(vsiType, vsiLen, vsiMsg);
        if(vsiType == 0x81 && vsiLen == 4)
        {
            bbuPort = vsiMsg[1]>>3;
            rruId = vsiMsg[3];
            findTopo = true;
            break;
        }

    }
    if(!findTopo)
    {
        printf("can't find topo info\r\n");
        return false;
    }

    uint8_t optReqIpType = 0x32;
    PacketBuffer optIPMsg;
    if(!GetOptMsgByMsgType(optReqIpType, optIPMsg))
    {
        return false;
    }
    uint32_t ipaddr = 0;
    memcpy(&ipaddr, &optIPMsg[0], sizeof(uint32_t));

    ip = convertIPAddress(ipaddr);

    return true;
}

/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
*/

bool dhcpReqInfoGet::unpack()
{

    bufferHandler dhcpBuffer(&data_[0], data_.size());
    int8_t res = true;
    uint8_t htype = 0;
    uint8_t hlen = 0;
    uint32_t magic = 0;
    
    res &= dhcpBuffer.readUint8(op_);
    res &= dhcpBuffer.readUint8(htype);
    res &= dhcpBuffer.readUint8(hlen);
    res &= dhcpBuffer.readUint8(hops_);
    res &= dhcpBuffer.readUint32(xid_);
    res &= dhcpBuffer.readUint16(secs_);
    res &= dhcpBuffer.readUint16(flags_);
    res &= dhcpBuffer.readUint32(ciaddr_);
    res &= dhcpBuffer.readUint32(yiaddr_);
    res &= dhcpBuffer.readUint32(siaddr_);
    res &= dhcpBuffer.readUint32(giaddr_);
    res &= dhcpBuffer.readData(&chaddr_, MAX_CHADDR_LEN);
    res &= dhcpBuffer.readData(&sname_, MAX_SNAME_LEN);
    res &= dhcpBuffer.readData(&file_, MAX_FILE_LEN);
    res &= dhcpBuffer.readUint32(magic);

    if(!res)
    {
        std::cout << "err, invalid DHCP packet" << std::endl;
        return false;
    }

    if(DHCP_OPTIONS_COOKIE != magic)
    {
        printf("no magic\r\n");
        return false;
    }

    if((0x01 != htype) || (0x06 != hlen))
    {
        std::cout << "err, not an eth mac address" << std::endl;
        return false;
    }
    std::memcpy(ethMacAddress_, &chaddr_[0], ETH_MAC_LENGTH);
    
    if(!collectOptions(dhcpBuffer))
    {
        printf("collectOption error\r\n");
        return false;
    }

    return true;
    
}
