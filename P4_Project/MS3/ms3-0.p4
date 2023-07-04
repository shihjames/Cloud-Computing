/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PINGPONG_FREQ 10
#define CHECK_FREQ 15

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_API = 200;
const bit<8> TYPE_TCP = 6;
const bit<16> TYPE_RESPONSE = 0x1234;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> ByteCounter_t;
typedef bit<32> PacketCounter_t;
typedef bit<80> PacketByteCounter_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header API_t {
    bit<8> protocol;
    bit<32> key;
    bit<32> rangeKey;
    bit<32> value;
    bit<32> uBound;
    bit<32> hostID;
    bit<2> SID;
    bit<2> packetType;
    bit<2> queryType;
    bit<7> accessType;
    bit<3> headerPad;
}

header response_t {
    bit<32> key;
    bit<32> value;
    bit<1> keyExists;
    bit<1> isLast;
    bit<6> headerPad;
}

struct metadata {
    bit<16> ecmp_select;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
    response_t[1025]     response;
    tcp_t                tcp;
    API_t                API;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ether;
    }

    state parse_ether{
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType){
            TYPE_RESPONSE: parse_response;
            default: accept;
        }
    }

    state parse_response {
        packet.extract(hdr.response.next); 
        transition select(hdr.response.last.isLast) {
            1: parse_ipv4;
            0: parse_response; 
            default: accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_API: parse_API;
            default: accept;
        }
    }

    state parse_API{
        packet.extract(hdr.API);
        transition select (hdr.API.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp{
        packet.extract(hdr.tcp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register <bit<32>>(2) queryCnt;

    action configHost1() {
        if (hdr.API.queryType == 1 && hdr.API.key > 512) {
            hdr.API.accessType = 2;
        }
    }

    action configHost2() {
        if (hdr.API.queryType == 0 && hdr.API.key > 256) {
            hdr.API.accessType = 1;
        } else if (hdr.API.queryType == 1 && hdr.API.key > 256) {
            hdr.API.accessType = 2;
        } else if (hdr.API.queryType == 2 && hdr.API.uBound > 257) {
            hdr.API.accessType = 1;
        } else if (hdr.API.queryType == 2 && hdr.API.key > 256) {
            hdr.API.accessType = 1;
        } 
    }

    table ACL {
        key = {
            hdr.API.hostID : exact;
            standard_metadata.ingress_port : exact;
        }
        actions = {
            configHost1;
            configHost2;
        }
    }

    register <bit<32>>(2) pingPongCnt1;
    register <bit<32>>(2) pingPongCnt2;

    apply {
        if (hdr.response[0].isValid()) {
            ACL.apply();
            if (hdr.API.accessType != 0) {
                hdr.API.headerPad = 1;
                standard_metadata.egress_spec = 1;
            } else {
                bit<32> currentQuery = 0;
                if (standard_metadata.ingress_port == 1){
                    queryCnt.read(currentQuery, 0);
                    if (currentQuery + 1 == PINGPONG_FREQ) {
                        queryCnt.write(0, 0);
                        bit<32> pingCount = 0;
                        pingPongCnt1.read(pingCount, 0);
                        pingPongCnt1.write(0, pingCount + 1);
                        pingPongCnt2.read(pingCount, 0);
                        pingPongCnt2.write(0, pingCount + 1);
                        clone(CloneType.I2E, 2);
                        hdr.API.packetType = 0;
                    } else {
                        
                        if (hdr.API.queryType == 1) {
                            clone(CloneType.I2E, 1);
                        }
                        hdr.API.packetType = 0;
                        queryCnt.write(0, currentQuery + 1);
                    }
                    if (hdr.API.key >= 0 && hdr.API.key <= 512){
                        standard_metadata.egress_spec = 2;
                    } else if (hdr.API.key > 512 && hdr.API.key <= 1024){
                        standard_metadata.egress_spec = 3;
                    }
                } 
                else {
                    queryCnt.read(currentQuery, 1);
                    bit<32> pingCnt1 = 0;
                    bit<32> pongCnt1 = 0;
                    bit<32> pingCnt2 = 0;
                    bit<32> pongCnt2 = 0;
                    pingPongCnt1.read(pingCnt1, 0);
                    pingPongCnt1.read(pongCnt1, 1);
                    pingPongCnt2.read(pingCnt2, 0);
                    pingPongCnt2.read(pongCnt2, 1);
                    
                    if (hdr.API.packetType == 2) {
                        if (hdr.API.SID == 1){
                            pongCnt1 = pongCnt1 + 1;
                            pingPongCnt1.write(1, pongCnt1); 
                        } else if (hdr.API.SID == 2) {
                            pongCnt2 = pongCnt2 + 1;
                            pingPongCnt2.write(1, pongCnt2); 
                        } else {
                            hdr.API.packetType = 0;
                        }
                    } else if (currentQuery + 1 == CHECK_FREQ) {
                        if (pingCnt1 - pongCnt1 > PINGPONG_FREQ) {
                            hdr.API.packetType = 3;
                        }
                        if (pingCnt2 - pongCnt2 > PINGPONG_FREQ) {
                            hdr.API.packetType = 3;
                        }
                        queryCnt.write(1, 0);
                    } else {
                        queryCnt.write(1, currentQuery + 1);
                    }
                    standard_metadata.egress_spec = 1; 
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  
        if (standard_metadata.instance_type == 2) {
            hdr.API.packetType = 1;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.response);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.API);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
