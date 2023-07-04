/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_API = 200;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_RESPONSE = 253;


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
    		TYPE_IPV4: parse_ipv4;
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
            TYPE_RESPONSE: parse_response;
            default: accept;
        }
    }

    state parse_response {
        packet.extract(hdr.response.next); 
        transition select(hdr.response.last.isLast) {
            1: parse_tcp;
            0: parse_response;
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

    register <bit<32>>(1025) map;
    register <bit<1>>(1025) exists;

    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action get() {
        map.read(hdr.response[0].value, hdr.API.key);
        exists.read(hdr.response[0].keyExists, hdr.API.key);
    }

    action put() {
        map.write(hdr.API.key, hdr.API.value);
        exists.write(hdr.API.key, 1);
    }

    action rangeSelect() {
        hdr.response.push_front(1);
        hdr.response[0].setValid();
        map.read(hdr.response[0].value, hdr.API.key);
        exists.read(hdr.response[0].keyExists, hdr.API.key);
        hdr.API.key = hdr.API.key + 1;
    }
    
    table Forwarding {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_nhop;
        }
    }

    table Operations {
        key = {
            hdr.API.queryType: exact;
        }
        actions = {
            drop;
            get;
            put;
            rangeSelect;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
    	if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (hdr.API.SID == 3) {
                Forwarding.apply();
            }
            Operations.apply();
            hdr.API.headerPad = 1;
            hdr.API.SID = 3;
            if (hdr.API.packetType == 1) {
                hdr.API.packetType = 2;
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
        if (hdr.response[0].isValid()) {
            if (hdr.API.queryType == 2 && hdr.API.packetType == 2) {
                	if (hdr.API.key < hdr.API.rangeKey){
            	    	recirculate_preserving_field_list(0);
            	    }
            }
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
        packet.emit(hdr.ipv4);
        packet.emit(hdr.API);
        packet.emit(hdr.response);
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
