/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// define tpye of ipv4 and customized header
const bit<16> TYPE_MYHEADER = 0x1234;
const bit<16> TYPE_IPV4 = 0x0800;

// create register for counting bytes sent
register<bit<32>>(5) sent_count;
// create register for per-packet switch
register<bit<32>>(1) packet_count;
// create register for counting packet index
register<bit<32>>(100) packet_index;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


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

header myHeader_t {
    bit<32> id;
    bit<16> protocol;
    bit<32> nhop;
    bit<32> S1P2;
    bit<32> S1P3;
    bit<32> S2P1;
    bit<32> S3P1;
    bit<32> S4P1;
}

struct metadata {
    bit<14> ecmp_select;
}

struct headers {
    ethernet_t ethernet;
    myHeader_t myHeader;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MYHEADER: parse_myHeader;
            default: accept;
        }
    }

    state parse_myHeader {
        packet.extract(hdr.myHeader);
        transition select(hdr.myHeader.protocol) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
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

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        bit<32> byteSent;
        sent_count.read(byteSent, 1);
        if (hdr.myHeader.nhop != 1) {
            byteSent = byteSent + standard_metadata.packet_length;
        }
        sent_count.write(1, byteSent);
        hdr.myHeader.S4P1 = byteSent;

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.myHeader.nhop = hdr.myHeader.nhop + 1;
    }

    action ecmp_forward(macAddr_t dstAddr, egressSpec_t port) {
        bit<32> bytesSent;
        bit<32> bytesS1P2;
        bit<32> bytesS1P3;
        sent_count.read(bytesS1P2, 2);
        sent_count.read(bytesS1P3, 3);

        if (port == 2) {
            bytesS1P2 = bytesS1P2 + standard_metadata.packet_length;
        }

        else if (port == 3) {
            bytesS1P3 = bytesS1P3 + standard_metadata.packet_length;
        }

        sent_count.write(2, bytesS1P2);
        sent_count.write(3, bytesS1P3);
        hdr.myHeader.S1P2 = bytesS1P2;
        hdr.myHeader.S2P1 = bytesS1P2;
        hdr.myHeader.S1P3 = bytesS1P3;
        hdr.myHeader.S3P1 = bytesS1P3;

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.myHeader.nhop = hdr.myHeader.nhop + 1;
    }

    action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        bit<32> route_select;
        packet_count.read(route_select, 0);

        if (route_select == 0) {
            meta.ecmp_select = 0;
            route_select = 1;
        } else {
            meta.ecmp_select = 1;
            route_select = 0;
        }

        packet_count.write(0, route_select);

        bit<32> idx;
        packet_index.read(idx, 0);
        
        idx = idx + 1;
        hdr.myHeader.id = idx;

        packet_index.write(0, idx);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
    }

    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            ecmp_forward;
        }
        size = 2;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (hdr.myHeader.nhop == 0) {
                ecmp_group.apply();
                ecmp_nhop.apply();
            } else {
                ipv4_lpm.apply();
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
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        packet.emit(hdr.myHeader);
        packet.emit(hdr.ipv4);
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
