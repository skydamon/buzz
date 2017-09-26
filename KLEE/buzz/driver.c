#include <stdio.h>
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>

int main(int argc, char *argv[]){
	locatedPacket pkt1;
	pkt1.packet.id = 1;
	pkt1.packet.srcIP = 0;
	pkt1.packet.dstIP = 1;
	pkt1.packet.dropped = 0;
	pkt1.packet.tag = 0;
	pkt1.packet.isHttp = 0;
	pkt1.packet.timeout = 0;
	pkt1.port.num = 0;

	locatedPacket pkt2;
	pkt2.packet.id = 2;
	pkt2.packet.srcIP = 0;
	pkt2.packet.dstIP = 1;
	pkt2.packet.dropped = 0;
	pkt2.packet.tag = 0;
	pkt2.packet.isHttp = 0;
	pkt2.packet.timeout = 0;
	pkt2.port.num = 0;

	locatedPacket pkt3;
	pkt3.packet.id = 3;
	pkt3.packet.srcIP = 0;
	pkt3.packet.dstIP = 1;
	pkt3.packet.dropped = 0;
	pkt3.packet.tag = 0;
	pkt3.packet.isHttp = 0;
	pkt3.packet.timeout = 0;
	pkt3.port.num = 0;

	locatedPacket pkt4;
	pkt4.packet.id = 4;
	pkt4.packet.srcIP = 0;
	pkt4.packet.dstIP = 1;
	pkt4.packet.dropped = 0;
	pkt4.packet.tag = 0;
	pkt4.packet.isHttp = 0;
	pkt4.packet.timeout = 0;
	pkt4.port.num = 0;


	pkt1.packet.tcpSYN = 1;
	pkt2.packet.tcpSYN = 1;
	pkt3.packet.tcpSYN = 1;
	pkt4.packet.tcpSYN = 1;

	int syn_of_pkt1;
	int syn_of_pkt2;
	int syn_of_pkt3;
	int syn_of_pkt4;

	klee_make_symbolic(&syn_of_pkt1, sizeof(syn_of_pkt1), "pkt1.packet.tcpSYN");
	klee_make_symbolic(&syn_of_pkt2, sizeof(syn_of_pkt2), "pkt2.packet.tcpSYN");
	klee_make_symbolic(&syn_of_pkt3, sizeof(syn_of_pkt3), "pkt3.packet.tcpSYN");
	klee_make_symbolic(&syn_of_pkt4, sizeof(syn_of_pkt4), "pkt4.packet.tcpSYN");

	memcpy(&pkt1.packet.tcpSYN, &syn_of_pkt1, sizeof(syn_of_pkt1));
	memcpy(&pkt2.packet.tcpSYN, &syn_of_pkt2, sizeof(syn_of_pkt2));
	memcpy(&pkt3.packet.tcpSYN, &syn_of_pkt3, sizeof(syn_of_pkt3));
	memcpy(&pkt4.packet.tcpSYN, &syn_of_pkt4, sizeof(syn_of_pkt4));
	



	pkt1.packet.signature = 1;
	pkt2.packet.signature = 1;
	pkt3.packet.signature = 1;
	pkt4.packet.signature = 1;

	int sig_of_pkt1;
	int sig_of_pkt2;
	int sig_of_pkt3;
	int sig_of_pkt4;

	klee_make_symbolic(&sig_of_pkt1, sizeof(sig_of_pkt1), "pkt1.packet.signature");
	klee_make_symbolic(&sig_of_pkt2, sizeof(sig_of_pkt2), "pkt2.packet.signature");
	klee_make_symbolic(&sig_of_pkt3, sizeof(sig_of_pkt3), "pkt3.packet.signature");
	klee_make_symbolic(&sig_of_pkt4, sizeof(sig_of_pkt4), "pkt4.packet.signature");

	memcpy(&pkt1.packet.signature, &sig_of_pkt1, sizeof(sig_of_pkt1));
	memcpy(&pkt2.packet.signature, &sig_of_pkt2, sizeof(sig_of_pkt2));
	memcpy(&pkt3.packet.signature, &sig_of_pkt3, sizeof(sig_of_pkt3));
	memcpy(&pkt4.packet.signature, &sig_of_pkt4, sizeof(sig_of_pkt4));
	
    //klee_assert(hips_badsig !=1);
	return 0;
}
