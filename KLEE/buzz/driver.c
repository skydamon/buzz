#include <stdio.h>
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>

int main(int argc, char *argv[]){
	locatedPacket pkt1;
    int syn_of_pkt1;
    klee_make_symbolic(&syn_of_pkt1, sizeof(syn_of_pkt1), "pkt1.packet.tcpSYN");
    memcpy(&pkt1.packet.tcpSYN, &syn_of_pkt1, sizeof(syn_of_pkt1));


	locatedPacket pkt2;
	locatedPacket pkt3;
	locatedPacket pkt4;
    locatedPacket pkt5;

	
	int syn_of_pkt2;
	int syn_of_pkt3;
	int syn_of_pkt4;
    int syn_of_pkt5;


	klee_make_symbolic(&syn_of_pkt2, sizeof(syn_of_pkt2), "pkt2.packet.tcpSYN");
	klee_make_symbolic(&syn_of_pkt3, sizeof(syn_of_pkt3), "pkt3.packet.tcpSYN");
	klee_make_symbolic(&syn_of_pkt4, sizeof(syn_of_pkt4), "pkt4.packet.tcpSYN");
    klee_make_symbolic(&syn_of_pkt5, sizeof(syn_of_pkt5), "pkt5.packet.tcpSYN");


	memcpy(&pkt2.packet.tcpSYN, &syn_of_pkt2, sizeof(syn_of_pkt2));
	memcpy(&pkt3.packet.tcpSYN, &syn_of_pkt3, sizeof(syn_of_pkt3));
	memcpy(&pkt4.packet.tcpSYN, &syn_of_pkt4, sizeof(syn_of_pkt4));
	memcpy(&pkt5.packet.tcpSYN, &syn_of_pkt5, sizeof(syn_of_pkt5));


	int sig_of_pkt2;
	int sig_of_pkt3;
	int sig_of_pkt4;
    int sig_of_pkt5;


	klee_make_symbolic(&sig_of_pkt2, sizeof(sig_of_pkt2), "pkt2.packet.signature");
	klee_make_symbolic(&sig_of_pkt3, sizeof(sig_of_pkt3), "pkt3.packet.signature");
	klee_make_symbolic(&sig_of_pkt4, sizeof(sig_of_pkt4), "pkt4.packet.signature");
    klee_make_symbolic(&sig_of_pkt5, sizeof(sig_of_pkt5), "pkt5.packet.signature");


	memcpy(&pkt2.packet.signature, &sig_of_pkt2, sizeof(sig_of_pkt2));
	memcpy(&pkt3.packet.signature, &sig_of_pkt3, sizeof(sig_of_pkt3));
	memcpy(&pkt4.packet.signature, &sig_of_pkt4, sizeof(sig_of_pkt4));
    memcpy(&pkt5.packet.signature, &sig_of_pkt5, sizeof(sig_of_pkt5));


    int sig_of_pkt1;
    klee_make_symbolic(&sig_of_pkt1, sizeof(sig_of_pkt1), "pkt1.packet.signature");
    memcpy(&pkt1.packet.signature, &sig_of_pkt1, sizeof(sig_of_pkt1));
    

    //klee_assert(hips_badsig !=1);
	return 0;
}
