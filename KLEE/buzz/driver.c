#include <stdio.h>
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>
int dlog(const char* str)
{
    FILE *log_file;
    log_file = fopen("log.file", "a");
    fputs(str,log_file);
    fclose(log_file);
return 0;
}

Link linkParser(char *linksLineStr){
	char *a[3];
	int n=0, i;
 
	a[n]=strtok(linksLineStr, "\t");

	while(a[n] && (n<4))
		a[++n] = strtok(NULL, "\t");

	Link l;
	l.end1.num = atoi(a[0]);
	l.end2.num = atoi(a[1]);

	return l;
}

Node nodeParser(char *nodesLineStr){
	char a[3][11];
	int n=0, i;

	char *token;
	token = strtok(nodesLineStr ,"\t");

	while((token != NULL) && (n<3)){
		strcpy(a[n++], token);
		token = strtok(NULL, "\t");
	}

	Node node;
	strcpy(node.type, a[0]);
	node.index = atoi(a[1]);
	node.port.num = atoi(a[2]);

	return node;
}

void forwardingTablesParser(char *forwardingTablesFileLineStr){
	char a[6][10];
	int n=0, i;

	char *token;
	token = strtok(forwardingTablesFileLineStr ,"\t");

	while((token != NULL) && (n<6)){
		strcpy(a[n++], token);
		token = strtok(NULL, "\t");
	}

	int inPort = atoi(a[1]);
	int srcIP = atoi(a[2]);
	int dstIP = atoi(a[3]);
	int tag = atoi(a[4]);
	int outPort = atoi(a[5]);

	nextHop[inPort][srcIP][dstIP][tag] = outPort;
}

void packetParser(char* pktStr, locatedPacket *pkt){
	//char *a[TRAFFIC_FILE_NO_OF_FIELDS];
	char *a[128];
	int n=0, i;
 
	a[n]=strtok(pktStr, "\t");

	while(a[n] && (n<TRAFFIC_FILE_NO_OF_FIELDS))
		a[++n] = strtok(NULL, "\t");

	// locatedPacket pkt;
	pkt->packet.id = atoi(a[0]);
	pkt->packet.srcIP = atoi(a[1]);
	pkt->packet.dstIP = atoi(a[2]);
	pkt->packet.srcPort = atoi(a[3]);
	pkt->packet.dstPort = atoi(a[4]);
	pkt->packet.proto = atoi(a[5]);
	pkt->packet.isHttp = atoi(a[6]);
	pkt->packet.httpGetObj = atoi(a[7]);
	pkt->packet.httpRespObj = atoi(a[8]);
	pkt->packet.tag = atoi(a[9]);
	pkt->packet.tcpSYN = atoi(a[10]);
	pkt->packet.tcpACK = atoi(a[11]);
	pkt->packet.tcpFIN = atoi(a[12]);
	pkt->packet.connId = atoi(a[13]);
	pkt->packet.fromClient = atoi(a[14]);
	pkt->packet.timeout = atoi(a[15]);
	pkt->packet.dropped = atoi(a[16]);
	pkt->port.num = atoi(a[17]);

//	return pkt;
}

locatedPacket swProc(locatedPacket inPkt){
	dlog("swProc\n");
	locatedPacket outPkt;
	outPkt = inPkt;
	outPkt.port.num = nextHop[inPkt.port.num][inPkt.packet.srcIP][inPkt.packet.dstIP][inPkt.packet.tag];
	return outPkt;
}

int main(int argc, char *argv[]){
    dlog("start\n");

    FILE *nodesFile = fopen("nodes.dat","r");
    FILE *linksFile = fopen("links.dat","r");
    FILE *forwardingTablesFile = fopen("forwardingTables.dat","r");

    hips_badsig = 0;

	if (nodesFile == 0){
		printf("Could not open links file\n");
		return 1;
	}

	if (linksFile == 0){
		printf("Could not open links file\n");
		return 1;
	}

	if (forwardingTablesFile == 0){
		printf("Could not open links file\n");
		return 1;
	}

	int i;
	int j;

	//initialize ips status for all conns
	for (i=0; i<MAX_NO_OF_IPSES; i++)
		for (j=0; j<MAX_NO_OF_BOHATEI; j++)
			ipsDiffConnStates[i][j] = Diff_0;

	//Reading the links file************************************************
    char *currentPacketStr = NULL;
    char *linksFileLineStr = NULL;
    size_t len = 0;

	
	//ignore the first line
	getline(&linksFileLineStr, &len, linksFile);

	int linksPort[MAX_NO_OF_NETWIDE_PORTS];
	for (i=0; i<MAX_NO_OF_NETWIDE_PORTS; i++)
		linksPort[i] = -1;

	while (getline(&linksFileLineStr, &len, linksFile) != -1){
		Link l = linkParser(linksFileLineStr);
		linksPort[l.end1.num] = l.end2.num;
		linksPort[l.end2.num] = l.end1.num;
	}
	
	//Reading the nodes file************************************************
	int noOfPorts = 0;
	Node portInfo[MAX_NO_OF_NETWIDE_PORTS];//each port corresponds to one line of nodes.dat
	for (i=0; i<MAX_NO_OF_NETWIDE_PORTS; i++){
		portInfo[i].index = -1;
		portInfo[i].port.num = -1;
	}

	// bohatei IPS
	// light IPS
	int noOfIPSes = 0;
	for (i=0; i<MAX_NO_OF_IPSES; i++)
		ipsPorts[i] = -1;
	
	// heavy IPS
	int noOfHIPSes = 0;
	for (i=0; i<MAX_NO_OF_IPSES; i++)
		hipsPorts[i] = -1;


	int noOfHosts = 0;
	for (i=0; i<MAX_NO_OF_HOSTS; i++)
		hostPorts[i] = -1;

	int noOfSws = 0;
	int swPorts[MAX_NO_OF_SWITCHES][MAX_NO_OF_SWITCH_PORTS];
	int swPortsSeen[MAX_NO_OF_SWITCHES];

	for (i=0; i<MAX_NO_OF_SWITCHES; i++){
		swPortsSeen[i] = 0;
		for (j=0; j<MAX_NO_OF_SWITCH_PORTS; j++)
			swPorts[i][j] = -1;
	}

       	char *nodesFileLineStr = NULL;

	//ignore the first line
	getline(&nodesFileLineStr, &len, nodesFile);

	while (getline(&nodesFileLineStr, &len, nodesFile) != -1){
		Node node = nodeParser(nodesFileLineStr);

		//this is to have all info about each port in one place as in node.dat
		strcpy(portInfo[node.port.num].type, node.type);
		portInfo[node.port.num].index = node.index;
		portInfo[node.port.num].port.num = node.port.num;

		// bohatei node type
		if (node.type[0] == 'b')
			ipsPorts[noOfIPSes++] = node.port.num;
		if (node.type[0] == 'l')
			ipsPorts[noOfIPSes++] = node.port.num;
		if (node.type[0] == 'H')
			hipsPorts[noOfHIPSes++] = node.port.num;
		if (node.type[0] == 'h')
			hostPorts[noOfHosts++] = node.port.num;
		if (node.type[0] == 's'){
			swPorts[node.index][swPortsSeen[node.index]++] = node.port.num;
			if (node.index >= noOfSws)
				noOfSws = node.index + 1;
		}
	}

	//Reading the forwarding tables file************************************************
	int k;
	int l;

	for (i=0; i< MAX_NO_OF_NETWIDE_PORTS; i++)
		for (j=0; j< MAX_NO_OF_NODES; j++)
			for (k=0; k< MAX_NO_OF_NODES; k++)
				for (l=0; l< MAX_NO_OF_TAGS; l++)
					nextHop[i][j][k][l] = -1;

       	char *forwardingTablesFileLineStr = NULL;

	//ignore the first line
	getline(&forwardingTablesFileLineStr, &len, forwardingTablesFile);

	while (getline(&forwardingTablesFileLineStr, &len, forwardingTablesFile) != -1){
		forwardingTablesParser(forwardingTablesFileLineStr);
	}

	//this is a test to see if an injected packet can follow through the topology
	int injectionPortNo = 0;
    //automatic test generation block


	int zz;

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

	IP dstIP_of_pkt1;
	IP dstIP_of_pkt2;
	IP dstIP_of_pkt3;
	IP dstIP_of_pkt4;

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

	memcpy(&pkt1.packet.signature, &sig_of_pkt1, sizeof(sig_of_pkt1));



	locatedPacket pkt = pkt1;
		//move the packet until it arrives its destination or gets dropped
		while ((pkt.port.num != hostPorts[pkt.packet.dstIP]) && (!pkt.packet.dropped)){
			//forward pkt on the link
			pkt.port.num = linksPort[pkt.port.num];
			if (portInfo[pkt.port.num].type[0] == 's'){
				pkt = swProc(pkt);
			printf("\n");
		}

		printf("#############packet fated###################\n");
	}

	klee_assert(hips_badsig !=1);

	return 0;
}
