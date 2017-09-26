typedef enum {IP_0=0, IP_=1, IP_2=2, IP_3=3} IP;
//this struct represents a tcp segment
typedef struct{
	int id;//this is a globally unique packet id preserved as the packet traverses the network
	IP srcIP;
	IP dstIP;
	int srcPort;
	int dstPort;
	int proto;//0:TCP, 1: UDP
	int isHttp;//0: no, 1; yes 
	int httpGetObj;//-1: not an HTTP GET. Obj_ID: otherwise
	int httpRespObj;//-1: not an HTTP RESP. Obj_ID: otherwise
	int tag;//general-purpose tag (as in flowtags)
	int tcpSYN;//0: unset, 1; set 
	int tcpACK;//0: unset, 1; set 
	int tcpFIN;//0: unset, 1; set 
	int connId;//-1: don't care (i.e., not part of a flow, e.g., for udp packets). otherwise denotes the conn. id.
	int fromClient;//1: src of the packet is a tcp client; 0: src of the packet is a tcp server 
	int timeout;//1: a special packet representing timeout of the connection; 0: otherwise
	int dropped;//1: a special packet representing a dropped packet; 0: otherwise 
        int signature;//1: a packet with bad signature such as "drovemeeting"
}Packet;

//Ports represents points of connection in the network
typedef struct{
	int num;//each port has unique network-wide number
}Port;

typedef struct{
	Packet packet;
	Port port;
}locatedPacket;