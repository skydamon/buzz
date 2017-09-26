#include "utils.h"
#include <string.h>
#include <klee/klee.h>

int main(int argc, char *argv[]){
    int var;
    klee_make_symbolic(&var, sizeof(var), "pkt1.packet.tcpSYN");
    klee_make_symbolic(&var, sizeof(var), "pkt2.packet.tcpSYN");
    klee_make_symbolic(&var, sizeof(var), "pkt3.packet.tcpSYN");
    klee_make_symbolic(&var, sizeof(var), "pkt4.packet.tcpSYN");
    klee_make_symbolic(&var, sizeof(var), "pkt5.packet.tcpSYN");


	return 0;
}
