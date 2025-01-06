#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>
#include <signal.h>
void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet);

void createWorkers ();
void KillThreads();
void SIGINTHandler(int a);
#endif
