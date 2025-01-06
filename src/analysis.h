#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

typedef struct Count{
  int syn;
  int arp;
  int bbc;
  int google;
} Count;

void analyse(int length,
             const unsigned char *packet,
             struct Count *count);

#endif
