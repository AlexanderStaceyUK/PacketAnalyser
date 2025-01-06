#include "dispatch.h"

#include <pcap.h>
#include "WorkQueue.h"
#include "analysis.h"
#include <stdlib.h>
#define NUMTHREADS 2

struct WorkQueue *WorkQueue;
pthread_mutex_t workQueue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t workQueue_condition = PTHREAD_COND_INITIALIZER;
pthread_t *workers[NUMTHREADS];
int end = 1;
void SIGINTHandler (int a){
  end = 0;
  KillThreads();
  exit(0);
}
// Kills threads and returns a summation of each individual count from each thread
void KillThreads(){
  int i;
  struct Count *endCount = malloc(sizeof(struct Count));
  endCount -> syn = 0;
  endCount -> arp = 0;
  endCount -> bbc = 0;
  endCount -> google = 0;
  for (i = 0 ; i < NUMTHREADS; i++){
    void *returned;
    
    pthread_join (workers[i], &returned);
    struct Count *threadCount = (struct Count *) returned;
    endCount -> syn = endCount -> syn + threadCount -> syn;
    endCount -> arp = endCount -> arp + threadCount -> arp;
    endCount -> bbc = endCount -> bbc + threadCount -> bbc;
    endCount -> google = endCount -> google + threadCount -> google;
  }
  printf("============================== \n");
  printf("Intrusion Detection Report: \n");
  printf("%d SYN packets detected from x different IPs (syn attack)\n", endCount->syn);
  printf("%d ARP responses (cache poisoning)\n", endCount -> arp);
  printf("%d URl Blacklist violations (%d google and %d bbc)\n", (endCount -> bbc + endCount -> google), endCount -> google, endCount -> bbc);
  printf("============================== \n");
}

// Handler for threads to complete work
void *threadHandler (){
  struct Count *count = (struct Count *) malloc (sizeof(struct Count));
  count -> bbc = 0;
  count -> syn = 0;
  count -> arp = 0;
  count -> google = 0;

  while (end){
    pthread_mutex_lock(&workQueue_mutex);
    while (isEmpty(WorkQueue)){
      pthread_cond_wait(&workQueue_condition, &workQueue_mutex);
    }
    unsigned const char *packet = WorkQueue -> head -> packet;
    int length = WorkQueue -> head -> length;
    dequeue(WorkQueue);
    pthread_mutex_unlock (&workQueue_mutex);
    if (packet != NULL && length != NULL){
      analyse(length, packet, count);
    }
  }
  pthread_exit ((void *) count);
}

// Creates threads and adds them to workers. Constructs an endCount for use when threads are killed alongside a workQueue
void createWorkers (){
  WorkQueue = create();
  int i;
  for (i = 0; i < NUMTHREADS; i++){
    pthread_create(&workers[i], NULL, threadHandler, NULL);
  }
}

// Manages enqueuing of work to the queue for use by threads
void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet) {

  pthread_mutex_lock (&workQueue_mutex);
  enqueue (WorkQueue, header -> len, packet);
  pthread_cond_broadcast (&workQueue_condition);
  pthread_mutex_unlock(&workQueue_mutex);
}
