#include <stdio.h>
#include <stdlib.h>
#include "WorkQueue.h"
// Based off threadpool queue

struct WorkQueue *create (void){
    struct WorkQueue *queue = (struct WorkQueue *) malloc (sizeof(struct WorkQueue));
    queue -> head = NULL;
    queue -> tail = NULL;
    return (queue);
}

void enqueue (struct WorkQueue *queue, int length, const unsigned char *packet){
    struct Node *newNode = (struct Node *) malloc(sizeof(struct Node));
    newNode -> length = length;
    newNode -> packet = packet;
    if (isEmpty(queue)){
        queue -> tail = newNode;
        queue -> head = newNode;
        queue -> tail -> next = NULL;
    }
    else {
        (queue -> tail) -> next = newNode;
        queue -> tail = newNode; 
    }
}


int isEmpty (struct WorkQueue *queue){
    return (queue -> head == NULL);
}

void dequeue (struct WorkQueue *queue){
    if (isEmpty(queue)){
        printf("Error: Can't dequeue from an empty queue");
    }
    else{
        struct Node *retained = queue -> head;
        queue -> head = queue -> head -> next;
        if (queue -> head == NULL){
            queue -> tail = NULL;
        }
        
    }
    
}

void destroy(struct WorkQueue *queue){
    while (!isEmpty(queue)){
        dequeue(queue);
    }

}