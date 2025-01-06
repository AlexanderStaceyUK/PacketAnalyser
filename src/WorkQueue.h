struct Node {
  const unsigned char *packet;
  int length;
  struct Node *next; // The next node in the linked list
};

struct WorkQueue {
    struct Node *head;
    struct Node *tail;
};

struct WorkQueue *create(void);

void enqueue (struct WorkQueue *queue, int length, const unsigned char *packet);

int isEmpty(struct WorkQueue *queue);

void dequeue(struct WorkQueue *queue);

void destroy(struct WorkQueue *queue);