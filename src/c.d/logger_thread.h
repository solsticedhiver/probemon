#ifndef LOGGER_THREAD_H
#define LOGGER_THREAD_H

#include <stdint.h>
#include <time.h>

struct probereq {
  struct timeval tv;
  char *mac;
  char *vendor;
  uint8_t *ssid;
  uint8_t ssid_len;
  int rssi;
};
typedef struct probereq probereq_t;

void *process_queue(void *args);
void free_probereq(probereq_t *pr);

#endif
