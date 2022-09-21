/*
worker thread that will process the queue filled by process_packet()
*/

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sqlite3.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <semaphore.h>

#include "parsers.h"
#include "queue.h"
#include "logger_thread.h"
#include "db.h"
#include "manuf.h"
#include "config_yaml.h"
#include "lruc.h"
#include "config.h"

extern pthread_mutex_t mutex_queue;
extern queue_t *queue;
extern sem_t queue_empty;
extern sem_t queue_full;
extern sqlite3 *db;
struct timespec start_ts_cache;
extern bool option_stdout;

extern manuf_t *ouidb;
extern size_t ouidb_size;

extern uint64_t *ignored;
extern int ignored_count;

lruc *ssid_pk_cache = NULL, *mac_pk_cache = NULL;

void free_probereq(probereq_t *pr)
{
    if (pr == NULL) return;

    free(pr->mac);
    pr->mac = NULL;
    free(pr->ssid);
    pr->ssid = NULL;
    if (pr->vendor) free(pr->vendor);
    pr->vendor = NULL;
    free(pr);
    pr = NULL;
    return;
}

void *process_queue(void *args)
{
  probereq_t *pr;
  struct timespec now;

  mac_pk_cache = lruc_new(MAC_CACHE_SIZE, 1);
  ssid_pk_cache = lruc_new(SSID_CACHE_SIZE, 1);

  clock_gettime(CLOCK_MONOTONIC, &start_ts_cache);

  while (true) {
    sem_wait(&queue_empty);
    pthread_mutex_lock(&mutex_queue);
    pr = (probereq_t *) dequeue(queue);
    pthread_mutex_unlock(&mutex_queue);
    sem_post(&queue_full);

    // look for vendor string in manuf
    int indx = lookup_oui(pr->mac, ouidb, ouidb_size);
    if (indx >= 0) {
      if (ouidb[indx].long_oui) {
        pr->vendor = strdup(ouidb[indx].long_oui);
      } else {
        pr->vendor = strdup(ouidb[indx].short_oui);
      }
    } else {
      pr->vendor = strdup("UNKNOWN");
    }
    // check if mac is not in ignored list
    uint64_t *res = NULL;
    if (ignored != NULL) {
      char *tmp = str_replace(pr->mac, ":", "");
      uint64_t mac_number = strtoll(tmp, NULL, 16);
      free(tmp);
      res = bsearch(&mac_number, ignored, ignored_count, sizeof(uint64_t), cmp_uint64_t);
    }
    if (res == NULL) {
      insert_probereq(*pr, db, mac_pk_cache, ssid_pk_cache);
      if (option_stdout) {
        char *pr_str = probereq_to_str(*pr);
        printf("%s\n", pr_str);
        free(pr_str);
      }
    }
    free_probereq(pr);
    if (option_stdout) {
      fflush(stdout);
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - start_ts_cache.tv_sec >= DB_CACHE_TIME) {
      // commit to db
      commit_txn(db);
      begin_txn(db);
      start_ts_cache = now;
    }
  }

  lruc_free(mac_pk_cache);
  lruc_free(ssid_pk_cache);

  return NULL;
}
