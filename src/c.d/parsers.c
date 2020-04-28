#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#include "radiotap_iter.h"
#include "parsers.h"
#include "logger_thread.h"

#define MAX_VENDOR_LENGTH 25
#define MAX_SSID_LENGTH 15

int8_t parse_radiotap_header(const u_char * packet, uint16_t * freq, int8_t * rssi)
{
  // parse radiotap header to get frequency and rssi
  // returns radiotap header size or -1 on error
  struct ieee80211_radiotap_header *rtaphdr;
  rtaphdr = (struct ieee80211_radiotap_header *) (packet);
  int8_t offset = (int8_t) rtaphdr->it_len;

  struct ieee80211_radiotap_iterator iter;
  //uint16_t flags = 0;
  int8_t r;

  static const struct radiotap_align_size align_size_000000_00[] = {
    [0] = {.align = 1,.size = 4, },
    [52] = {.align = 1,.size = 4, },
  };

  static const struct ieee80211_radiotap_namespace vns_array[] = {
    {
     .oui = 0x000000,
     .subns = 0,
     .n_bits = sizeof(align_size_000000_00),
     .align_size = align_size_000000_00,
      },
  };

  static const struct ieee80211_radiotap_vendor_namespaces vns = {
    .ns = vns_array,
    .n_ns = sizeof(vns_array) / sizeof(vns_array[0]),
  };

  int err =
      ieee80211_radiotap_iterator_init(&iter, rtaphdr, rtaphdr->it_len,
                                       &vns);
  if (err) {
    printf("Error: malformed radiotap header (init returned %d)\n", err);
    return -1;
  }

  *freq = 0;
  *rssi = 0;
  // iterate through radiotap filed and look for frequency and rssi
  while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
    if (iter.this_arg_index == IEEE80211_RADIOTAP_CHANNEL) {
      assert(iter.this_arg_size == 4);  // XXX: why ?
      *freq = iter.this_arg[0] + (iter.this_arg[1] << 8);
      //flags = iter.this_arg[2] + (iter.this_arg[3] << 8);
    }
    if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
      r = (int8_t) * iter.this_arg;
      if (r != 0)
        *rssi = r;              // XXX: why do we get multiple dBm_antSignal with 0 value after the first one ?
    }
    if (*freq != 0 && *rssi != 0)
      break;
  }
  return offset;
}

void parse_probereq_frame(const u_char *packet, uint32_t header_len,
  int8_t offset, char **mac, char **ssid, uint8_t *ssid_len)
{
  *mac = malloc(18 * sizeof(char));
  // parse the probe request frame to look for mac and Information Element we need (ssid)
  // SA
  const u_char *sa_addr = packet + offset + 2 + 2 + 6;   // FC + duration + DA
  sprintf(*mac, "%02X:%02X:%02X:%02X:%02X:%02X", sa_addr[0],
    sa_addr[1], sa_addr[2], sa_addr[3], sa_addr[4], sa_addr[5]);

  *ssid = NULL;
  u_char *ie = (u_char *)sa_addr + 6 + 6 + 2 ; // + SA + BSSID + Seqctl
  uint8_t ie_len = *(ie + 1);
  *ssid_len = 0;

  // iterate over Information Element to look for SSID
  while (ie < packet + header_len) {
    if ((ie + ie_len + 2 < packet + header_len)) {     // just double check that this is an IE with length inside packet
      if (*ie == 0) { // SSID aka IE with id 0
        *ssid_len = *(ie + 1);
        *ssid = malloc((*ssid_len + 1) * sizeof(char));        // AP name
        snprintf(*ssid, *ssid_len+1, "%s", ie + 2);
        break;
      }
    }
    ie = ie + ie_len + 2;
    ie_len = *(ie + 1);
  }
  return;
}

char *probereq_to_str(probereq_t pr)
{
  char tmp[1024], vendor[MAX_VENDOR_LENGTH+1], ssid[MAX_SSID_LENGTH+1], datetime[20], rssi[5];
  char *pr_str;

  strftime(datetime, 20, "%Y-%m-%d %H:%M:%S", localtime(&pr.ts));

  // cut or pad vendor string
  if (strlen(pr.vendor) >= MAX_VENDOR_LENGTH) {
      strncpy(vendor, pr.vendor, MAX_VENDOR_LENGTH-1);
      for (int i=MAX_VENDOR_LENGTH-3; i<MAX_VENDOR_LENGTH; i++) {
        vendor[i] = '.';
      }
      vendor[MAX_VENDOR_LENGTH] = '\0';
  } else {
    strncpy(vendor, pr.vendor, strlen(pr.vendor));
    for (int i=strlen(pr.vendor); i<MAX_VENDOR_LENGTH; i++) {
      vendor[i] = ' ';
    }
    vendor[MAX_VENDOR_LENGTH] = '\0';
  }
  // cut or pad ssid string
  if (strlen(pr.ssid) >= MAX_SSID_LENGTH) {
      strncpy(ssid, pr.ssid, MAX_SSID_LENGTH-1);
      for (int i=MAX_SSID_LENGTH-3; i<MAX_SSID_LENGTH; i++) {
        ssid[i] = '.';
      }
      ssid[MAX_SSID_LENGTH] = '\0';
  } else {
    strncpy(ssid, pr.ssid, strlen(pr.ssid));
    for (int i=strlen(pr.ssid); i<MAX_SSID_LENGTH; i++) {
      ssid[i] = ' ';
    }
    ssid[MAX_SSID_LENGTH] = '\0';
  }

  sprintf(rssi, "%-3d", pr.rssi);

  tmp[0] = '\0';
  strcat(tmp, datetime);
  strcat(tmp, "\t");
  strcat(tmp, pr.mac);
  strcat(tmp, "\t");
  strcat(tmp, vendor);
  strcat(tmp, "\t");
  strcat(tmp, ssid);
  strcat(tmp, "\t");
  strcat(tmp, rssi);

  pr_str = malloc(strlen(tmp)+1);
  strncpy(pr_str, tmp, strlen(tmp)+1);

  return pr_str;
}

// https://stackoverflow.com/a/779960/283067
// You must free the result if result is non-NULL.
char *str_replace(const char *orig, const char *rep, const char *with) {
    char *result;
    char *ins;
    char *tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL;
    if (!with)
        with = "";
    len_with = strlen(with);

    #pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    ins = (char *)orig;
    #pragma GCC diagnostic ignored "-Wparentheses"
    for (count = 0; tmp = strstr(ins, rep); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}
