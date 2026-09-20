#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#include "radiotap_iter.h"
#include "parsers.h"
#include "logger_thread.h"
#include "base64.h"
#include "config.h"

int8_t parse_radiotap_header(const uint8_t * packet, uint16_t * freq, int8_t * rssi)
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
  // iterate through radiotap fields and look for frequency and rssi
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

void parse_probereq_frame(const uint8_t *packet, uint32_t packet_len,
  int8_t offset, char **mac, uint8_t **ssid, uint8_t *ssid_len)
{
  *mac = malloc(18 * sizeof(char));
  // parse the probe request frame to look for mac and Information Element we need (ssid)
  // SA
  const uint8_t *sa_addr = packet + offset + 2 + 2 + 6;   // FC + duration + DA
  sprintf(*mac, "%02x:%02x:%02x:%02x:%02x:%02x", sa_addr[0],
    sa_addr[1], sa_addr[2], sa_addr[3], sa_addr[4], sa_addr[5]);

  *ssid = NULL;
  uint8_t *ie = (uint8_t *)sa_addr + 6 + 6 + 2 ; // + SA + BSSID + Seqctl
  uint8_t ie_len = *(ie + 1);
  *ssid_len = 0;

  // iterate over Information Element to look for SSID
  while (ie < packet + packet_len) {
    if ((ie + ie_len + 2 <= packet + packet_len)) {     // just double check that this is an IE with length inside packet
      if (*ie == 0) { // SSID aka IE with id 0
        *ssid_len = *(ie + 1);
        if (*ssid_len > 32) {
          fprintf(stderr, "Warning: detected SSID greater than 32 bytes. Cutting it to 32 bytes.");
          *ssid_len = 32;
        }
        *ssid = malloc((*ssid_len) * sizeof(uint8_t));        // AP name
        memcpy(*ssid, ie+2, *ssid_len);
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

  strftime(datetime, 20, "%Y-%m-%d %H:%M:%S", localtime(&pr.tv.tv_sec));

  char *first = strndup(pr.mac, 2);
  bool is_laa = strtoll(first, NULL, 16) & 0x2;
  free(first);

  // cut or pad vendor string
  if (strlen(pr.vendor) >= MAX_VENDOR_LENGTH) {
      strncpy(vendor, pr.vendor, MAX_VENDOR_LENGTH-1);
      for (int i=MAX_VENDOR_LENGTH-3; i<MAX_VENDOR_LENGTH; i++) {
        vendor[i] = '.';
      }
      vendor[MAX_VENDOR_LENGTH] = '\0';
  } else {
    strcpy(vendor, pr.vendor);
    for (int i=strlen(pr.vendor); i<MAX_VENDOR_LENGTH; i++) {
      vendor[i] = ' ';
    }
    vendor[MAX_VENDOR_LENGTH] = '\0';
  }
  // is ssid a valid utf-8 string
  memcpy(tmp, pr.ssid, pr.ssid_len);
  tmp[pr.ssid_len] = '\0';

  if (!is_utf8(tmp)) {
    // base64 encode the ssid
    size_t length;
    char * b64tmp = base64_encode((unsigned char *)tmp, pr.ssid_len, &length);
    snprint(tmp, 1024, "b64_%s", b64tmp);
    free(b64tmp);
  }
  // cut or pad ssid string
  if (strlen(tmp) >= MAX_SSID_LENGTH) {
      strncpy(ssid, tmp, MAX_SSID_LENGTH);
      for (int i=MAX_SSID_LENGTH-3; i<MAX_SSID_LENGTH; i++) {
        ssid[i] = '.';
      }
      ssid[MAX_SSID_LENGTH] = '\0';
  } else {
    strcpy(ssid, tmp);
    for (int i=strlen(tmp); i<MAX_SSID_LENGTH; i++) {
      ssid[i] = ' ';
    }
    ssid[MAX_SSID_LENGTH] = '\0';
  }

  sprintf(rssi, "%-3d", pr.rssi);

  tmp[0] = '\0';
  strcat(tmp, datetime);
  strcat(tmp, "\t");
  strcat(tmp, pr.mac);
  if (is_laa) {
    strcat(tmp, " (LAA)");
  }
  strcat(tmp, "\t");
  strcat(tmp, vendor);
  strcat(tmp, "\t");
  strcat(tmp, ssid);
  strcat(tmp, "\t");
  strcat(tmp, rssi);

  pr_str = strdup(tmp);

  return pr_str;
}

// from https://stackoverflow.com/a/1031773/283067
bool is_utf8(const char * string)
{
  if (!string) {
    return 0;
  }

  const unsigned char * bytes = (const unsigned char *)string;
  while(*bytes) {
    if ( (// ASCII
      // use bytes[0] <= 0x7F to allow ASCII control characters
      bytes[0] == 0x09 ||
      bytes[0] == 0x0A ||
      bytes[0] == 0x0D ||
      (0x20 <= bytes[0] && bytes[0] <= 0x7E)
    ) ) {
      bytes += 1;
      continue;
    }

    if( (// non-overlong 2-byte
      (0xC2 <= bytes[0] && bytes[0] <= 0xDF) &&
      (0x80 <= bytes[1] && bytes[1] <= 0xBF)
    ) ) {
      bytes += 2;
      continue;
    }

    if( (// excluding overlongs
      bytes[0] == 0xE0 &&
      (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
      (0x80 <= bytes[2] && bytes[2] <= 0xBF)
    ) ||
    (// straight 3-byte
      ((0xE1 <= bytes[0] && bytes[0] <= 0xEC) ||
      bytes[0] == 0xEE ||
      bytes[0] == 0xEF) &&
      (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
      (0x80 <= bytes[2] && bytes[2] <= 0xBF)
    ) ||
    (// excluding surrogates
      bytes[0] == 0xED &&
      (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
      (0x80 <= bytes[2] && bytes[2] <= 0xBF)
    ) ) {
      bytes += 3;
      continue;
    }

    if( (// planes 1-3
      bytes[0] == 0xF0 &&
      (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
      (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
      (0x80 <= bytes[3] && bytes[3] <= 0xBF)
    ) ||
    (// planes 4-15
      (0xF1 <= bytes[0] && bytes[0] <= 0xF3) &&
      (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
      (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
      (0x80 <= bytes[3] && bytes[3] <= 0xBF)
    ) ||
    (// plane 16
      bytes[0] == 0xF4 &&
      (0x80 <= bytes[1] && bytes[1] <= 0x8F) &&
      (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
      (0x80 <= bytes[3] && bytes[3] <= 0xBF)
    ) ) {
      bytes += 4;
      continue;
    }

    return 0;
  }

  return 1;
}
