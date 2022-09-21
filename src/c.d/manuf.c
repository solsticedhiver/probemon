#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manuf.h"

static inline char *str_strip(const char *s)
{
    char *ret;
    if (s[strlen(s)-1] == '\n') {
        ret = strndup(s, strlen(s)-1);
    } else {
      ret = strdup(s);
    }
    return ret;
}

// from https://stackoverflow.com/a/779960/283067
char *str_replace(const char *orig, const char *rep, const char *with)
{
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

    ins = (char *)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
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

void free_manuf_t(manuf_t *m)
{
  free(m->short_oui);
  free(m->long_oui);
  free(m->comment);
  free(m);
}

int cmp_manuf_t(const void *u, const void *v)
{
  uint64_t a = ((manuf_t *)u)->min;
  uint64_t b = ((manuf_t *)v)->min;
  if (a<b) return -1;
  if (a>b) return 1;
  //assert(a == b);
  return 0;
}

int parse_mac_field(char *mac, manuf_t *m)
{
  char *smac = str_strip(mac);
  char *tmp = str_replace(smac, "-", ":");
  free(smac);
  char *mr = str_replace(tmp, ":", "");
  free(tmp);
  if (strlen(mr) == 6) {
    char *min = malloc(13 * sizeof(char));
    strncpy(min, mr, 6);
    strcat(min, "000000");
    m->min = strtoll(min, NULL, 16);
    char *max = malloc(13 * sizeof(char));
    strncpy(max, mr, 6);
    strcat(max, "ffffff");
    m->max = strtoll(max, NULL, 16);
    free(min);
    free(max);
  } else if (strlen(mr) == 12) {
    m->min = strtoll(mr, NULL, 16);
    m->max = m->min;
  } else if (strlen(mr) == 15) {
    mr[12] = '\0';
    char *tmp = strndup(mr, 11);
    m->min = strtoll(tmp, NULL, 16);
    free(tmp);
    tmp = strndup(mr+13, 2);
    int mask = (int)strtol(tmp, NULL, 10);
    free(tmp);
    uint64_t t = 0;
    for (int i=0; i<(48-mask)/4; i++) {
      t += 0xf << i;
    }
    m->max = m->min+t;
  } else {
    // we failed !
    //printf("%s\n", mr);
  }
  free(mr);

  return 0;
}

manuf_t *parse_manuf_file(const char*path, size_t *ouidb_size)
{
  FILE *manuf;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  manuf = fopen(path, "r");
  if (manuf == NULL) {
    return NULL;
  }

  *ouidb_size = 30*1024;
  int count = 0;
  manuf_t *ouidb = malloc(*ouidb_size * sizeof(manuf_t));

  while ((read = getline(&line, &len, manuf)) != -1) {
    if (line[0] == '#' || strlen(line) == 1) {
      continue;
    }
    char *token, *str = line;
    int indx = 0;
    if (count == *ouidb_size) {
      *ouidb_size += 1;
      ouidb = realloc(ouidb, *ouidb_size * sizeof(manuf_t));
    }
    ouidb[count].short_oui = NULL;
    ouidb[count].long_oui = NULL;
    ouidb[count].comment = NULL;
    while ((token = strsep(&str, "\t"))) {
      if (indx == 0) {
        parse_mac_field(token, &ouidb[count]);
      } else if (indx == 1) {
        char *stoken = str_strip(token);
        ouidb[count].short_oui = stoken;
      } else if (indx == 2) {
        char *stoken = str_strip(token);
        ouidb[count].long_oui = stoken;
      } else if (indx == 3) {
        char *stoken = str_strip(token);
        ouidb[count].comment = stoken;
      }
      indx++;
    }
    count++;
  }
  fclose(manuf);

  qsort(ouidb, *ouidb_size, sizeof(manuf_t), cmp_manuf_t);

  if (line) {
    free(line);
  }

  return ouidb;
}

int lookup_oui(char *mac, manuf_t *ouidb, size_t ouidb_size)
{
  char *tmp = str_replace(mac, ":", "");
  uint64_t mac_number = strtoll(tmp, NULL, 16);
  free(tmp);

  int count = 0;
  uint64_t val = ouidb[count].max;

  while ((count < ouidb_size) && mac_number > val) {
    count++;
    val = ouidb[count].max;
  }

  if (count == ouidb_size) {
    return -1;
  }
  if (mac_number > ouidb[count].min) {
    return count;
  } else {
    return -1;
  }
}

/*
int main(void)
{
  size_t ouidb_size;
  manuf_t *ouidb = parse_manuf_file("../manuf", &ouidb_size);

  int count = lookup_oui("da:a1:19:ac:b7:cc", ouidb, ouidb_size);
  if (count >= 0) {
    printf("%s %s\n", ouidb[count].short_oui, ouidb[count].long_oui);
  }

  size_t mu = sizeof(manuf_t) * ouidb_size;
  for (int i=0; i<ouidb_size; i++  ) {
    mu += strlen(ouidb[i].short_oui);
    if (ouidb[i].long_oui) mu += strlen(ouidb[i].long_oui);
    if (ouidb[i].comment) mu += strlen(ouidb[i].comment);
    free(ouidb[i].short_oui);
    free(ouidb[i].long_oui);
    free(ouidb[i].comment);
  }
  free(ouidb);

  printf("Memory used by ouidb: %u\n", mu);

  return 0;
}
*/
