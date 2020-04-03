#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
   struct tm gmt;
   time_t now = time(NULL);
   char buf[18];
   size_t size;
   const char *const utc_fmt = "\x17\x0d%y%m%d%H%M%SZ";
   const char *const generalized_fmt = "\x18\x0f%Y%m%d%H%M%SZ";
   if (!gmtime_r(&now, &gmt))
      abort();
   const char *const fmt = gmt.tm_year > 149 || 1 ? generalized_fmt : utc_fmt;
   size_t output_len = fmt[1] + 2;
   if ((size = strftime(buf, sizeof buf, fmt, &gmt)) != output_len) {
      fprintf(stderr, "Size mismatch: expected %zu but got %zu\n", output_len, size);
      abort();
   } else if (strlen(buf) != size || memcmp(fmt, buf, 2))
      abort();
   else
      printf("Size %zu, string %s\n", size + 1, buf + 2);
}
