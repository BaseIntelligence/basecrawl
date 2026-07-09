#include "basecrawl.h"

#include <stdio.h>

int main(int argc, char **argv) {
  const char *url = argc > 1 ? argv[1] : "https://example.com";
  const char *format = argc > 2 ? argv[2] : "rawHtml";
  char options[128];
  int written = snprintf(
      options,
      sizeof(options),
      "{\"formats\":[\"%s\"],\"renderEnabled\":false}",
      format);
  if (written < 0 || written >= (int)sizeof(options)) {
    fputs("failed to encode C SDK options\n", stderr);
    return 2;
  }

  char *proof = basecrawl_scrape_json(url, options);
  if (proof == NULL) {
    const char *error = basecrawl_last_error_json();
    fputs(error == NULL ? "{\"error\":{\"kind\":\"unknown\"}}\n" : error, stderr);
    fputc('\n', stderr);
    return 1;
  }

  puts(proof);
  basecrawl_free_string(proof);
  return 0;
}
