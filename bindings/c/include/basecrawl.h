#ifndef BASECRAWL_H
#define BASECRAWL_H

#ifdef __cplusplus
extern "C" {
#endif

#define BASECRAWL_VERSION "0.1.0"

const char *basecrawl_version(void);
char *basecrawl_scrape_json(const char *url, const char *options_json);
const char *basecrawl_last_error_json(void);
void basecrawl_free_string(char *value);

#ifdef __cplusplus
}
#endif

#endif
