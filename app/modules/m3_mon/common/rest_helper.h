#ifndef REST_HELPER_H
#define REST_HELPER_H

#include <curl/curl.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int send_alert(const char *json_str, const char *endpoint)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    CURLcode res;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return res == CURLE_OK ? 0 : -1;
}

#ifdef __cplusplus
}
#endif

#endif // REST_HELPER_H
