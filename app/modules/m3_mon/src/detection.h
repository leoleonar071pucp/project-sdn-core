#ifndef DETECTION_H
#define DETECTION_H

#include <stdint.h>
#include "alert_schema.h"

#ifdef __cplusplus
extern "C" {
#endif

int detection_init(void);
void *detection_loop(void *arg);
void detection_volumetric(void);
void detection_scan(void);
int detection_enqueue_alert(const alert_t *alert);

#ifdef __cplusplus
}
#endif

#endif // DETECTION_H
