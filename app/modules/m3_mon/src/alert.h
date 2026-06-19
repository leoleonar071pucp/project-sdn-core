#ifndef ALERT_H
#define ALERT_H

#include <stdint.h>
#include "alert_schema.h"

#ifdef __cplusplus
extern "C" {
#endif

int alert_init(uint32_t ring_size);
int alert_enqueue(const alert_t *alert);
void *alert_publisher_loop(void *arg);

#ifdef __cplusplus
}
#endif

#endif // ALERT_H
