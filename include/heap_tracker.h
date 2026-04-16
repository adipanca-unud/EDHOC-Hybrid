/* heap_tracker.h — Thread-local peak heap usage tracker.
 *
 * Uses GNU ld --wrap to intercept malloc/free/calloc/realloc.
 * Call heap_tracker_reset() before the code section you want to measure,
 * then heap_tracker_get_peak() to read peak heap bytes for the calling thread.
 */
#ifndef HEAP_TRACKER_H
#define HEAP_TRACKER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reset the per-thread current and peak counters to zero. */
void heap_tracker_reset(void);

/* Return peak heap bytes allocated (concurrent) since last reset. */
size_t heap_tracker_get_peak(void);

/* Return current heap bytes allocated. */
size_t heap_tracker_get_current(void);

#ifdef __cplusplus
}
#endif

#endif /* HEAP_TRACKER_H */
