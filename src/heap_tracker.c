/* heap_tracker.c — Thread-local peak heap tracker via GNU ld --wrap.
 *
 * Intercepts malloc, free, calloc, realloc at link time.
 * Uses malloc_usable_size() (glibc) to determine actual block sizes
 * without modifying returned pointers — fully transparent to callers.
 *
 * Compile: gcc -c heap_tracker.c
 * Link:    gcc ... -Wl,--wrap=malloc,--wrap=free,--wrap=calloc,--wrap=realloc
 */

#define _GNU_SOURCE
#include "heap_tracker.h"
#include <malloc.h>   /* malloc_usable_size */
#include <stdint.h>
#include <string.h>

/* Real libc functions provided by the linker --wrap mechanism */
extern void *__real_malloc(size_t size);
extern void  __real_free(void *ptr);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void *__real_realloc(void *ptr, size_t size);

/* Per-thread counters */
static _Thread_local size_t tl_current = 0;
static _Thread_local size_t tl_peak    = 0;

void heap_tracker_reset(void)
{
	tl_current = 0;
	tl_peak    = 0;
}

size_t heap_tracker_get_peak(void)
{
	return tl_peak;
}

size_t heap_tracker_get_current(void)
{
	return tl_current;
}

/* ── Wrapped allocators ─────────────────────────────────────────────── */

void *__wrap_malloc(size_t size)
{
	void *ptr = __real_malloc(size);
	if (ptr) {
		size_t usable = malloc_usable_size(ptr);
		tl_current += usable;
		if (tl_current > tl_peak)
			tl_peak = tl_current;
	}
	return ptr;
}

void __wrap_free(void *ptr)
{
	if (ptr) {
		size_t usable = malloc_usable_size(ptr);
		if (tl_current >= usable)
			tl_current -= usable;
		else
			tl_current = 0;
	}
	__real_free(ptr);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
	void *ptr = __real_calloc(nmemb, size);
	if (ptr) {
		size_t usable = malloc_usable_size(ptr);
		tl_current += usable;
		if (tl_current > tl_peak)
			tl_peak = tl_current;
	}
	return ptr;
}

void *__wrap_realloc(void *old, size_t size)
{
	size_t old_usable = 0;
	if (old)
		old_usable = malloc_usable_size(old);

	void *ptr = __real_realloc(old, size);
	if (ptr) {
		size_t new_usable = malloc_usable_size(ptr);
		if (tl_current >= old_usable)
			tl_current -= old_usable;
		else
			tl_current = 0;
		tl_current += new_usable;
		if (tl_current > tl_peak)
			tl_peak = tl_current;
	}
	return ptr;
}
