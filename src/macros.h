/*
 * macros.h
 *
 *  Created on: Jul 31, 2014
 *      Author: lfw
 */

#ifndef MACROS_H_
#define MACROS_H_

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <execinfo.h>
#include <stddef.h>

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

// need gcc to compile this.
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define ERROR(fmt, args...) \
do \
{ \
    fprintf(stderr, "\033[33m[%s:%d %s()] ERROR: " fmt "\033[0m\n", __FILE__, __LINE__, \
            __FUNCTION__, ##args); \
} \
while (0)

#define ERROR_LIBC(fmt, args...) \
do \
{ \
    fprintf(stderr, "\033[33m[%s:%d %s()] ERROR: " fmt ": %s\033[0m\n", __FILE__, __LINE__, \
            __FUNCTION__, ##args, strerror(errno)); \
} \
while (0)

#define INFO(fmt, args...) \
do \
{ \
    fprintf(stdout, "[%s:%d %s()] " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##args); \
} \
while (0)

#define PRINT_BACK_TRACE() \
do \
{ \
    int i = 0, ret = -1; void * back_trace_buffer[64]; \
    ret = backtrace(back_trace_buffer, 64); \
    fprintf(stderr, "BACK TRACE:\n"); \
    for (i = 0; i < ret; i++) fprintf(stderr, "%p\n", back_trace_buffer[i]); \
} \
while (0)

#endif /* LOG_MACROS_H_ */
