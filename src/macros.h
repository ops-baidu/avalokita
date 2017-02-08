/*
 * macros.h
 *
 *  Created on: Jul 31, 2014
 *      Author: lfw
 */

#ifndef MACROS_H_
#define MACROS_H_

#ifdef __RELATIVE_PATH__
#define __SOURCE__ __RELATIVE_PATH__
#else
#define __SOURCE__ __FILE__
#endif

#include <stddef.h>

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

// need gcc to compile this.
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <execinfo.h>

#define INFO(fmt, args...) \
do \
{ \
    fprintf(stdout, fmt " \e[36m[%s:%d %s()]\033[0m\n", \
            ##args, __SOURCE__, __LINE__, __FUNCTION__); \
} \
while (0)

#define ERROR(fmt, args...) \
do \
{ \
    fprintf(stderr, "\e[33mERROR: " fmt "\033[0m \e[36m[%s:%d %s()]\033[0m\n", \
            ##args, __SOURCE__, __LINE__, __FUNCTION__); \
} \
while (0)

#define ERROR_LIBC_ERRNO(no, fmt, args...) \
    ERROR("libc " fmt ": %s", ##args, strerror(no))

#define ERROR_LIBC(fmt, args...) ERROR_LIBC_ERRNO(errno, fmt, ##args)

#define PRINT_BACK_TRACE() \
do \
{ \
    int i = 0, ret = -1; void * back_trace_buffer[64]; \
    ret = backtrace(back_trace_buffer, 64); \
    fprintf(stderr, "BACK TRACE BEGIN:\n"); \
    for (i = 0; i < ret; i++) fprintf(stderr, "%p\n", back_trace_buffer[i]); \
    fprintf(stderr, "BACK TRACE END:\n"); \
} \
while (0)

#endif //MACROS_H_
