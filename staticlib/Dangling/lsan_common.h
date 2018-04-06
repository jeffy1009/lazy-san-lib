#ifndef LSAN_COMMON_H
#define LSAN_COMMON_H

#include <unistd.h>
#include "metapagetable.h"

#define REFCNT_INIT 0

#define LS_INFO_FREED 		0x1
#define LS_INFO_USE_ZDLPV	0x2
#define LS_INFO_USE_ZDAPV	0x6
#define LS_INFO_USE_MASK	0x6
#define LS_INFO_RCBELOWZERO 	0x10000

typedef struct ls_obj_info_t {
  int flags:16;
  unsigned long base:48;
#if defined(DEBUG_LS) || defined(DEBUG_LS_HIGH)
  unsigned int size;
  int refcnt;
#else
  long refcnt;
#endif
} ls_obj_info;

extern __thread bool malloc_flag;
extern __thread bool free_flag;

#endif /* LSAN_COMMON_H */
