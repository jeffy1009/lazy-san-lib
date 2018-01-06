#ifndef LSAN_COMMON_H
#define LSAN_COMMON_H

#define REFCNT_INIT 0

#define LS_INFO_FREED 		0x1
#define LS_INFO_RCBELOWZERO 	0x10000

typedef struct ls_obj_info_t {
  char *base, *end;
  unsigned long size;
  int refcnt;
  int flags;
} ls_obj_info;

#endif /* LSAN_COMMON_H */
