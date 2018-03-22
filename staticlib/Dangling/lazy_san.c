#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>
#include "lsan_common.h"
#include "../../gperftools-metalloc/src/base/linux_syscall_support.h"

#include "metadata.h"

#ifdef DEBUG_LS
#define DEBUG(x) do { x; } while (0)
#else
#define DEBUG(x) do { ; } while (0)
#endif

#define GLOBAL_PTRLOG_BASE 0x408000000000  /* next to metalloc pagetable */
#define GLOBAL_PTRLOG_SIZE 0x020000000000  /* 2TB */
#define GLOBAL_PTRLOG_END (GLOBAL_PTRLOG_BASE+GLOBAL_PTRLOG_SIZE)
/* TODO: get exact heap end instead of this fixed value */
#define HEAP_END_ADDR 0x000400000000 /* 16GB */

static unsigned long *global_ptrlog;

__attribute__ ((visibility("hidden"))) extern char _end;

/* prototypes */

static void ls_inc_refcnt(char *p, char *dest, int setbit);
static void ls_dec_refcnt(char *p, char *dummy);
void ls_incdec_refcnt_noinc(char *dest);
void ls_incdec_refcnt(char *p, char *dest);
static void ls_copy_ptrlog(char *d, char *s, unsigned long size);
void ls_incdec_copy_ptrlog(char *d, char *s, unsigned long size);
void ls_incdec_move_ptrlog(char *d, char *s, unsigned long size);
void ls_check_ptrlog(char *p, unsigned long size);
static void ls_inc_ptrlog(char *d, char *s, unsigned long size, int setbit);
static void ls_dec_ptrlog_int(char *p, char *end, int clearbit);
void ls_dec_ptrlog(char *p, unsigned long size);

void _ZdlPv(void *);
void _ZdaPv(void *);

static void alloc_common(char *base, unsigned long size);
static void free_common(char *base, unsigned long source);
static void realloc_hook(char *old_ptr, char *new_ptr, unsigned long size);

#define LS_META_SPACE_MAX_SIZE 0x08000000 /* 128MB */

static ls_obj_info *ls_meta_space;
static unsigned long cur_meta_idx = 0;
static unsigned long meta_idx_limit = (1UL<<12)/sizeof(ls_obj_info);
static unsigned long num_obj_info = 0;
static const unsigned long meta_idx_max = LS_META_SPACE_MAX_SIZE/sizeof(ls_obj_info);

static ls_obj_info *alloc_obj_info(char *base, unsigned long size) {
  ls_obj_info *cur;
  do {
    cur = ls_meta_space + cur_meta_idx;
    if (++cur_meta_idx >= meta_idx_limit) cur_meta_idx = 0;
  } while (cur->base != 0);

  metaset_8((unsigned long)base, size, (unsigned long)cur);
  ++num_obj_info;
  /* keep meta space large enough to have sufficient vacant slots */
  if ((num_obj_info+num_obj_info/4) > meta_idx_limit) {
    DEBUG(if ((num_obj_info+num_obj_info/4) > meta_idx_max)
            fprintf(stderr, "[lazy-san] num obj info reached the limit!\n"));
    meta_idx_limit *= 2;
  }
  cur->base = base;
  cur->size = size;
  cur->refcnt = REFCNT_INIT;
  cur->flags = 0;
  return cur;
}

static ls_obj_info *get_obj_info(char *p) {
  if (p > &_end && p < (char*)HEAP_END_ADDR)
    return (ls_obj_info*)metaget_8((unsigned long)p);
  return NULL;
}

size_t tc_malloc_size(void *);

static void delete_obj_info(ls_obj_info *info) {
  metaset_8((unsigned long)info->base, tc_malloc_size(info->base), 0);
  info->base = 0;
  --num_obj_info;
}

#ifdef DEBUG_LS
static unsigned long alloc_max = 0, alloc_cur = 0, alloc_tot = 0;
static unsigned long num_ptrs = 0;
static unsigned long quarantine_size = 0, quarantine_max = 0, quarantine_max_mb = 0;
static unsigned long num_incdec = 0, same_ldst_cnt = 0;
#endif

#ifdef DEBUG_LS
void atexit_hook() {
  ls_dec_ptrlog_int(0, &_end, 0);

  fprintf(stderr, "PROGRAM TERMINATED!\n");
  fprintf(stderr, "max alloc: %ld, cur alloc: %ld, tot alloc: %ld\n",
         alloc_max, alloc_cur, alloc_tot);
  fprintf(stderr, "num ptrs: %ld\n", num_ptrs);
  fprintf(stderr, "quarantine max: %ld B, cur: %ld B\n", quarantine_max, quarantine_size);
  fprintf(stderr, "num incdec: %ld, same ldst cnt: %ld\n", num_incdec, same_ldst_cnt);
}
#endif

void __attribute__((visibility ("hidden"), constructor(-1))) init_lazysan() {
  static int initialized = 0;

  if (initialized) return;
  initialized = 1;

  DEBUG(if (atexit(atexit_hook))
          fprintf(stderr, "atexit failed!\n"));

  /* sys_mmap from gperftools/src/base/linux_syscall_support.h
     gives much better performance and memory usage */
  global_ptrlog = sys_mmap((void*)GLOBAL_PTRLOG_BASE, GLOBAL_PTRLOG_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE,
                           -1, 0);
  if (global_ptrlog == (void*)-1) {
     /* strangely, perror() segfaults */
    fprintf(stderr, "[lazy-san] global_ptrlog mmap failed: errno %d\n", errno);
    exit(0);
  }
  fprintf(stderr, "[lazy-san] global_ptrlog mmap'ed @ 0x%lx\n",
         (unsigned long)global_ptrlog);

  ls_meta_space = sys_mmap((void*)GLOBAL_PTRLOG_END, LS_META_SPACE_MAX_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE,
                           -1, 0);
  if (ls_meta_space == (void*)-1) {
     /* strangely, perror() segfaults */
    fprintf(stderr, "[lazy-san] ls_meta_space mmap failed: errno %d\n", errno);
    exit(0);
  }
  fprintf(stderr, "[lazy-san] ls_meta_space mmap'ed @ 0x%lx\n",
         (unsigned long)ls_meta_space);

  metalloc_malloc_posthook = alloc_common;
  metalloc_realloc_posthook = realloc_hook;
  metalloc_free_prehook = free_common;
}

__attribute__((section(".preinit_array"),
               used)) void (*init_ls_preinit)(void) = init_lazysan;

/*****************************/
/**  Refcnt modification  ****/
/*****************************/

static inline void ls_free(char *p, ls_obj_info *info) {
  free_flag = 1;
  switch (info->flags & LS_INFO_USE_MASK) {
  case 0: free(p); break;
  case LS_INFO_USE_ZDLPV: _ZdlPv(p); break;
  case LS_INFO_USE_ZDAPV: _ZdaPv(p); break;
  }
}

/* p - written pointer value
   dest - store destination
   setbit - whether or not bit field should be set, should be constant-folded
   upon inlining */
static void ls_inc_refcnt(char *p, char *dest, int setbit) {
  ls_obj_info *info;
  unsigned long offset, widx, bidx;

  DEBUG(num_ptrs++);
  info = get_obj_info(p);

  if (info) {
    DEBUG(if ((info->flags & LS_INFO_FREED) && info->refcnt == REFCNT_INIT)
            fprintf(stderr, "[lazy-san] refcnt became alive again??\n"));
    atomic_fetch_add((atomic_int*)&info->refcnt, 1);

    if (setbit) {
      /* mark pointer type field */
      offset = (unsigned long)dest >> 3;
      widx = offset >> 6; /* word index */
      bidx = offset & 0x3F; /* bit index */
      atomic_fetch_or((atomic_ulong*)&global_ptrlog[widx], (1UL << bidx));
    }
  }
}

static void ls_dec_refcnt(char *p, char *dummy) {
  ls_obj_info *info;

  info = get_obj_info(p);
  if (info) { /* is heap node */
    DEBUG(if (info->refcnt<=REFCNT_INIT && !(info->flags & LS_INFO_RCBELOWZERO)) {
        info->flags |= LS_INFO_RCBELOWZERO;
        /* fprintf(stderr, "[lazy-san] refcnt <= 0???\n"); */
      });
    atomic_fetch_sub((atomic_int*)&info->refcnt, 1);
    if (info->refcnt<=0) {
      if (info->flags & LS_INFO_FREED) { /* marked to be freed */
        char *tmp = info->base;
        DEBUG(quarantine_size -= info->size);
        delete_obj_info(info);
        ls_free(tmp, info);
      }
      /* if not yet freed, the pointer is probably in some
         register. */
    }
  }
}

void __attribute__((noinline)) ls_incdec_refcnt_noinc(char *dest) {
  unsigned long offset, widx, bidx;
  unsigned long need_dec;
  unsigned long tmp_ptrlog_val;
  ls_obj_info *old_info;

  offset = (unsigned long)dest >> 3;
  widx = offset >> 6; /* word index */
  bidx = offset & 0x3F; /* bit index */
  tmp_ptrlog_val = global_ptrlog[widx];
  need_dec = (tmp_ptrlog_val & (1UL << bidx));

  if (!need_dec)
    return;

  atomic_fetch_and((atomic_ulong*)&global_ptrlog[widx], ~(1UL << bidx));
  DEBUG(num_incdec++);

  old_info = get_obj_info((char*)*(unsigned long*)(offset << 3));
  if (!old_info)
    return;

  DEBUG(if (old_info->refcnt<=REFCNT_INIT && !(old_info->flags & LS_INFO_RCBELOWZERO)) {
      old_info->flags |= LS_INFO_RCBELOWZERO;
      /* fprintf(stderr, "[lazy-san] refcnt <= 0???\n"); */
    });

  atomic_fetch_sub((atomic_int*)&old_info->refcnt, 1);
  if (old_info->refcnt<=0) {
    if (old_info->flags & LS_INFO_FREED) { /* marked to be freed */
      char *tmp = old_info->base;
      DEBUG(quarantine_size -= old_info->size);
      delete_obj_info(old_info);
      ls_free(tmp, old_info);
    }
    /* if not yet freed, the pointer is probably in some
       register. */
  }
}

// NOTE: we should increase refcnt before decreasing it..
// if it is decreased first, refcnt could become 0 and the quarantine cleared
// but if the pointer happens to point to the same object, refcnt will become
// one again..
void __attribute__((noinline)) ls_incdec_refcnt(char *p, char *dest) {
  ls_obj_info *info, *old_info;
  unsigned long offset, widx, bidx;
  unsigned long need_dec;
  unsigned long tmp_ptrlog_val;

  DEBUG(num_ptrs++);
  DEBUG(num_incdec++);

  offset = (unsigned long)dest >> 3;
  widx = offset >> 6; /* word index */
  bidx = offset & 0x3F; /* bit index */
  tmp_ptrlog_val = global_ptrlog[widx];

  need_dec = (tmp_ptrlog_val & (1UL << bidx));

  info = get_obj_info(p);
  if (!info && !need_dec)
    return;

  DEBUG(if (info && (info->flags & LS_INFO_FREED) && info->refcnt == REFCNT_INIT)
          fprintf(stderr, "[lazy-san] refcnt became alive again??\n"));

  if (need_dec) {
    old_info = get_obj_info((char*)(*(unsigned long*)(offset << 3)));
    if (info == old_info) {
      DEBUG(same_ldst_cnt++);
      return;
    }
    if (!info)
      atomic_fetch_and((atomic_ulong*)&global_ptrlog[widx], ~(1UL << bidx));
    else
      atomic_fetch_add((atomic_int*)&info->refcnt, 1);

    if (!old_info)
      return;

    DEBUG(if (old_info->refcnt<=REFCNT_INIT && !(old_info->flags & LS_INFO_RCBELOWZERO)) {
        old_info->flags |= LS_INFO_RCBELOWZERO;
        /* fprintf(stderr, "[lazy-san] refcnt <= 0???\n"); */
      });

    atomic_fetch_sub((atomic_int*)&old_info->refcnt, 1);
    if (old_info->refcnt<=0) {
      if (old_info->flags & LS_INFO_FREED) { /* marked to be freed */
        char *tmp = old_info->base;
        DEBUG(quarantine_size -= old_info->size);
        delete_obj_info(old_info);
        ls_free(tmp, old_info);
      }
      /* if not yet freed, the pointer is probably in some
         register. */
    }
  } else if (info) {
    atomic_fetch_or((atomic_ulong*)&global_ptrlog[widx], (1UL << bidx));
    atomic_fetch_add((atomic_int*)&info->refcnt, 1);
  }
}

static void ls_copy_ptrlog(char *d, char *s, unsigned long size) {
  unsigned long offset = (unsigned long)d >> 3;
  unsigned long s_offset = (unsigned long)s >> 3;
  unsigned long widx = offset >> 6;
  unsigned long s_widx = s_offset >> 6;
  unsigned long bidx = offset & 0x3F;
  unsigned long s_bidx = s_offset & 0x3F;
  unsigned long *pl = global_ptrlog + widx;
  unsigned long *s_pl = global_ptrlog + s_widx;

  unsigned long bitcnts = size >> 3;

  /* TODO: do this more efficiently */
  /* TODO: can we skip if size is not multiple of 8? */

  unsigned long cur = bidx;
  unsigned long s_cur = s_bidx;

  while (bitcnts--) {
    unsigned long s_curbit = 1UL << s_cur;
    unsigned long bitset = (*s_pl & s_curbit) ? 1 : 0;
    *pl = (*pl & ~(bitset << cur)) | (bitset << cur);
    cur = ((cur+1) & 0x3f);
    s_cur = ((s_cur+1) & 0x3f);
    if (cur == 0) pl++;
    if (s_cur == 0) s_pl++;
  }
}

/* corresponding to memcpy, d and s do not overlap */
void __attribute__((noinline)) ls_incdec_copy_ptrlog(char *d, char *s, unsigned long size) {
  /* TODO: do this more efficiently */
  /* TODO: can we skip if size is not multiple of 8? */

  if (s == d) /* very weird case found in gcc */
    return;

  ls_dec_ptrlog_int(d, d + size, 1);
  ls_inc_ptrlog(d, s, size, 1);
}

/* corresponding to memmove, d and s may overlap */
void __attribute__((noinline)) ls_incdec_move_ptrlog(char *d, char *s, unsigned long size) {
  unsigned long offset = (unsigned long)d >> 3;
  unsigned long s_offset = (unsigned long)s >> 3;
  unsigned long widx = offset >> 6;
  unsigned long s_widx = s_offset >> 6;
  unsigned long bidx = offset & 0x3F;
  unsigned long s_bidx = s_offset & 0x3F;
  unsigned long *pl = global_ptrlog + widx;
  unsigned long *s_pl = global_ptrlog + s_widx;

  unsigned long bitcnts = size >> 3;

  if (((d > s) && (d > (s+size)))
      || ((s > d) && (s > (d+size)))) {
    ls_incdec_copy_ptrlog(d, s, size);
    return;
  }

  ls_dec_ptrlog_int(d, d + size, 0);
  ls_inc_ptrlog(d, s, size, 0);

  unsigned long cur = bidx;
  unsigned long s_cur = s_bidx;

  while (bitcnts--) {
    unsigned long s_curbit = 1UL << s_cur;
    unsigned long bitset = (*s_pl & s_curbit) ? 1 : 0;
    *pl = (*pl & ~(bitset << cur)) | (bitset << cur);
    cur = ((cur+1) & 0x3f);
    s_cur = ((s_cur+1) & 0x3f);
    if (cur == 0) pl++;
    if (s_cur == 0) s_pl++;
  }
}

/* Only used for debugging */
void __attribute__((noinline)) ls_check_ptrlog(char *p, unsigned long size) {
  char *end = p + size;
  unsigned long offset = (unsigned long)p >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);
  volatile int dummy; /* To make it easier to set breakpoints */

  if (widx == widx_e) {
    mask |= mask_e;
    if (*pl & ~mask)
      dummy = 0;
    return;
  }

  if (*pl++ & ~mask)
    dummy = 0;
  while (pl < pl_e) {
    if (*pl++ != 0)
      dummy = 0;
  }
  if (*pl & ~mask_e)
    dummy = 0;
}

static void ls_inc_ptrlog(char *d, char *s, unsigned long size, int setbit) {
  char *end = s + size;
  unsigned long offset = (unsigned long)s >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long mask_e = (-1L << bidx_e);
  unsigned long *sw = (unsigned long *)s, *dw = (unsigned long *)d;
  unsigned long pl_val;

  if (widx == widx_e) {
    pl_val = (*pl & ~mask_e) >> bidx;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      ls_inc_refcnt((char*)*(sw+tmp), (char*)(dw+tmp), setbit);
      pl_val &= (pl_val - 1);
    }
    return;
  }

  pl_val = *pl >> bidx;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_inc_refcnt((char*)*(sw+tmp), (char*)(dw+tmp), setbit);
    pl_val &= (pl_val - 1);
  }
  pl++, sw+=(64-bidx), dw+=(64-bidx);

  while (pl < pl_e) {
    pl_val = *pl;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      ls_inc_refcnt((char*)*(sw + tmp), (char*)(dw+tmp), setbit);
      pl_val &= (pl_val - 1);
    }
    pl++, sw+=64, dw+=64;
  }

  pl_val = *pl & ~mask_e;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_inc_refcnt((char*)*(sw + tmp), (char*)(dw+tmp), setbit);
    pl_val &= (pl_val - 1);
  }
}

static void ls_dec_ptrlog_int(char *p, char *end, int clearbit) {
  unsigned long offset = (unsigned long)p >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);
  unsigned long *pw = (unsigned long *)p;
  unsigned long pl_val;

  if (widx == widx_e) {
    pl_val = (*pl & ~mask_e) >> bidx;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      ls_dec_refcnt((char*)*(pw+tmp), (char*)(pw+tmp));
      pl_val &= (pl_val - 1);
    }
    if (clearbit) atomic_fetch_and((atomic_ulong*)pl, (mask | mask_e));
    return;
  }

  pl_val = *pl >> bidx;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_dec_refcnt((char*)*(pw+tmp), (char*)(pw+tmp));
    pl_val &= (pl_val - 1);
  }
  if (clearbit) atomic_fetch_and((atomic_ulong*)pl, mask);
  pl++, pw+=(64-bidx);

  while (pl < pl_e) {
    pl_val = *pl;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      ls_dec_refcnt((char*)*(pw + tmp), (char*)(pw+tmp));
      pl_val &= (pl_val - 1);
    }
    if (clearbit) *pl = 0; // clear
    pl++, pw+=64;
  }

  pl_val = *pl & ~mask_e;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_dec_refcnt((char*)*(pw + tmp), (char*)(pw+tmp));
    pl_val &= (pl_val - 1);
  }
  if (clearbit) atomic_fetch_and((atomic_ulong*)pl, mask_e);
}

void __attribute__((noinline)) ls_dec_ptrlog(char *p, unsigned long size) {
  ls_dec_ptrlog_int(p, p+size, 1);
  DEBUG(memset(p, 0, size));
}

void __attribute__((noinline)) ls_dec_ptrlog_addr(char *p, char *end) {
  assert(p && end && p < end);
  ls_dec_ptrlog_int(p, end, 1);
  // do not memset!
}

/********************/
/**  Hooks    *******/
/********************/

static void alloc_common(char *base, unsigned long size) {
#ifdef DEBUG_LS
  if (++alloc_cur > alloc_max)
    alloc_max = alloc_cur;

  ++alloc_tot;
  if (quarantine_size > quarantine_max) {
    unsigned long quarantine_mb_tmp;
    quarantine_max = quarantine_size;
    quarantine_mb_tmp = quarantine_max/1024/1024;
    if (quarantine_mb_tmp > quarantine_max_mb) {
      quarantine_max_mb = quarantine_mb_tmp;
      fprintf(stderr, "[lazy-san] quarantine_max = %ld MB\n", quarantine_max_mb);
    }
  }
#endif

  alloc_obj_info(base, size);
}

static void free_common(char *base, unsigned long source) {
  if (base == 0)
    return;

  DEBUG(--alloc_cur);

  ls_obj_info *info = get_obj_info(base);
  DEBUG(if (info->flags & LS_INFO_FREED)
          fprintf(stderr, "[lazy-san] double free??????\n"));

  switch (source) {
  case 1: {
    info->flags |= LS_INFO_USE_ZDLPV;
    break;
  }
  case 2: {
    if (info) {
      info->flags |= LS_INFO_USE_ZDAPV;
      break;
    }
    /* alloc'ed with new[0] */
    free_flag = 1;
    _ZdaPv(base);
    return;
  }
  }

  ls_dec_ptrlog(base, info->size);
  if (info->refcnt <= 0) {
    delete_obj_info(info);
    ls_free(base, info);
  } else {
    info->flags |= LS_INFO_FREED;
    DEBUG(quarantine_size += info->size);
  }
}

static void realloc_hook(char *old_ptr, char *new_ptr, unsigned long size) {
  ls_obj_info *info = get_obj_info(old_ptr);
  if (old_ptr != new_ptr) {
    ls_copy_ptrlog(new_ptr, old_ptr, info->size);
    free_common(old_ptr, 0);
  } else {
    info->size = size;
  }
}
