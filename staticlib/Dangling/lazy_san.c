#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>
#include "lsan_common.h"
#include "../../gperftools-metalloc/src/base/linux_syscall_support.h"

#ifdef USE_RBTREE
#include "red_black_tree.h"
#else
#include "metadata.h"
#endif

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

#ifdef USE_RBTREE

rb_red_blk_tree *rb_root = NULL;

static ls_obj_info *alloc_obj_info(char *base, unsigned long size) {
  return &RBTreeInsert(rb_root, base, size)->info;
}

static ls_obj_info *get_obj_info(char *p) {
  rb_red_blk_node *n = RBExactQuery(rb_root, p);
  if (n)
    return &n->info;
  return NULL;
}

static void delete_obj_info(ls_obj_info *info) {
  RBDelete(rb_root, RBExactQuery(rb_root, info->base));
}

#else /* !USE_RBTREE */

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

static void delete_obj_info(ls_obj_info *info) {
  metaset_8((unsigned long)info->base, tc_malloc_size(info->base), 0);
  info->base = 0;
  --num_obj_info;
}

#endif

#ifdef DEBUG_LS
static unsigned long alloc_max = 0, alloc_cur = 0, alloc_tot = 0;
static unsigned long num_ptrs = 0;
static unsigned long quarantine_size = 0, quarantine_max = 0, quarantine_max_mb = 0;
static unsigned long num_incdec = 0, same_ldst_cnt = 0;
#endif

static void ls_dec_ptrlog_int(char *p, char *end);

#ifdef DEBUG_LS
void atexit_hook() {
  ls_dec_ptrlog_int(0, (unsigned long)&_end);

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

#ifndef USE_RBTREE
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
#else
  rb_root = RBTreeCreate();
#endif
}

__attribute__((section(".preinit_array"),
               used)) void (*init_ls_preinit)(void) = init_lazysan;

/*****************************/
/**  Refcnt modification  ****/
/*****************************/

/* prototypes */
void ls_inc_refcnt(char *p, char *dest);
void ls_dec_refcnt(char *p, char *dummy);
void ls_incdec_refcnt_noinc(char *dest);
void ls_incdec_refcnt(char *p, char *dest);
void ls_clear_ptrlog(char *p, unsigned long size);
void ls_copy_ptrlog(char *d, char *s, unsigned long size);
void ls_incdec_copy_ptrlog(char *d, char *s, unsigned long size);
void ls_incdec_move_ptrlog(char *d, char *s, unsigned long size);
void ls_check_ptrlog(char *p, unsigned long size);
void ls_inc_ptrlog(char *d, char *s, unsigned long size);
void ls_dec_ptrlog(char *p, unsigned long size);
void ls_dec_clear_ptrlog(char *p, unsigned long size);

#ifndef CPLUSPLUS
static inline void ls_free(char *p, ls_obj_info *info) { free(p); }
#else
static inline void ls_free(char *p, ls_obj_info *info) {
  switch (info->flags & LS_INFO_USE_MASK) {
  case 0: free(p); break;
  case LS_INFO_USE_ZDLPV: _ZdlPv(p); break;
  case LS_INFO_USE_ZDAPV: _ZdaPv(p); break;
  }
}
#endif

/* p - written pointer value
   dest - store destination */
void ls_inc_refcnt(char *p, char *dest) {
  ls_obj_info *info;
  unsigned long offset, widx, bidx;

  DEBUG(num_ptrs++);
  info = get_obj_info(p);

  if (info) {
    DEBUG(if ((info->flags & LS_INFO_FREED) && info->refcnt == REFCNT_INIT)
            fprintf(stderr, "[lazy-san] refcnt became alive again??\n"));
    ++info->refcnt;

    /* mark pointer type field */
    offset = (unsigned long)dest >> 3;
    widx = offset >> 6; /* word index */
    bidx = offset & 0x3F; /* bit index */
    global_ptrlog[widx] |= (1UL << bidx);
  }
}

void ls_dec_refcnt(char *p, char *dummy) {
  ls_obj_info *info;

  info = get_obj_info(p);
  if (info) { /* is heap node */
    DEBUG(if (info->refcnt<=REFCNT_INIT && !(info->flags & LS_INFO_RCBELOWZERO)) {
        info->flags |= LS_INFO_RCBELOWZERO;
        /* fprintf(stderr, "[lazy-san] refcnt <= 0???\n"); */
      });
    --info->refcnt;
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

  global_ptrlog[widx] = tmp_ptrlog_val & ~(1UL << bidx);
  DEBUG(num_incdec++);

  old_info = get_obj_info(*(unsigned long*)(offset << 3));
  if (!old_info)
    return;

  DEBUG(if (old_info->refcnt<=REFCNT_INIT && !(old_info->flags & LS_INFO_RCBELOWZERO)) {
      old_info->flags |= LS_INFO_RCBELOWZERO;
      /* fprintf(stderr, "[lazy-san] refcnt <= 0???\n"); */
    });

  --old_info->refcnt;
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
      global_ptrlog[widx] = tmp_ptrlog_val & ~(1UL << bidx);
    else
      ++info->refcnt;

    if (!old_info)
      return;

    DEBUG(if (old_info->refcnt<=REFCNT_INIT && !(old_info->flags & LS_INFO_RCBELOWZERO)) {
        old_info->flags |= LS_INFO_RCBELOWZERO;
        /* fprintf(stderr, "[lazy-san] refcnt <= 0???\n"); */
      });

    --old_info->refcnt;
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
    global_ptrlog[widx] = tmp_ptrlog_val | (1UL << bidx);
    ++info->refcnt;
  }
}

void __attribute__((noinline)) ls_clear_ptrlog(char *p, unsigned long size) {
  char *end = p + size;
  unsigned long offset = (unsigned long)p >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);

  if (widx == widx_e) {
    mask |= mask_e;
    *pl &= mask;
    return;
  }

  *pl++ &= mask;
  while (pl < pl_e)
    *pl++ = 0;
  *pl &= mask_e;
}

void __attribute__((noinline)) ls_copy_ptrlog(char *d, char *s, unsigned long size) {
  char *end = d + size, *s_end = s + size;
  unsigned long offset = (unsigned long)d >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long s_offset = (unsigned long)s >> 3, s_offset_e = (unsigned long)s_end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long s_widx = s_offset >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long s_bidx = s_offset & 0x3F, s_bidx_e = s_offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long *s_pl = global_ptrlog + s_widx;
  unsigned long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);
  unsigned long s_mask = ((1UL << s_bidx) - 1), s_mask_e = (-1L << s_bidx_e);
  unsigned long pl_val, s_pl_val;

  unsigned long bitcnts = size >> 3;

  /* TODO: do this more efficiently */
  /* TODO: distinguish memcpy from memmove */
  /* TODO: can we skip if size is not multiple of 8? */

  unsigned long cur = bidx;
  unsigned long s_cur = s_bidx;

  ls_clear_ptrlog(d, size);

  while (bitcnts--) {
    unsigned long s_curbit = 1UL << s_cur;
    unsigned long bitset = (*s_pl & s_curbit) ? 1 : 0;
    *pl = (*pl & ~(bitset << cur)) | (bitset << cur);
    cur = (++cur & 0x3f);
    s_cur = (++s_cur & 0x3f);
    if (cur == 0) pl++;
    if (s_cur == 0) s_pl++;
  }
}

/* corresponding to memcpy, d and s do not overlap */
void __attribute__((noinline)) ls_incdec_copy_ptrlog(char *d, char *s, unsigned long size) {
  char *end = d + size, *s_end = s + size;
  unsigned long offset = (unsigned long)d >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long s_offset = (unsigned long)s >> 3, s_offset_e = (unsigned long)s_end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long s_widx = s_offset >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long s_bidx = s_offset & 0x3F, s_bidx_e = s_offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long *s_pl = global_ptrlog + s_widx;
  unsigned long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);
  unsigned long s_mask = ((1UL << s_bidx) - 1), s_mask_e = (-1L << s_bidx_e);
  unsigned long pl_val, s_pl_val;

  unsigned long bitcnts = size >> 3;

  /* TODO: do this more efficiently */
  /* TODO: can we skip if size is not multiple of 8? */

  unsigned long cur = bidx;
  unsigned long s_cur = s_bidx;

  ls_dec_clear_ptrlog(d, size);
  ls_inc_ptrlog(d, s, size);
}

/* corresponding to memmove, d and s may overlap */
void __attribute__((noinline)) ls_incdec_move_ptrlog(char *d, char *s, unsigned long size) {
  char *end = d + size, *s_end = s + size;
  unsigned long offset = (unsigned long)d >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long s_offset = (unsigned long)s >> 3, s_offset_e = (unsigned long)s_end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long s_widx = s_offset >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long s_bidx = s_offset & 0x3F, s_bidx_e = s_offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long *s_pl = global_ptrlog + s_widx;
  unsigned long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);
  unsigned long s_mask = ((1UL << s_bidx) - 1), s_mask_e = (-1L << s_bidx_e);
  unsigned long pl_val, s_pl_val;

  unsigned long bitcnts = size >> 3;

  if (((d > s) && (d > (s+size)))
      || ((s > d) && (s > (d+size)))) {
    ls_incdec_copy_ptrlog(d, s, size);
    return;
  }

  unsigned long cur = bidx;
  unsigned long s_cur = s_bidx;
  while (bitcnts--) {
    unsigned long s_curbit = 1UL << s_cur;
    unsigned long bitset = (*s_pl & s_curbit) ? 1 : 0;
    *pl = (*pl & ~(bitset << cur)) | (bitset << cur);
    cur = (++cur & 0x3f);
    s_cur = (++s_cur & 0x3f);
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

void __attribute__((noinline)) ls_inc_ptrlog(char *d, char *s, unsigned long size) {
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
      ls_inc_refcnt((char*)*(sw+tmp), (char*)(dw+tmp));
      pl_val &= (pl_val - 1);
    }
    return;
  }

  pl_val = *pl >> bidx;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_inc_refcnt((char*)*(sw+tmp), (char*)(dw+tmp));
    pl_val &= (pl_val - 1);
  }
  pl++, sw+=(64-bidx), dw+=(64-bidx);

  while (pl < pl_e) {
    pl_val = *pl;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      ls_inc_refcnt((char*)*(sw + tmp), (char*)(dw+tmp));
      pl_val &= (pl_val - 1);
    }
    pl++, sw+=64, dw+=64;
  }

  pl_val = *pl & ~mask_e;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_inc_refcnt((char*)*(sw + tmp), (char*)(dw+tmp));
    pl_val &= (pl_val - 1);
  }
}

static void ls_dec_ptrlog_int(char *p, char *end) {
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
      ls_dec_refcnt((char*)*(pw+tmp), pw+tmp);
      pl_val &= (pl_val - 1);
    }
    *pl &= (mask | mask_e); // clear
    return;
  }

  pl_val = *pl >> bidx;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_dec_refcnt((char*)*(pw+tmp), pw+tmp);
    pl_val &= (pl_val - 1);
  }
  *pl &= mask; // clear
  pl++, pw+=(64-bidx);

  while (pl < pl_e) {
    pl_val = *pl;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      ls_dec_refcnt((char*)*(pw + tmp), pw+tmp);
      pl_val &= (pl_val - 1);
    }
    *pl = 0; // clear
    pl++, pw+=64;
  }

  pl_val = *pl & ~mask_e;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_dec_refcnt((char*)*(pw + tmp), pw+tmp);
    pl_val &= (pl_val - 1);
  }
  *pl &= mask_e;
}

void __attribute__((noinline)) ls_dec_ptrlog(char *p, unsigned long size) {
  ls_dec_ptrlog_int(p, p+size);
  DEBUG(memset(p, 0, size));
}

void __attribute__((noinline)) ls_dec_ptrlog_addr(char *p, char *end) {
  assert(p && end && p < end);
  ls_dec_ptrlog_int(p, end);
  // do not memset!
}

void __attribute__((noinline)) ls_dec_clear_ptrlog(char *p, unsigned long size) {
  char *end = p + size;
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
      ls_dec_refcnt((char*)*(pw+tmp), 0);
      pl_val &= (pl_val - 1);
    }
    *pl &= (mask | mask_e); // clear
    return;
  }

  pl_val = *pl >> bidx;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_dec_refcnt((char*)*(pw+tmp), 0);
    pl_val &= (pl_val - 1);
  }
  *pl &= mask; // clear
  pl++, pw+=(64-bidx);

  while (pl < pl_e) {
    pl_val = *pl;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      ls_dec_refcnt((char*)*(pw + tmp), 0);
      pl_val &= (pl_val - 1);
    }
    *pl = 0; // clear
    pl++, pw+=64;
  }

  pl_val = *pl & ~mask_e;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    ls_dec_refcnt((char*)*(pw + tmp), 0);
    pl_val &= (pl_val - 1);
  }
  *pl &= mask_e;
}

/********************/
/**  Wrappers  ******/
/********************/

static ls_obj_info *alloc_common(char *base, unsigned long size) {
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

  return alloc_obj_info(base, size);
}

static void free_common(char *base, ls_obj_info *info) {
  DEBUG(--alloc_cur);

  DEBUG(if (info->flags & LS_INFO_FREED)
          fprintf(stderr, "[lazy-san] double free??????\n"));

  if (info->refcnt <= 0) {
    delete_obj_info(info);
    ls_free(base, info);
  } else {
    info->flags |= LS_INFO_FREED;
    DEBUG(quarantine_size += info->size);
  }
}

void *malloc_wrap(size_t size) {
  char *ret = malloc(size);
  DEBUG(if (!ret)
          fprintf(stderr, "[lazy-san] malloc failed ??????\n"));
  alloc_common(ret, size);
  return(ret);
}

void *calloc_wrap(size_t num, size_t size) {
  char *ret = calloc(num, size);
  DEBUG(if (!ret)
          fprintf(stderr, "[lazy-san] calloc failed ??????\n"));
  alloc_common(ret, num*size);
  return(ret);
}

void *realloc_wrap(void *ptr, size_t size) {
  char *p = (char*)ptr;
  ls_obj_info *info, *newinfo;
  char *ret;

  if (p==NULL)
    return malloc(size);

  info = get_obj_info(p);

  /* NOTE: realloc should be modified not to free old ptr */
  ret = realloc(ptr, size);
  if (ret != ptr) {
    newinfo = alloc_common(ret, size);
    ls_copy_ptrlog(ret, ptr, info->size);
    free_common(p, info);
  } else {
    info->size = size;
  }

  return(ret);
}

void free_wrap(void *ptr) {
  ls_obj_info *info;

  if (ptr==NULL)
    return;

  info = get_obj_info(ptr);
  ls_dec_ptrlog(ptr, info->size);
  free_common(ptr, info);
}

#ifdef CPLUSPLUS

void *_Znwm_wrap(size_t size) {
  char *ret = _Znwm(size);
  DEBUG(if (!ret)
          fprintf(stderr, "[lazy-san] new failed ??????\n"));
  alloc_common(ret, size);
  return(ret);
}

void *_Znam_wrap(size_t size) {
  char *ret = _Znam(size);
  DEBUG(if (!ret)
          fprintf(stderr, "[lazy-san] new[] failed ??????\n"));
  alloc_common(ret, size);
  return(ret);
}

void _ZdlPv_wrap(void *ptr) {
  ls_obj_info *info;

  if (ptr==NULL)
    return;

  info = get_obj_info(ptr);
  ls_dec_ptrlog(ptr, info->size);
  info->flags |= LS_INFO_USE_ZDLPV;
  free_common(ptr, info);
}

void _ZdaPv_wrap(void *ptr) {
  ls_obj_info *info;

  if (ptr==NULL)
    return;

  info = get_obj_info(ptr);
  if (!info) { _ZdaPv(ptr); return; } /* alloc'ed with new[0] */
  ls_dec_ptrlog(ptr, info->size);
  info->flags |= LS_INFO_USE_ZDAPV;
  free_common(ptr, info);
}

#endif
