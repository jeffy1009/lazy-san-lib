#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>
#include "lsan_common.h"

//#define USE_RBTREE
#ifdef USE_RBTREE
#include "red_black_tree.h"
#else
#include "metadata.h"
#endif

#define GLOBAL_PTRLOG_BASE 0x000400000000
#define GLOBAL_PTRLOG_SIZE 0x020000000000  /* 2TB */
#define GLOBAL_PTRLOG_END (GLOBAL_PTRLOG_BASE+GLOBAL_PTRLOG_SIZE)

static unsigned long *global_ptrlog;

#ifdef USE_RBTREE

extern rb_red_blk_tree *rb_root;

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

__attribute__ ((visibility("hidden"))) extern char _end;

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
    if ((num_obj_info+num_obj_info/4) > meta_idx_max)
      printf("[lazy-san] num obj info reached the limit!\n");
    meta_idx_limit *= 2;
  }
  cur->base = base;
  cur->size = size;
  cur->refcnt = REFCNT_INIT;
  cur->flags = 0;
  return cur;
}

static ls_obj_info *get_obj_info(char *p) {
  if (p > &_end && p < (char*)GLOBAL_PTRLOG_BASE)
    return (ls_obj_info*)metaget_8((unsigned long)p);
  return NULL;
}

static void delete_obj_info(ls_obj_info *info) {
  metaset_8((unsigned long)info->base, tc_malloc_size(info->base), 0);
  info->base = 0;
  --num_obj_info;
}

#endif

unsigned long alloc_max = 0, alloc_cur = 0, alloc_tot = 0;
unsigned long num_ptrs = 0;
unsigned long quarantine_size = 0, quarantine_max = 0, quarantine_max_mb = 0;

void atexit_hook() {
  printf("PROGRAM TERMINATED!\n");
  printf("max alloc: %ld, cur alloc: %ld, tot alloc: %ld\n",
         alloc_max, alloc_cur, alloc_tot);
  printf("num ptrs: %ld\n", num_ptrs);
  printf("quarantine max: %ld B, cur: %ld B\n", quarantine_max, quarantine_size);
}

void __attribute__((visibility ("hidden"), constructor(-1))) init_lazysan() {
  static int initialized = 0;

  if (initialized) return;
  initialized = 1;

  if (atexit(atexit_hook))
    printf("atexit failed!\n");

  global_ptrlog = mmap((void*)GLOBAL_PTRLOG_BASE, GLOBAL_PTRLOG_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE,
                       -1, 0);
  if (global_ptrlog == (void*)-1) {
     /* strangely, perror() segfaults */
    printf("[lazy-san] global_ptrlog mmap failed: errno %d\n", errno);
    exit(0);
  }
  printf("[lazy-san] global_ptrlog mmap'ed @ 0x%lx\n",
         (unsigned long)global_ptrlog);

#ifndef USE_RBTREE
  ls_meta_space = mmap((void*)GLOBAL_PTRLOG_END, LS_META_SPACE_MAX_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE,
                       -1, 0);
  if (ls_meta_space == (void*)-1) {
     /* strangely, perror() segfaults */
    printf("[lazy-san] ls_meta_space mmap failed: errno %d\n", errno);
    exit(0);
  }
  printf("[lazy-san] ls_meta_space mmap'ed @ 0x%lx\n",
         (unsigned long)ls_meta_space);
#endif
}

__attribute__((section(".preinit_array"),
               used)) void (*init_ls_preinit)(void) = init_lazysan;

/*****************************/
/**  Refcnt modification  ****/
/*****************************/

/* p - written pointer value
   dest - store destination */
void ls_inc_refcnt(char *p, char *dest) {
  ls_obj_info *info;
  unsigned long offset, widx, bidx;

  if (!p)
    return;

  num_ptrs++;
  info = get_obj_info(p);

  if (info) {
    if ((info->flags & LS_INFO_FREED) && info->refcnt == REFCNT_INIT)
      printf("[lazy-san] refcnt became alive again??\n");
    ++info->refcnt;
  }

  /* mark pointer type field */
  offset = (unsigned long)dest >> 3;
  widx = offset >> 6; /* word index */
  bidx = offset & 0x3F; /* bit index */
  global_ptrlog[widx] |= (1UL << bidx);
}

void ls_dec_refcnt(char *p, char *dummy) {
  ls_obj_info *info;

  if (!p)
    return;

  info = get_obj_info(p);
  if (info) { /* is heap node */
    if (info->refcnt<=REFCNT_INIT && !(info->flags & LS_INFO_RCBELOWZERO)) {
      info->flags |= LS_INFO_RCBELOWZERO;
      /* printf("[lazy-san] refcnt <= 0???\n"); */
    }
    --info->refcnt;
    if (info->refcnt<=0) {
      if (info->flags & LS_INFO_FREED) { /* marked to be freed */
        char *tmp = info->base;
        quarantine_size -= info->size;
        delete_obj_info(info);
        free(tmp);
      }
      /* if not yet freed, the pointer is probably in some
         register. */
    }
  }
}

void ls_clear_ptrlog(char *p, unsigned long size) {
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

void ls_copy_ptrlog(char *d, char *s, unsigned long size) {
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

static void inc_or_dec_ptrlog(char *p, unsigned long size, void (*f)(char *, char *)) {
  char *end = p + size;
  unsigned long offset = (unsigned long)p >> 3, offset_e = (unsigned long)end >> 3;
  unsigned long widx = offset >> 6, widx_e = offset_e >> 6;
  unsigned long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  unsigned long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  unsigned long mask_e = (-1L << bidx_e);
  unsigned long *pw = (unsigned long *)p;
  unsigned long pl_val;

  if (widx == widx_e) {
    pl_val = (*pl & ~mask_e) >> bidx;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      f((char*)*(pw+tmp), 0);
      pl_val &= (pl_val - 1);
    }
    return;
  }

  pl_val = *pl >> bidx;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    f((char*)*(pw+tmp), 0);
    pl_val &= (pl_val - 1);
  }
  pl++, pw+=(64-bidx);

  while (pl < pl_e) {
    pl_val = *pl;
    while (pl_val) {
      unsigned long tmp = __builtin_ctzl(pl_val);
      f((char*)*(pw + tmp), 0);
      pl_val &= (pl_val - 1);
    }
    pl++, pw+=64;
  }

  pl_val = *pl & ~mask_e;
  while (pl_val) {
    unsigned long tmp = __builtin_ctzl(pl_val);
    f((char*)*(pw + tmp), 0);
    pl_val &= (pl_val - 1);
  }
}

void ls_inc_ptrlog(char *p, unsigned long size) {
  inc_or_dec_ptrlog(p, size, ls_inc_refcnt);
}

void ls_dec_ptrlog(char *p, unsigned long size) {
  inc_or_dec_ptrlog(p, size, ls_dec_refcnt);
}

/********************/
/**  Wrappers  ******/
/********************/

static ls_obj_info *alloc_common(char *base, unsigned long size) {
  if (++alloc_cur > alloc_max)
    alloc_max = alloc_cur;

  ++alloc_tot;
  if (quarantine_size > quarantine_max) {
    unsigned long quarantine_mb_tmp;
    quarantine_max = quarantine_size;
    quarantine_mb_tmp = quarantine_max/1024/1024;
    if (quarantine_mb_tmp > quarantine_max_mb) {
      quarantine_max_mb = quarantine_mb_tmp;
      printf("[lazy-san] quarantine_max = %ld MB\n", quarantine_max_mb);
    }
  }

  ls_clear_ptrlog(base, size);

  return alloc_obj_info(base, size);
}

static void free_common(char *base, ls_obj_info *info) {
  --alloc_cur;

  if (info->flags & LS_INFO_FREED)
    printf("[lazy-san] double free??????\n");

  if (info->refcnt <= 0) {
    delete_obj_info(info);
    free(base);
  } else {
    info->flags |= LS_INFO_FREED;
    quarantine_size += info->size;
  }
}

void *malloc_wrap(size_t size) {
  char *ret = malloc(size);
  if (!ret)
    printf("[lazy-san] malloc failed ??????\n");
  memset(ret, 0, size);
  alloc_common(ret, size);
  return(ret);
}

void *calloc_wrap(size_t num, size_t size) {
  char *ret = calloc(num, size);
  if (!ret)
    printf("[lazy-san] calloc failed ??????\n");
  memset(ret, 0, num*size);
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
  }

  return(ret);
}

void free_wrap(void *ptr) {
  ls_obj_info *info;

  if (ptr==NULL)
    return;

  info = get_obj_info(ptr);
  if (!info) {
    /* there are no dangling pointers to this node,
       so the node is already removed from the rangetree */
    /* NOTE: there can be a dangling pointer in the register
       and that register value could later be stored in memory.
       Should we handle this case?? */
    free(ptr);
    return;
  }

  ls_dec_ptrlog(ptr, info->size);
  free_common(ptr, info);
}
