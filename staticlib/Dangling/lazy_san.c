#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>
#include "red_black_tree.h"

long *global_ptrlog;
extern rb_red_blk_tree *rb_root;

long alloc_max = 0, alloc_cur = 0, alloc_tot = 0;
long num_ptrs = 0;
long quarantine_size = 0, quarantine_max = 0, quarantine_max_mb = 0;

void atexit_hook() {
  printf("PROGRAM TERMINATED!\n");
  printf("max alloc: %ld, cur alloc: %ld, tot alloc: %ld\n",
         alloc_max, alloc_cur, alloc_tot);
  printf("num ptrs: %ld\n", num_ptrs);
  printf("quarantine max: %ld B, cur: %ld B\n", quarantine_max, quarantine_size);
}

void __attribute__((constructor)) init_interposer() {

  if (atexit(atexit_hook))
    printf("atexit failed!\n");

  global_ptrlog = mmap((void*)0x00007fff8000, 0x020000000000 /* 2TB */,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE,
                       -1, 0);
  if (global_ptrlog == (void*)-1) {
     /* strangely, perror() segfaults */
    printf("[lazy-san] global_ptrlog mmap failed: errno %d\n", errno);
    exit(0);
  }
  printf("[lazy-san] global_ptrlog mmap'ed @ 0x%lx\n", (long)global_ptrlog);
}

/*****************************/
/**  Refcnt modification  ****/
/*****************************/

/* p - written pointer value
   dest - store destination */
void ls_inc_refcnt(char *p, char *dest) {
  rb_red_blk_node *n;
  long offset, widx, bidx;

  if (!p)
    return;

  num_ptrs++;
  n = RBExactQuery(rb_root, p);
  if (n) {
    if ((n->flags & RB_INFO_FREED) && n->refcnt == REFCNT_INIT)
      printf("[lazy-san] refcnt became alive again??\n");
    ++n->refcnt;
  }

  /* mark pointer type field */
  offset = (long)dest >> 3;
  widx = offset >> 6; /* word index */
  bidx = offset & 0x3F; /* bit index */
  global_ptrlog[widx] |= (1UL << bidx);
}

void ls_dec_refcnt(char *p, char *dummy) {
  rb_red_blk_node *n;

  if (!p)
    return;

  n = RBExactQuery(rb_root, p);
  if (n) { /* is heap node */
    if (n->refcnt<=REFCNT_INIT && !(n->flags & RB_INFO_RCBELOWZERO)) {
      n->flags |= RB_INFO_RCBELOWZERO;
      /* printf("[lazy-san] refcnt <= 0???\n"); */
    }
    --n->refcnt;
    if (n->refcnt<=0) {
      if (n->flags & RB_INFO_FREED) { /* marked to be freed */
        quarantine_size -= n->size;
        free(n->base);
        RBDelete(rb_root, n);
      }
      /* if n is not yet freed, the pointer is probably in some
         register. */
    }
  }
}

void ls_clear_ptrlog(char *p, long size) {
  char *end = p + size;
  long offset = (long)p >> 3, offset_e = (long)end >> 3;
  long widx = offset >> 6, widx_e = offset_e >> 6;
  long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);

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

void ls_copy_ptrlog(char *d, char *s, long size) {
  char *end = d + size, *s_end = s + size;
  long offset = (long)d >> 3, offset_e = (long)end >> 3;
  long s_offset = (long)s >> 3, s_offset_e = (long)s_end >> 3;
  long widx = offset >> 6, widx_e = offset_e >> 6;
  long s_widx = s_offset >> 6;
  long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  long s_bidx = s_offset & 0x3F, s_bidx_e = s_offset_e & 0x3F;
  long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  long *s_pl = global_ptrlog + s_widx;
  long mask = ((1UL << bidx) - 1), mask_e = (-1L << bidx_e);
  long s_mask = ((1UL << s_bidx) - 1), s_mask_e = (-1L << s_bidx_e);
  long pl_val, s_pl_val;

  long bitcnts = size >> 3;

  /* TODO: do this more efficiently */
  /* TODO: distinguish memcpy from memmove */
  /* TODO: can we skip if size is not multiple of 8? */

  long cur = bidx;
  long s_cur = s_bidx;
  while (bitcnts--) {
    long s_curbit = 1UL << s_cur;
    long bitset = (*s_pl & s_curbit) ? 1 : 0;
    *pl = (*pl & ~(bitset << cur)) | (bitset << cur);
    cur = (++cur & 0x3f);
    s_cur = (++s_cur & 0x3f);
    if (cur == 0) pl++;
    if (s_cur == 0) s_pl++;
  }
}

static void inc_or_dec_ptrlog(char *p, long size, void (*f)(char *, char *)) {
  char *end = p + size;
  long offset = (long)p >> 3, offset_e = (long)end >> 3;
  long widx = offset >> 6, widx_e = offset_e >> 6;
  long bidx = offset & 0x3F, bidx_e = offset_e & 0x3F;
  long *pl = global_ptrlog + widx, *pl_e = global_ptrlog + widx_e;
  long mask_e = (-1L << bidx_e);
  long *pw = (long *)p;
  long pl_val;

  if (widx == widx_e) {
    pl_val = (*pl & ~mask_e) >> bidx;
    while (pl_val) {
      long tmp = __builtin_ctzl(pl_val);
      f((char*)*(pw+tmp), 0);
      pl_val &= (pl_val - 1);
    }
    return;
  }

  pl_val = *pl >> bidx;
  while (pl_val) {
    long tmp = __builtin_ctzl(pl_val);
    f((char*)*(pw+tmp), 0);
    pl_val &= (pl_val - 1);
  }
  pl++, pw+=(64-bidx);

  while (pl < pl_e) {
    pl_val = *pl;
    while (pl_val) {
      long tmp = __builtin_ctzl(pl_val);
      f((char*)*(pw + tmp), 0);
      pl_val &= (pl_val - 1);
    }
    pl++, pw+=64;
  }

  pl_val = *pl & ~mask_e;
  while (pl_val) {
    long tmp = __builtin_ctzl(pl_val);
    f((char*)*(pw + tmp), 0);
    pl_val &= (pl_val - 1);
  }
}

void ls_inc_ptrlog(char *p, long size) {
  inc_or_dec_ptrlog(p, size, ls_inc_refcnt);
}

void ls_dec_ptrlog(char *p, long size) {
  inc_or_dec_ptrlog(p, size, ls_dec_refcnt);
}

/********************/
/**  Wrappers  ******/
/********************/

static rb_red_blk_node *alloc_common(char *base, long size) {
  if (++alloc_cur > alloc_max)
    alloc_max = alloc_cur;

  ++alloc_tot;
  if (quarantine_size > quarantine_max) {
    long quarantine_mb_tmp;
    quarantine_max = quarantine_size;
    quarantine_mb_tmp = quarantine_max/1024/1024;
    if (quarantine_mb_tmp > quarantine_max_mb) {
      quarantine_max_mb = quarantine_mb_tmp;
      printf("[lazy-san] quarantine_max = %ld MB\n", quarantine_max_mb);
    }
  }

  memset(base, 0, size);
  ls_clear_ptrlog(base, size);

  return RBTreeInsert(rb_root, base, size);
}

static void free_common(char *base, rb_red_blk_node *n) {
  --alloc_cur;

  if (n->flags & RB_INFO_FREED)
    printf("[lazy-san] double free??????\n");

  if (n->refcnt <= 0) {
    free(base);
    RBDelete(rb_root, n);
  } else {
    n->flags |= RB_INFO_FREED;
    quarantine_size += n->size;
  }
}

void *malloc_wrap(size_t size) {
  char *ret = malloc(size);
  if (!ret)
    printf("[lazy-san] malloc failed ??????\n");
  alloc_common(ret, size);
  return(ret);
}

void *calloc_wrap(size_t num, size_t size) {
  char *ret = calloc(num, size);
  if (!ret)
    printf("[lazy-san] calloc failed ??????\n");
  alloc_common(ret, num*size);
  return(ret);
}

void *realloc_wrap(void *ptr, size_t size) {
  char *p = (char*)ptr;
  rb_red_blk_node *orig_n, *new_n;
  char *ret;

  if (p==NULL)
    return malloc(size);

  orig_n = RBExactQuery(rb_root, p);

  if (orig_n->base != p)
    printf("[lazy-san] ptr != base in realloc ??????\n");
  if ((p+size) <= orig_n->end)
    return p;

  /* just malloc */
  ret = malloc(size);
  if (!ret)
    printf("[lazy-san] malloc failed ??????\n");

  new_n = alloc_common(ret, size);

  memcpy(ret, p, orig_n->size);

  ls_copy_ptrlog(new_n->base, orig_n->base, orig_n->size);

  free_common(p, orig_n);

  return(ret);
}

void free_wrap(void *ptr) {
  rb_red_blk_node *n;

  if (ptr==NULL)
    return;

  n = RBExactQuery(rb_root, ptr);
  if (!n) {
    /* there are no dangling pointers to this node,
       so the node is already removed from the rangetree */
    /* NOTE: there can be a dangling pointer in the register
       and that register value could later be stored in memory.
       Should we handle this case?? */
    free(ptr);
    return;
  }

  ls_dec_ptrlog(ptr, n->size);
  free_common(ptr, n);
}
