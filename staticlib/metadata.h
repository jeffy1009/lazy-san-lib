#ifndef METADATA_H
#define METADATA_H

#include <stdint.h>
#include <string.h>

typedef uint64_t meta8;

/* Need declaration of get/set functions */
#define DECLARE_METAGET(size) 				\
  meta##size metaget_##size (unsigned long ptrInt);

DECLARE_METAGET(8)

#define DECLARE_METASET(size)                                           \
  unsigned long metaset_##size (unsigned long ptrInt,                   \
                                unsigned long count, meta##size value);

DECLARE_METASET(8)

#endif /* !METADATA_H */
