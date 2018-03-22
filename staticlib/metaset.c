#include <metadata.h>
#include <metapagetable_core.h>

#define CREATE_METASET(size)                        \
unsigned long metaset_##size (unsigned long ptrInt, \
        unsigned long count, meta##size value) {    \
    unsigned long page = ptrInt / METALLOC_PAGESIZE;\
    unsigned long entry = pageTable[page];          \
    unsigned long alignment = entry & 0xFF;         \
    char *metabase = (char*)(entry >> 8);           \
    unsigned long pageOffset = ptrInt -             \
                        (page * METALLOC_PAGESIZE); \
    char *metaptr = metabase + ((pageOffset >>      \
                                    alignment) *    \
                        size);                      \
    unsigned long metasize = ((count +              \
                    (1 << (alignment)) - 1) >>      \
                alignment);                         \
    for (unsigned long i = 0; i < metasize; ++i) {  \
        *(meta##size *)metaptr  = value;   \
        metaptr += size;                            \
    }                                               \
    return entry;                                   \
}

CREATE_METASET(8)
