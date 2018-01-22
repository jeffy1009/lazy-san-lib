#include <metadata.h>
#include <metapagetable_core.h>

#define unlikely(x)     __builtin_expect((x),0)

#define CREATE_METAGET(size)                        \
meta##size metaget_##size (unsigned long ptrInt) {  \
    unsigned long page = ptrInt / METALLOC_PAGESIZE;\
    unsigned long entry = pageTable[page];          \
    if (unlikely(entry == 0)) {                     \
        meta##size zero;                            \
        for (int i = 0; i < sizeof(meta##size) /    \
                        sizeof(unsigned long); ++i) \
            ((unsigned long*)&zero)[i] = 0;         \
        return zero;                                \
    }                                           \
    unsigned long alignment = entry & 0xFF;         \
    char *metabase = (char*)(entry >> 8);           \
    unsigned long pageOffset = ptrInt -             \
                        (page * METALLOC_PAGESIZE); \
    char *metaptr = metabase + ((pageOffset >>      \
                                    alignment) *    \
                        size);                      \
    return *(meta##size *)metaptr;                  \
}

CREATE_METAGET(4)
CREATE_METAGET(8)
