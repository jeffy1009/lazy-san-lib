#define _GNU_SOURCE
#define __USE_GNU

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <stdio.h>
#include <metadata.h>
#include <metapagetable_core.h>

unsigned long dang_global_start;
unsigned long dang_global_size;

__attribute__ ((visibility("hidden"))) extern char _end;

__attribute__((visibility ("hidden"), constructor(-1))) void initialize_global_metadata() {
    static int initialized;

    /* use both constructor and preinit_array to be first in executables and still work in shared objects */
    if (initialized) return;
    initialized = 1;

    if (!is_fixed_compression()) {
	/* code, data, bss, ... all assumed to be together */
        Dl_info info = {};
        if (!dladdr(initialize_global_metadata, &info)) {
            perror("initialize_global_metadata: dladdr failed");
	    exit(-1);
        }
	char *global_start = info.dli_fbase;
	char *global_end = &_end;

        /* DangSan: 
         * Global start and end is required to find global objects/ptrs.
         */
        dang_global_start = (unsigned long) global_start;
        dang_global_size = (unsigned long) (global_end - global_start);
    }

    return;
}

__attribute__((section(".preinit_array"),
               used)) void (*initialize_global_metadat_preinit)(void) = initialize_global_metadata;
