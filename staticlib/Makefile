CC=gcc
METAPAGETABLEDIR=../metapagetable
INCLUDES=-I. -I$(METAPAGETABLEDIR)
CFLAGS=-c -Wall -fPIC -std=gnu11
OBJDIR=./obj

CFLAGS += -O3
# you can uncomment or supply these to make invocation
# LS_DEBUG=y # insert debugging code
#LS_DEBUG_HIGH=y # enable more debugging code including tracking not freed object
#LS_ENABLE_MULTITHREAD=y # enable multithreading support

EXE=$(OBJDIR)/libmetadata.a

SRCS   := compat.c Dangling/lazy_san.c Dangling/red_black_tree.c

OBJS    := $(patsubst %.c,$(OBJDIR)/%.c.o,$(SRCS))
DEPS    := $(OBJS:.o=.d)

ifdef LS_DEBUG
CFLAGS += -DDEBUG_LS
endif

ifdef LS_DEBUG_HIGH
CFLAGS += -DDEBUG_LS_HIGH
endif

ifdef LS_ENABLE_MULTITHREAD
CFLAGS += -DENABLE_MULTITHREAD
endif

all: directories $(EXE)

clean:
	rm -f $(OBJS)
	rm -f $(DEPS)
	rm -f $(EXE)

$(EXE): $(OBJS) directories
	llvm-ar crv $@ $(OBJS)
	llvm-ranlib $@

-include $(DEPS)

$(OBJDIR)/%.c.o: %.c directories
	$(CC) $(INCLUDES) $(CFLAGS) -MMD -o $@ $< 

directories:
	mkdir -p $(OBJDIR)
	mkdir -p $(OBJDIR)/Dangling
