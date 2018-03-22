CC=clang
METAPAGETABLEDIR=../metapagetable
INCLUDES=-I. -I$(METAPAGETABLEDIR)
CFLAGS=-c -Wall -flto -fPIC -std=gnu11
OBJDIR=./obj

CFLAGS += -O3
# you can uncomment or supply these to make invocation
# LS_DEBUG=y # insert debugging code

EXE=$(OBJDIR)/libmetadata.a

SRCS   := compat.c  metaget.c metaset.c Dangling/lazy_san.c

OBJS    := $(patsubst %.c,$(OBJDIR)/%.c.o,$(SRCS))
DEPS    := $(OBJS:.o=.d)

ifdef LS_DEBUG
CFLAGS += -DDEBUG_LS
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
