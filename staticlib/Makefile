CC=clang
METAPAGETABLEDIR=../metapagetable
INCLUDES=-I. -I$(METAPAGETABLEDIR)
CFLAGS=-c -Wall -flto -fPIC -std=gnu11
OBJDIR=./obj

CFLAGS += -O3
# you can uncomment or supply these to make invocation
# LS_DEBUG=y # insert debugging code

EXE=$(OBJDIR)/libmetadata.a
EXE2=$(OBJDIR)/libmetadata_cpp.a

SRCS_COMMON   := compat.c Dangling/lazy_san.c
SRCS := $(SRCS_COMMON) metaget.c metaset.c

OBJS    := $(patsubst %.c,$(OBJDIR)/%.c.o,$(SRCS))
OBJS2    := $(patsubst %.c,$(OBJDIR)/%.cpp.o,$(SRCS))
DEPS    := $(OBJS:.o=.d)

ifdef LS_DEBUG
CFLAGS += -DDEBUG_LS
endif

all: directories $(EXE) $(EXE2)

clean:
	rm -f $(OBJS) $(OBJS2)
	rm -f $(DEPS)
	rm -f $(EXE) $(EXE2)

$(EXE): $(OBJS) directories
	llvm-ar crv $@ $(OBJS)
	llvm-ranlib $@

$(EXE2): $(OBJS2) directories
	llvm-ar crv $@ $(OBJS2)
	llvm-ranlib $@

-include $(DEPS)

$(OBJDIR)/%.c.o: %.c directories
	$(CC) $(INCLUDES) $(CFLAGS) -MMD -o $@ $< 

$(OBJDIR)/%.cpp.o: %.c directories
	$(CC) $(INCLUDES) $(CFLAGS) -MMD -o $@ $< -DCPLUSPLUS

directories:
	mkdir -p $(OBJDIR)
	mkdir -p $(OBJDIR)/Dangling
