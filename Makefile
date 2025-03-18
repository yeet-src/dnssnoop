.PHONY: default \
	debug \
	pkg \
	unpkg \
	clean \
	vmlinux \
	clean_vmlinux \
	format \
	check_format \
	container

PROJECT_ROOT=$(shell git rev-parse --show-toplevel)

BINDIR = bin
TARGET = dnssnoop
SRCDIR = src
BUILDDIR = build
VMLINUX ?= /sys/kernel/btf/vmlinux
CFORMAT = .clang-format

CC = clang-19
CFLAGS = -g -O2 -target bpf -I include

SRCS := $(wildcard $(SRCDIR)/*.bpf.c)
OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
CONTAINER ?= $(shell test -e /.dockerenv && echo yes || echo no)
CLANG_FORMAT ?= $(shell type -P "clang-format-19" &> /dev/null && echo "clang-format-19" || echo "clang-format" )
BPFTOOL ?= $(shell type -P "bpftool" &> /dev/null && echo "bpftool" || echo "/usr/sbin/bpftool" )

default: $(if $(filter yes, $(CONTAINER)), container, include/vmlinux.h $(BUILDDIR) $(BINDIR) $(BINDIR)/$(TARGET))
ifeq ($(CONTAINER), yes)
	docker run --rm -it -v $(CURDIR):/opt/$(TARGET) -w /opt/$(TARGET) $(TARGET) make
endif

debug: CFLAGS += -DBPF_DEBUG=1
debug: default

pkg:
	$(PROJECT_ROOT)/scripts/yeet_pkg.sh --target $(TARGET)

unpkg:
	$(PROJECT_ROOT)/scripts/yeet_pkg.sh -u --target $(TARGET)

container:
	docker build -t $(TARGET) .

$(BINDIR)/$(TARGET): $(OBJS)
	$(BPFTOOL) gen object $@ $^
	chmod +x $@

$(BINDIR):
	mkdir -p $(BINDIR)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.bpf.o: $(SRCDIR)/%.bpf.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR)
	rm -rf $(BINDIR)
	rm -rf $(TARGET).yeet
	rm -rf $(TARGET)

include/vmlinux.h: $(if $(filter yes, $(CONTAINER)), /sys/kernel/btf/vmlinux, )
	make vmlinux

vmlinux: $(if $(filter yes, $(CONTAINER)), container, )
ifeq ($(CONTAINER), yes)
	docker run --rm -it -v $(CURDIR):/opt/$(TARGET) -w /opt/$(TARGET) $(TARGET) make vmlinux
else
	$(BPFTOOL) btf dump file $(VMLINUX) format c > include/vmlinux.h
endif

clean_vmlinux:
	rm include/vmlinux.h

format:
ifeq ($(CONTAINER), yes)
	docker run --rm -it -v $(CURDIR):/opt/$(TARGET) -w /opt/$(TARGET) $(TARGET) make format
else
	@find . -name "*.c" -exec $(CLANG_FORMAT) -i -style=file:$(CFORMAT) {} + || exit 1; \
	echo "Formatted all files"
endif

check_format: $(if $(filter yes, $(CONTAINER)), container, )
ifeq ($(CONTAINER), yes)
	docker run --rm -it -v $(CURDIR):/opt/$(TARGET) -w /opt/$(TARGET) $(TARGET) make check_format
else
	@find . -name "*.c" -exec $(CLANG_FORMAT) -style=file:$(CFORMAT) --dry-run --Werror {} + || exit 1;
endif
