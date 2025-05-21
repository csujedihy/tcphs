# Compiler and tools
CC = gcc
CLANG = clang
LLC = llc

# Compiler flags
CFLAGS = -g -O2 -Wall
XDP_CFLAGS = -D__BPF__ -O2 \
    -D__BPF_TRACING__ \
	-target bpf \
	-emit-llvm -Wall -Wno-unused-value \
	-Wno-pointer-sign -Wno-compare-distinct-pointer-types \
	-O2 -g
LDFLAGS = -lbpf -lxdp

# Test interface name
TEST_IFACE = lo

# Source files
USER_SRC = af_xdp_user.c
XDP_SRC = af_xdp_kern.c

# Output files
USER_OBJ = af_xdp_user.o
XDP_OBJ = af_xdp_kern.o
USER_BIN = af_xdp_user
XDP_LL = af_xdp_kern.ll

# Default target
all: clean $(USER_BIN) $(XDP_OBJ)

# Link user-mode application
$(USER_BIN): $(USER_OBJ)
	$(CC) $(USER_OBJ) -o $(USER_BIN) $(LDFLAGS)

# Compile user-mode application
$(USER_OBJ): $(USER_SRC)
	$(CC) $(CFLAGS) -c $(USER_SRC) -o $(USER_OBJ)

# Compile XDP program to LLVM IR
$(XDP_LL): $(XDP_SRC)
	$(CLANG) $(XDP_CFLAGS) -c $(XDP_SRC) -o $(XDP_LL)

# Compile LLVM IR to BPF object file
$(XDP_OBJ): $(XDP_LL)
	$(LLC) -march=bpf -filetype=obj -o $(XDP_OBJ) $(XDP_LL)

# Clean build artifacts
clean:
	rm -f $(USER_OBJ) $(XDP_OBJ) $(USER_BIN) $(XDP_LL)

test: all
	echo "testing...\n"
	sudo ip link set dev $(TEST_IFACE) xdp off
	sudo ./$(USER_BIN) -d $(TEST_IFACE) -p 4433
	sudo ip link set dev $(TEST_IFACE) xdp off

# Phony targets
.PHONY: all clean