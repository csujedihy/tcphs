# Compiler to use
CC = gcc

# Compiler flags
CFLAGS = -Wall -g -O3

# Target executable name
TARGET = tcphs

# Source file
SRC = main.c

# Default target
all: $(TARGET)

# Link object files to create the executable
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Clean up
clean:
	rm -f $(TARGET)

# Phony targets (not actual files)
.PHONY: all clean