#Author: Dimitris Segkesser
#A.M.: 5006

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lssl -lcrypto

# Directories
SRC_DIR = ./src
LAUNCHER_DIR = $(SRC_DIR)/launcher
UTIL_DIR = $(SRC_DIR)/utils
BUILD_DIR = ./build

# Source files
SRCS = $(LAUNCHER_DIR)/launcher.c $(UTIL_DIR)/logging.c $(SRC_DIR)/main.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Output executable
TARGET = $(BUILD_DIR)/monitor

# Ensure build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Rule to compile launcher module
$(BUILD_DIR)/launcher.o: $(LAUNCHER_DIR)/launcher.c $(LAUNCHER_DIR)/launcher.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to compile logger
$(BUILD_DIR)/logging.o: $(UTIL_DIR)/logging.c $(UTIL_DIR)/logging.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to compile main.c
$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to link the final executable
$(TARGET): $(BUILD_DIR)/launcher.o $(BUILD_DIR)/logging.o $(BUILD_DIR)/main.o
	$(CC) $(CFLAGS) $(BUILD_DIR)/launcher.o $(BUILD_DIR)/logging.o $(BUILD_DIR)/main.o $(LIBS) -o $(TARGET)

# Default rule (build everything)
all: $(TARGET)

# Clean rule (remove everything from build directory)
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
