# Author: 	Dimitris Segkesser
# Date: 	10/4/2025

CC := gcc
CFLAGS := -Wall -Wextra -std=c11 -g -MMD -MP
LDFLAGS := -lcrypto  # OpenSSL for MD5 and SHA-256
SRC_DIR := ./src
BUILD_DIR := ./build
TARGET := $(BUILD_DIR)/monitor
TEST_DIR := ./tests

# Find all .c files recursively
SRC_FILES := $(shell find $(SRC_DIR) -type f -name "*.c")
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))
DEP_FILES := $(OBJ_FILES:.o=.d)  # Generate .d files alongside .o files

.PHONY: all clean iotest httptest1 httptest2 test

# Default target
all: $(TARGET)

# Create the target executable
$(TARGET): $(OBJ_FILES)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compile each .c file into a .o file in /build and generate dependencies
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Include dependency files to track header changes
-include $(DEP_FILES)

# Clean up the build directory
clean:
	rm -rf $(BUILD_DIR)

# Clean up the filedump directory (not -rf)
clean-dumps:
	rm ./filedumps/*

iotest: $(TARGET) $(BUILD_DIR)/tests/iotest.o
	$(CC) $(BUILD_DIR)/tests/iotest.o -o $(BUILD_DIR)/tests/iotest
	$(TARGET) $(BUILD_DIR)/tests/iotest

$(BUILD_DIR)/tests/iotest.o:  $(TARGET) $(TEST_DIR)/iotest.c
	@mkdir -p $(BUILD_DIR)/tests
	$(CC) -c $(TEST_DIR)/iotest.c -o $(BUILD_DIR)/tests/iotest.o

simpletest: $(TARGET) $(BUILD_DIR)/tests/helloworld.o
	$(CC) $(BUILD_DIR)/tests/helloworld.o -o $(BUILD_DIR)/tests/helloworld
	$(TARGET) $(BUILD_DIR)/tests/helloworld

$(BUILD_DIR)/tests/helloworld.o:  $(TARGET) $(TEST_DIR)/helloworld.c
	@mkdir -p $(BUILD_DIR)/tests
	$(CC) -c $(TEST_DIR)/helloworld.c -o $(BUILD_DIR)/tests/helloworld.o

httptest1:  $(TARGET)
	$(TARGET) $(TEST_DIR)/request.py

httptest2:  $(TARGET)
	$(TARGET) $(TEST_DIR)/enhanced.py

mixedtest:  $(TARGET)
	$(TARGET) $(TEST_DIR)/mixed.py