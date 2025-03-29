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

.PHONY: all clean test

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

# Run tests with each executable under ./tests as an argument
TEST_EXECUTABLES := $(shell find $(TEST_DIR) -type f -executable)

# If no extra arguments are given, run all tests
# Otherwise, pass the argument to the monitor
test: $(TARGET)
	@if [ -z "$(filter test,$(MAKECMDGOALS))" ]; then \
		for test_exec in $(TEST_EXECUTABLES); do \
			echo "Running test with $$test_exec"; \
			$(TARGET) $$test_exec; \
		done; \
	else \
		echo "Running monitor with argument: $(filter-out test,$(MAKECMDGOALS))"; \
		$(TARGET) $(filter-out test,$(MAKECMDGOALS)); \
	fi

# Prevent make from treating additional arguments as files
%:
	@:
