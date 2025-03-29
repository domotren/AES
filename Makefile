include colors.mk

BUILD_SUCCESS = $(BOLD)$(GREEN)$(CHECKMARK)$(RESET)
BUILD_ERROR   = $(BOLD)$(RED)$(CROSSMARK)$(RESET)

CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -MMD
INCLUDES = -Iinclude
(LDFLAGS =)
(LIBS =)

SRC_DIR = src
MAIN_DIR = main
TEST_DIR = test
BUILD_DIR = build
BUILD_OBJ_DIR = $(BUILD_DIR)/obj
BUILD_MAIN_DIR = $(BUILD_DIR)/main
BUILD_TEST_DIR = $(BUILD_DIR)/test

SRCS = $(wildcard $(SRC_DIR)/*.c)
MAIN_SRC = $(wildcard $(MAIN_DIR)/*.c)
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)

OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_OBJ_DIR)/%.o,$(SRCS))
MAIN_OBJS = $(patsubst $(MAIN_DIR)/%.c,$(BUILD_OBJ_DIR)/%.o,$(MAIN_SRC))
TEST_OBJS = $(patsubst $(TEST_DIR)/%.c,$(BUILD_OBJ_DIR)/%.o,$(TEST_SRC))

TARGET_MAIN = $(BUILD_MAIN_DIR)/aes_main
TARGET_TEST = $(BUILD_TEST_DIR)/aes_test

vpath %c $(SRC_DIR) $(MAIN_DIR) $(TEST_DIR)

all: $(TARGET_MAIN) $(TARGET_TEST)

$(TARGET_MAIN): $(OBJS) $(MAIN_OBJS) | $(BUILD_MAIN_DIR)
	@if ! $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS); then \
		echo "$(BUILD_ERROR) Build main program failed"; \
		exit 1; \
	fi
	@echo "$(BUILD_SUCCESS) Build main program successful"

$(TARGET_TEST): $(OBJS) $(TEST_OBJS) | $(BUILD_TEST_DIR)
	@if ! $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS); then \
		echo "$(BUILD_ERROR) Build test program failed"; \
		exit 1; \
	fi
	@echo "$(BUILD_SUCCESS) Build test program successful"

$(BUILD_OBJ_DIR)/%.o: %.c | $(BUILD_OBJ_DIR)
	@if ! $(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@; then \
		echo "$(BUILD_ERROR) Failed to compile $<"; \
		exit 1; \
	fi
	@echo "$(BUILD_SUCCESS) $< compiled"

$(BUILD_DIR) $(BUILD_OBJ_DIR) $(BUILD_MAIN_DIR) $(BUILD_TEST_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

-include $(OBJS:.o=.d)
-include $(MAIN_OBJS:.o=.d)
-include $(TEST_OBJS:.o=.d)

.PHONY: all clean
