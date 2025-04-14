include colors.mk

BUILD_SUCCESS = $(BOLD)$(GREEN)$(CHECKMARK)$(RESET)
BUILD_ERROR   = $(BOLD)$(RED)$(CROSSMARK)$(RESET)

# choose AES bits and mode
# if not specified, enable AES-128 ECB in default
TYPE ?= 128
MODE ?= ECB
CONFIG_FILE := config

SUPPORTED_TYPES := 128 192 256
SUPPORTED_MODES := ECB CBC CTR GCM

ifeq ($(filter $(TYPE), $(SUPPORTED_TYPES)),)
$(error TYPE must be one of: $(SUPPORTED_TYPES))
endif

MODE_UPPER := $(shell echo $(MODE) | tr a-z A-Z)
ifeq ($(filter $(MODE_UPPER), $(SUPPORTED_MODES)),)
$(error MODE must be one of: $(SUPPORTED_MODES))
endif

CFLAGS += -DTYPE_AES_$(TYPE) -DMODE_AES_$(MODE_UPPER)

CC = gcc
CFLAGS += -Wall -Wextra -g -O2 -MMD -fsanitize=address
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

all: $(CONFIG_FILE) $(TARGET_MAIN) $(TARGET_TEST)

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

$(BUILD_OBJ_DIR)/%.o: %.c $(CONFIG_FILE) | $(BUILD_OBJ_DIR)
	@if ! $(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@; then \
		echo "$(BUILD_ERROR) Failed to compile $<"; \
		exit 1; \
	fi
	@echo "$(BUILD_SUCCESS) $< compiled"

$(BUILD_DIR) $(BUILD_OBJ_DIR) $(BUILD_MAIN_DIR) $(BUILD_TEST_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(CONFIG_FILE)

-include $(OBJS:.o=.d)
-include $(MAIN_OBJS:.o=.d)
-include $(TEST_OBJS:.o=.d)

.PHONY: all clean

.PHONY: FORCE
FORCE:

$(CONFIG_FILE): FORCE
	@echo "$(TYPE)-$(MODE)" > $(CONFIG_FILE).tmp
	@if ! cmp -s $(CONFIG_FILE).tmp $(CONFIG_FILE); then \
		mv $(CONFIG_FILE).tmp $(CONFIG_FILE); \
		echo "Config updated";\
	else \
		rm -f $(CONFIG_FILE).tmp; \
		echo "Config unchanged"; \
	fi
