# ============================================================================
# EDHOC-Hybrid Makefile
# Builds the EDHOC-Hybrid application using uoscore-uedhoc as core library.
# ============================================================================

.DEFAULT_GOAL := all

CC      = gcc

PROJ_DIR    = $(CURDIR)
SRC_DIR     = $(PROJ_DIR)/src
INC_DIR     = $(PROJ_DIR)/include
BUILD_DIR   = $(PROJ_DIR)/build
LIB_DIR     = $(PROJ_DIR)/lib/uoscore-uedhoc
LIB_BUILD   = $(LIB_DIR)/build
TV_DIR      = $(LIB_DIR)/test_vectors
EXT_DIR     = $(LIB_DIR)/externals

TARGET = $(BUILD_DIR)/edhoc_hybrid

# Source files
APP_SRCS  = $(SRC_DIR)/main.c
APP_SRCS += $(SRC_DIR)/edhoc_common.c
APP_SRCS += $(SRC_DIR)/edhoc_type0_classic.c
APP_SRCS += $(SRC_DIR)/edhoc_type3_classic.c

TV_SRCS = $(TV_DIR)/edhoc_test_vectors_rfc9529.c

ZCBOR_SRCS  = $(EXT_DIR)/zcbor/src/zcbor_decode.c
ZCBOR_SRCS += $(EXT_DIR)/zcbor/src/zcbor_common.c
ZCBOR_SRCS += $(EXT_DIR)/zcbor/src/zcbor_encode.c

COMPACT25519_SRCS  = $(EXT_DIR)/compact25519/src/compact_x25519.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/compact_ed25519.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/compact_wipe.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/c25519/sha512.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/c25519/f25519.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/c25519/edsign.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/c25519/ed25519.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/c25519/c25519.c
COMPACT25519_SRCS += $(EXT_DIR)/compact25519/src/c25519/fprime.c

MBEDTLS_SRCS = $(wildcard $(EXT_DIR)/mbedtls/library/*.c)

APP_OBJS       = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(APP_SRCS))
TV_OBJS        = $(patsubst $(TV_DIR)/%.c,$(BUILD_DIR)/tv_%.o,$(TV_SRCS))
ZCBOR_OBJS     = $(patsubst $(EXT_DIR)/zcbor/src/%.c,$(BUILD_DIR)/zcbor_%.o,$(ZCBOR_SRCS))
COMPACT_OBJS   = $(patsubst %.c,$(BUILD_DIR)/c25519_%.o,$(notdir $(COMPACT25519_SRCS)))
MBEDTLS_OBJS   = $(patsubst $(EXT_DIR)/mbedtls/library/%.c,$(BUILD_DIR)/mbedtls_%.o,$(MBEDTLS_SRCS))

OBJS = $(APP_OBJS) $(TV_OBJS) $(ZCBOR_OBJS) $(COMPACT_OBJS) $(MBEDTLS_OBJS)

LIB_A = $(LIB_BUILD)/libuoscore-uedhoc.a

C_INCLUDES  = -I$(INC_DIR)
C_INCLUDES += -I$(LIB_DIR)/inc
C_INCLUDES += -I$(TV_DIR)
C_INCLUDES += -I$(EXT_DIR)/compact25519/src/c25519/
C_INCLUDES += -I$(EXT_DIR)/compact25519/src/
C_INCLUDES += -I$(EXT_DIR)/mbedtls/library
C_INCLUDES += -I$(EXT_DIR)/mbedtls/include
C_INCLUDES += -I$(EXT_DIR)/mbedtls/include/mbedtls
C_INCLUDES += -I$(EXT_DIR)/mbedtls/include/psa
C_INCLUDES += -I$(EXT_DIR)/zcbor/include

CFLAGS  = -std=c11 -g3 -O0
CFLAGS += -DUNIT_TEST -DZCBOR -DZCBOR_CANONICAL -DOSCORE_NVM_SUPPORT
CFLAGS += -DCOMPACT25519 -DMBEDTLS
CFLAGS += -DEAD_SIZE=0 -DC_I_SIZE=1 -DC_R_SIZE=1
CFLAGS += -DID_CRED_R_SIZE=296 -DID_CRED_I_SIZE=296
CFLAGS += -DCRED_R_SIZE=293 -DCRED_I_SIZE=293
CFLAGS += -DSUITES_I_SIZE=1
CFLAGS += -Wno-unused-parameter -Wno-sign-conversion -Wno-conversion
CFLAGS += -Wno-cast-qual -Wno-missing-field-initializers -Wno-pointer-arith

LDFLAGS  = -L$(LIB_BUILD) -luoscore-uedhoc -lpthread -lm

.PHONY: all clean lib lib-clean run help

all: lib $(TARGET)
	@echo ''
	@echo '  Build complete: $(TARGET)'
	@echo '  Run with: $(TARGET)'
	@echo ''

lib: $(LIB_A)

$(LIB_A):
	@echo '=== Building uoscore-uedhoc library ==='
	$(MAKE) -C $(LIB_DIR)

$(TARGET): $(OBJS) $(LIB_A)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo '=== Linked: $@ ==='

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/tv_%.o: $(TV_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/zcbor_%.o: $(EXT_DIR)/zcbor/src/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/c25519_%.o: $(EXT_DIR)/compact25519/src/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/c25519_%.o: $(EXT_DIR)/compact25519/src/c25519/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/mbedtls_%.o: $(EXT_DIR)/mbedtls/library/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(C_INCLUDES) -c $< -o $@

run: all
	@$(TARGET)

clean:
	rm -f $(BUILD_DIR)/main.o $(BUILD_DIR)/edhoc_common.o
	rm -f $(BUILD_DIR)/edhoc_type0_classic.o $(BUILD_DIR)/edhoc_type3_classic.o
	rm -f $(BUILD_DIR)/tv_*.o $(TARGET)

lib-clean:
	$(MAKE) -C $(LIB_DIR) clean
	rm -rf $(BUILD_DIR)

help:
	@echo ''
	@echo '  EDHOC-Hybrid Build System'
	@echo '  ========================='
	@echo ''
	@echo '  make          - Build library + externals + application'
	@echo '  make lib      - Build only the uoscore-uedhoc library'
	@echo '  make run      - Build and run the application'
	@echo '  make clean    - Clean application object files'
	@echo '  make lib-clean - Clean everything (library + application)'
	@echo '  make help     - Show this help'
	@echo ''
