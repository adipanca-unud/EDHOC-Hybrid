# ============================================================================
# EDHOC-Hybrid Makefile
# Builds the EDHOC-Hybrid application using uoscore-uedhoc as core library.
# ============================================================================

.DEFAULT_GOAL := all

CC      = gcc
USE_PQCLEAN ?= 1

PROJ_DIR    = $(CURDIR)
SRC_DIR     = $(PROJ_DIR)/src
INC_DIR     = $(PROJ_DIR)/include
BUILD_DIR   = $(PROJ_DIR)/build
LIB_DIR     = $(PROJ_DIR)/lib/uoscore-uedhoc
LIB_BUILD   = $(LIB_DIR)/build
TV_DIR      = $(LIB_DIR)/test_vectors
EXT_DIR     = $(LIB_DIR)/externals

TARGET = $(BUILD_DIR)/edhoc_hybrid

# liboqs directory (used when USE_PQCLEAN=0)
LIBOQS_DIR  = $(PROJ_DIR)/lib/liboqs
LIBOQS_BUILD = $(LIBOQS_DIR)/build

# PQClean directory (used when USE_PQCLEAN=1)
PQCLEAN_DIR       = $(PROJ_DIR)/lib/PQClean
PQCLEAN_KEM_DIR   = $(PQCLEAN_DIR)/crypto_kem/ml-kem-768/clean
PQCLEAN_SIG_DIR   = $(PQCLEAN_DIR)/crypto_sign/ml-dsa-65/clean
PQCLEAN_COMMON_DIR= $(PQCLEAN_DIR)/common
PQCLEAN_KEM_SRCS   = $(wildcard $(PQCLEAN_KEM_DIR)/*.c)
PQCLEAN_SIG_SRCS   = $(wildcard $(PQCLEAN_SIG_DIR)/*.c)
PQCLEAN_COMMON_SRCS= $(wildcard $(PQCLEAN_COMMON_DIR)/*.c)

# Source files
APP_SRCS  = $(SRC_DIR)/main.c
APP_SRCS += $(SRC_DIR)/edhoc_common.c
APP_SRCS += $(SRC_DIR)/edhoc_type0_classic.c
APP_SRCS += $(SRC_DIR)/edhoc_type3_classic.c
APP_SRCS += $(SRC_DIR)/edhoc_pq_kem.c
APP_SRCS += $(SRC_DIR)/edhoc_type0_pq.c
APP_SRCS += $(SRC_DIR)/edhoc_type3_pq.c
APP_SRCS += $(SRC_DIR)/edhoc_type3_hybrid.c
APP_SRCS += $(SRC_DIR)/edhoc_benchmark.c
APP_SRCS += $(SRC_DIR)/crypto_libsodium.c

TV_SRCS = $(TV_DIR)/edhoc_test_vectors_rfc9529.c

ZCBOR_SRCS  = $(EXT_DIR)/zcbor/src/zcbor_decode.c
ZCBOR_SRCS += $(EXT_DIR)/zcbor/src/zcbor_common.c
ZCBOR_SRCS += $(EXT_DIR)/zcbor/src/zcbor_encode.c

MBEDTLS_SRCS = $(wildcard $(EXT_DIR)/mbedtls/library/*.c)

APP_OBJS       = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(APP_SRCS))
TV_OBJS        = $(patsubst $(TV_DIR)/%.c,$(BUILD_DIR)/tv_%.o,$(TV_SRCS))
ZCBOR_OBJS     = $(patsubst $(EXT_DIR)/zcbor/src/%.c,$(BUILD_DIR)/zcbor_%.o,$(ZCBOR_SRCS))
MBEDTLS_OBJS   = $(patsubst $(EXT_DIR)/mbedtls/library/%.c,$(BUILD_DIR)/mbedtls_%.o,$(MBEDTLS_SRCS))

PQCLEAN_KEM_OBJS    = $(patsubst $(PQCLEAN_KEM_DIR)/%.c,$(BUILD_DIR)/pqclean_kem_%.o,$(PQCLEAN_KEM_SRCS))
PQCLEAN_SIG_OBJS    = $(patsubst $(PQCLEAN_SIG_DIR)/%.c,$(BUILD_DIR)/pqclean_sig_%.o,$(PQCLEAN_SIG_SRCS))
PQCLEAN_COMMON_OBJS = $(patsubst $(PQCLEAN_COMMON_DIR)/%.c,$(BUILD_DIR)/pqclean_common_%.o,$(PQCLEAN_COMMON_SRCS))

OBJS = $(APP_OBJS) $(TV_OBJS) $(ZCBOR_OBJS) $(MBEDTLS_OBJS)

ifeq ($(USE_PQCLEAN),1)
OBJS += $(PQCLEAN_KEM_OBJS) $(PQCLEAN_SIG_OBJS) $(PQCLEAN_COMMON_OBJS)
endif

LIB_A = $(LIB_BUILD)/libuoscore-uedhoc.a

CFLAGS  = -std=c11 -g -O2
CFLAGS += -DUNIT_TEST -DZCBOR -DZCBOR_CANONICAL -DOSCORE_NVM_SUPPORT
CFLAGS += -DLIBSODIUM -DMBEDTLS
CFLAGS += -DEAD_SIZE=0 -DC_I_SIZE=1 -DC_R_SIZE=1
CFLAGS += -DID_CRED_R_SIZE=296 -DID_CRED_I_SIZE=296
CFLAGS += -DCRED_R_SIZE=293 -DCRED_I_SIZE=293
CFLAGS += -DSUITES_I_SIZE=1
CFLAGS += -Wno-unused-parameter -Wno-sign-conversion -Wno-conversion
CFLAGS += -Wno-cast-qual -Wno-missing-field-initializers -Wno-pointer-arith

# PQClean sources benefit from -O3 (ML-KEM-768/ML-DSA-65 lattice math)
PQCLEAN_CFLAGS = $(subst -O2,-O3,$(CFLAGS))

C_INCLUDES  = -I$(INC_DIR)
C_INCLUDES += -I$(LIB_DIR)/inc
C_INCLUDES += -I$(TV_DIR)
C_INCLUDES += -I$(EXT_DIR)/mbedtls/library
C_INCLUDES += -I$(EXT_DIR)/mbedtls/include
C_INCLUDES += -I$(EXT_DIR)/mbedtls/include/mbedtls
C_INCLUDES += -I$(EXT_DIR)/mbedtls/include/psa
C_INCLUDES += -I$(EXT_DIR)/zcbor/include

ifeq ($(USE_PQCLEAN),1)
C_INCLUDES += -I$(PQCLEAN_DIR)
C_INCLUDES += -I$(PQCLEAN_COMMON_DIR)
C_INCLUDES += -I$(PQCLEAN_KEM_DIR)
C_INCLUDES += -I$(PQCLEAN_SIG_DIR)
CFLAGS += -DUSE_PQCLEAN
else
C_INCLUDES += -I$(LIBOQS_BUILD)/include
endif

ifeq ($(USE_PQCLEAN),1)
LDFLAGS  = -L$(LIB_BUILD) -luoscore-uedhoc -lsodium -lpthread -lm
else
LDFLAGS  = -L$(LIB_BUILD) -luoscore-uedhoc -L$(LIBOQS_BUILD)/lib -loqs -lsodium -lpthread -lm
endif

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

$(BUILD_DIR)/mbedtls_%.o: $(EXT_DIR)/mbedtls/library/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/pqclean_kem_%.o: $(PQCLEAN_KEM_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(PQCLEAN_CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/pqclean_sig_%.o: $(PQCLEAN_SIG_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(PQCLEAN_CFLAGS) $(C_INCLUDES) -c $< -o $@

$(BUILD_DIR)/pqclean_common_%.o: $(PQCLEAN_COMMON_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(PQCLEAN_CFLAGS) $(C_INCLUDES) -c $< -o $@

run: all
	@$(TARGET)

clean:
	rm -f $(BUILD_DIR)/main.o $(BUILD_DIR)/edhoc_common.o
	rm -f $(BUILD_DIR)/edhoc_type0_classic.o $(BUILD_DIR)/edhoc_type3_classic.o
	rm -f $(BUILD_DIR)/edhoc_pq_kem.o $(BUILD_DIR)/edhoc_type0_pq.o $(BUILD_DIR)/edhoc_type3_pq.o
	rm -f $(BUILD_DIR)/edhoc_type3_hybrid.o
	rm -f $(BUILD_DIR)/edhoc_type3_hybrid.o
	rm -f $(BUILD_DIR)/edhoc_benchmark_socket.o
	rm -f $(BUILD_DIR)/pqclean_*.o
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
