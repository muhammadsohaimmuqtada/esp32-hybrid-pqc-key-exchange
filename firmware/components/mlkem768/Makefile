# Makefile for building ML-KEM-768 shared library on host (Linux / macOS)
CC ?= gcc
CFLAGS ?= -O3 -fPIC -Wall -Wextra -DKYBER_K=3
INCLUDES = -Iinclude -Isrc/ref

SRCS = src/ref/mlkem_wrapper.c \
       src/ref/kem_ref.c \
       src/ref/indcpa_ref.c \
       src/ref/poly_ref.c \
       src/ref/polyvec_ref.c \
       src/ref/ntt_ref.c \
       src/ref/reduce_ref.c \
       src/ref/cbd_ref.c \
       src/ref/verify_ref.c \
       src/ref/symmetric_ref.c \
       src/ref/fips202_ref.c \
       randombytes.c

TARGET = libmlkem.so

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -shared $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
