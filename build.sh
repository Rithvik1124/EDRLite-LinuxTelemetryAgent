#!/bin/bash

set -e

echo "[1/3] Compiling eBPF program..."
clang \
    -g \
    -O2 \
    -target bpf \
    -I. \
    -c trial.bpf.c \
    -o trial.bpf.o

echo "[2/3] Generating skeleton..."
bpftool gen skeleton trial.bpf.o > trial.skel.h

echo "[3/3] Building userspace loader..."
clang \
    -g \
    -O2 \
    trial.c \
    -o trial \
    -lbpf

echo
echo "Build complete."
echo "Generated:"
echo "  trial.bpf.o"
echo "  trial.skel.h"
echo "  loader"
