#!/bin/sh

set -e

# Uncomment the set -v line for debugging
# set -v

# Test compression flags and check that they work
zstd file                 ; zstd -t file.zst
zstd -f file              ; zstd -t file.zst
zstd -f -z file           ; zstd -t file.zst
zstd -f -k file           ; zstd -t file.zst
zstd -f -C file           ; zstd -t file.zst
zstd -f --check file      ; zstd -t file.zst
zstd -f --no-check file   ; zstd -t file.zst
zstd -f -- file           ; zstd -t file.zst

# Test output file compression
zstd -o file-out.zst ; zstd -t file-out.zst
zstd -fo file-out.zst; zstd -t file-out.zst

# Test compression to stdout
zstd -c file       | zstd -t
zstd --stdout file | zstd -t
println bob | zstd | zstd -t

# Test --rm
cp file file-rm
zstd --rm file-rm; zstd -t file-rm.zst
test ! -f file-rm
