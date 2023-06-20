#!/bin/bash

set -x
md5sum recursive.zlib
dd if=recursive.zlib bs=1 skip=8 count=213 2>/dev/null | openssl zlib -d | md5sum
dd if=recursive.zlib bs=1 skip=8 count=213 2>/dev/null | openssl zlib -d | dd bs=1 skip=8 count=213 2>/dev/null | openssl zlib -d | md5sum
