#!/bin/bash

# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex

v=$1
out=$2

mkdir -p "${out}"
sed -e "s/@BSLOT@/${v}/g" libtpm2.pc.in > "${out}/libtpm2.pc"
