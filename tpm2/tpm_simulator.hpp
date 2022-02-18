// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_TPM_SIMULATOR_H_
#define TPM2_TPM_SIMULATOR_H_

namespace tpm2 {

extern "C" {
#include <tpm2/_TPM_Init_fp.h>
#include <tpm2/BaseTypes.h>
#include <tpm2/ExecCommand_fp.h>
#include <tpm2/GetCommandCodeString_fp.h>
#include <tpm2/Platform.h>
#include <tpm2/tpm_generated.h>
#include <tpm2/tpm_manufacture.h>
#include <tpm2/TpmBuildSwitches.h>
#include <tpm2/Manufacture_fp.h>  // NOLINT(build/include_alpha) - needs TpmBuildSwitches.h
}

}  // namespace tpm2

#endif  // TPM2_TPM_SIMULATOR_H_
