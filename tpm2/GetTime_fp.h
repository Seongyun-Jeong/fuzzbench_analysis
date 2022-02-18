// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// THIS CODE IS GENERATED - DO NOT MODIFY!

#ifndef TPM2_GETTIME_FP_H_
#define TPM2_GETTIME_FP_H_

#include "tpm_generated.h"

typedef struct {
  TPMI_RH_ENDORSEMENT privacyAdminHandle;
  TPMI_DH_OBJECT signHandle;
  TPM2B_DATA qualifyingData;
  TPMT_SIG_SCHEME inScheme;
} GetTime_In;

typedef struct {
  TPM2B_ATTEST timeInfo;
  TPMT_SIGNATURE signature;
} GetTime_Out;

// Executes GetTime with request handles and parameters from
// |in| and computes response handles and parameters to |out|.
TPM_RC TPM2_GetTime(GetTime_In* in, GetTime_Out* out);

// Unmarshals any request parameters starting at |request_parameter_buffer|.
// Executes command. Marshals any response handles and parameters to the
// global response buffer and computes |*response_handle_buffer_size| and
// |*response_parameter_buffer_size|. If |tag| == TPM_ST_SESSIONS, marshals
// parameter_size indicating the size of the parameter area. parameter_size
// field is located between the handle area and parameter area.
TPM_RC Exec_GetTime(TPMI_ST_COMMAND_TAG tag,
                    BYTE** request_parameter_buffer,
                    INT32* request_parameter_buffer_size,
                    TPM_HANDLE request_handles[],
                    UINT32* response_handle_buffer_size,
                    UINT32* response_parameter_buffer_size);

#endif  // TPM2_GETTIME_FP_H
