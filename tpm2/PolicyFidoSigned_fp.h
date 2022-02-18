// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_POLICYFIDOSIGNED_FP_H_
#define TPM2_POLICYFIDOSIGNED_FP_H_

#include "tpm_generated.h"

/*
 * Data range expression to select the segments in authenticatorData
 * for policy digest extension
 */
typedef struct {
  UINT16 offset;
  UINT16 size;
} DATA_OFFSET;

/*
 * Input data structure of PolicyFidoSigned command
 */
typedef struct {
  TPMI_DH_OBJECT authObject;
  TPMI_SH_POLICY policySession;

  TPM2B_AUTHDATA authData;
  UINT16 authDataDescrCount;
  DATA_OFFSET authDataDescr[MAX_AUTH_DATA_DESCR_COUNT];

  TPMT_SIGNATURE auth;
} PolicyFidoSigned_In;

/*
 * Output data structure of PolicyFidoSigned command
 */
typedef struct {

  /* No response parameter */

} PolicyFidoSigned_Out;

/*
 * Process PolicyFidoSigned command
 *
 * @param in   input buffer of request
 * @param out  output buffer of response
 * @return TPM_RC_SUCCESS or
 *         TPM_RC_SIGNATURE if the signature is not genuine, or
 *         TPM_RC_SCHEME if the scheme is not supported, or
 *         TPM_RC_HANDLE if an HMAC key was selected but the private part of
 *                          the key is not.
 */
TPM_RC TPM2_PolicyFidoSigned(PolicyFidoSigned_In* in,
                             PolicyFidoSigned_Out* out);

/*
 * Execute PolicyFidoSigned command, including unmarshaling/marshaling and
 * processing
 *
 * Unmarshals any request parameters starting at |request_parameter_buffer|.
 * Executes command. Marshals any response handles and parameters to the
 * global response buffer and computes |*response_handle_buffer_size| and
 * |*response_parameter_buffer_size|. If |tag| == TPM_ST_SESSIONS, marshals
 * parameter_size indicating the size of the parameter area. parameter_size
 * field is located between the handle area and parameter area.
 *
 * @param tag                     command tag
 * @param req_param_buffer        Buffer of request parameters
 * @param req_param_buffer_size   Buffer size of request parameters
 * @param req_handles             Array of request handles
 * @param resp_handle_buf_size    Buffer size of handles
 * @param resp_param_buf_size     Buffer size of response parameters
 * @return TPM_RC_SUCCESS if processed successfully, or
 *         non-zero error code otherwise.
 */
TPM_RC Exec_PolicyFidoSigned(TPMI_ST_COMMAND_TAG tag,
                             BYTE** req_param_buffer,
                             INT32* req_param_buffer_size,
                             TPM_HANDLE req_handles[],
                             UINT32* resp_handle_buf_size,
                             UINT32* resp_param_buf_size);

#endif  // TPM2_POLICYFIDOSIGNED_FP_H_