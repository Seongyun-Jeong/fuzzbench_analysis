/*
 * Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "MemoryLib_fp.h"
#include "PolicyFidoSigned_fp.h"

#if IS_CCE_ENABLED(PolicyFidoSigned)
/*
 * Marshal output data of PolicyFidoSigned command.
 *
 * @param source  input buffer of data to marshal
 * @param tag     Request tag
 * @param buffer  output buffer to write marshalled data
 * @param size    size of marshalled data
 * @return actual size of response excluding the size of the parameter field.
 */
static UINT16
PolicyFidoSigned_Out_Marshal(PolicyFidoSigned_Out* source,
                             TPMI_ST_COMMAND_TAG tag,
                             BYTE** buffer,
                             INT32* size)
{
  if (tag == TPM_ST_SESSIONS) {
    UINT32 param_size = 0;

    /* Add param_size=0 to indicate size of the parameter area. */
    UINT32_Marshal(&param_size, buffer, size);
  }

  return 0;
}

/*
 * Unmarshal input data of PolicyFidoSigned command.
 *
 * @param target       input buffer to unmarshal
 * @param req_handles
 * @param buffer       output buffer to write unmarshalled data
 * @param size         size of unmarshalled data.
 * @return TPM_RC_SUCCESS if processed successfully, or
 *         TPM_RC_SIZE if input data size is not correct, or
 *         TPM_RC_SCHEME if Authenticator algorithm is not specified, or
 *         TPM_RC_HASH if hash is missing or wrong.
 *
 *
 */
static TPM_RC
PolicyFidoSigned_In_Unmarshal(PolicyFidoSigned_In* target,
                              TPM_HANDLE req_handles[],
                              BYTE** buffer,
                              INT32* size)
{
  TPM_RC result = TPM_RC_SUCCESS;
  int i;

  /* Get request handles from req_handles array. */
  target->authObject = req_handles[0];
  target->policySession = req_handles[1];

  result = UINT16_Unmarshal(&target->authData.t.size, buffer, size);
  if (result != TPM_RC_SUCCESS)
    return result;

  if (target->authData.t.size > MAX_AUTH_DATA_SIZE ||
      target->authData.t.size == 0)
    return TPM_RC_SIZE;

  /* Unmarshall authData. */
  for (i = 0; i < target->authData.t.size; ++i) {
    result = BYTE_Unmarshal(&(target->authData.t.buffer[i]), buffer, size);
    if (result != TPM_RC_SUCCESS)
      return result;
  }

  /* Unmarshal request parameters. */
  result = UINT16_Unmarshal(&target->authDataDescrCount, buffer, size);
  if (result != TPM_RC_SUCCESS)
    return result;

  if (target->authDataDescrCount > sizeof(target->authDataDescr))
    return TPM_RC_SIZE;

  /* Unmarshall authDataDescr. */
  for (i = 0; i < target->authDataDescrCount; i++) {
    result = UINT16_Unmarshal(&(target->authDataDescr[i].offset), buffer, size);
    if (result != TPM_RC_SUCCESS)
      return result;

    result = UINT16_Unmarshal(&(target->authDataDescr[i].size), buffer, size);
    if (result != TPM_RC_SUCCESS)
      return result;

    /* The range size should be non-zero. */
    if (target->authDataDescr[i].size == 0)
      return TPM_RC_VALUE;

    /* The range is beyond the actual authData string */
    if (target->authDataDescr[i].offset + target->authDataDescr[i].size >
        target->authData.t.size)
      return TPM_RC_VALUE;
  }

  result = TPMT_SIGNATURE_Unmarshal(&target->auth, buffer, size);
  if (result != TPM_RC_SUCCESS)
    return result;

  /* Size should be zero. */
  if (*size)
    return TPM_RC_SIZE;

  return result;
}

TPM_RC Exec_PolicyFidoSigned(TPMI_ST_COMMAND_TAG tag,
                             BYTE** req_param_buffer,
                             INT32* req_param_buffer_size,
                             TPM_HANDLE req_handles[],
                             UINT32* resp_handle_buf_size,
                             UINT32* resp_param_buf_size)
{
  TPM_RC result = TPM_RC_SUCCESS;
  PolicyFidoSigned_In in;
  PolicyFidoSigned_Out out;
  BYTE* resp_buf;
  INT32 resp_buf_size;
  const INT32 resp_header_size = sizeof(TPM_ST) + sizeof(UINT32) +
                                 sizeof(TPM_RC);

  *resp_handle_buf_size = 0;
  *resp_param_buf_size = 0;

  /* Unmarshal request parameters to input structure. */
  result = PolicyFidoSigned_In_Unmarshal(&in,
                                         req_handles,
                                         req_param_buffer,
                                         req_param_buffer_size);
  if (result != TPM_RC_SUCCESS)
    return result;

  /* Execute command. */
  result = TPM2_PolicyFidoSigned(&in, &out);
  if (result != TPM_RC_SUCCESS)
    return result;

  /* Marshal output structure to global response buffer. */
  resp_buf = MemoryGetResponseBuffer(TPM_CCE_PolicyFidoSigned)
             + resp_header_size;
  resp_buf_size = MAX_RESPONSE_SIZE - resp_header_size;

  *resp_param_buf_size = PolicyFidoSigned_Out_Marshal(&out,
                                                      tag,
                                                      &resp_buf,
                                                      &resp_buf_size);
  return TPM_RC_SUCCESS;
}
#endif    /* IS_CCE_ENABLED(PolicyFidoSigned) */
