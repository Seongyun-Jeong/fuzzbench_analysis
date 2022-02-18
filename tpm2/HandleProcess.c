// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// THIS CODE IS GENERATED - DO NOT MODIFY!

#include "tpm_generated.h"
#include "HandleProcess_fp.h"
#include "Implementation.h"
#include "TPM_Types.h"

TPM_RC ParseHandleBuffer(TPM_CC command_code,
                         BYTE** request_handle_buffer_start,
                         INT32* request_buffer_remaining_size,
                         TPM_HANDLE request_handles[],
                         UINT32* num_request_handles) {
  TPM_RC result = TPM_RC_SUCCESS;
  *num_request_handles = 0;

  if (command_code & TPM_CCE_BIT_MASK) {
    switch (command_code) {
#if IS_CCE_ENABLED(PolicyFidoSigned)
    case TPM_CCE_PolicyFidoSigned:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS)
        return result;

      ++(*num_request_handles);
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS)
        return result;

      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
    default:
      break;
    }
    return TPM_RC_COMMAND_CODE;
  }

  switch (command_code) {
#if IS_CC_ENABLED(ActivateCredential)
    case TPM_CC_ActivateCredential:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Certify)
    case TPM_CC_Certify:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(CertifyCreation)
    case TPM_CC_CertifyCreation:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ChangeEPS)
    case TPM_CC_ChangeEPS:
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ChangePPS)
    case TPM_CC_ChangePPS:
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Clear)
    case TPM_CC_Clear:
      result = TPMI_RH_CLEAR_Unmarshal(
          (TPMI_RH_CLEAR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ClearControl)
    case TPM_CC_ClearControl:
      result = TPMI_RH_CLEAR_Unmarshal(
          (TPMI_RH_CLEAR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ClockRateAdjust)
    case TPM_CC_ClockRateAdjust:
      result = TPMI_RH_PROVISION_Unmarshal(
          (TPMI_RH_PROVISION*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ClockSet)
    case TPM_CC_ClockSet:
      result = TPMI_RH_PROVISION_Unmarshal(
          (TPMI_RH_PROVISION*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Commit)
    case TPM_CC_Commit:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ContextLoad)
    case TPM_CC_ContextLoad:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ContextSave)
    case TPM_CC_ContextSave:
      result = TPMI_DH_CONTEXT_Unmarshal(
          (TPMI_DH_CONTEXT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Create)
    case TPM_CC_Create:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(CreatePrimary)
    case TPM_CC_CreatePrimary:
      result = TPMI_RH_HIERARCHY_Unmarshal(
          (TPMI_RH_HIERARCHY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(DictionaryAttackLockReset)
    case TPM_CC_DictionaryAttackLockReset:
      result = TPMI_RH_LOCKOUT_Unmarshal(
          (TPMI_RH_LOCKOUT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(DictionaryAttackParameters)
    case TPM_CC_DictionaryAttackParameters:
      result = TPMI_RH_LOCKOUT_Unmarshal(
          (TPMI_RH_LOCKOUT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Duplicate)
    case TPM_CC_Duplicate:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ECC_Parameters)
    case TPM_CC_ECC_Parameters:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ECDH_KeyGen)
    case TPM_CC_ECDH_KeyGen:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ECDH_ZGen)
    case TPM_CC_ECDH_ZGen:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(EC_Ephemeral)
    case TPM_CC_EC_Ephemeral:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(EncryptDecrypt)
    case TPM_CC_EncryptDecrypt:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(EventSequenceComplete)
    case TPM_CC_EventSequenceComplete:
      result = TPMI_DH_PCR_Unmarshal(
          (TPMI_DH_PCR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(EvictControl)
    case TPM_CC_EvictControl:
      result = TPMI_RH_PROVISION_Unmarshal(
          (TPMI_RH_PROVISION*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(FieldUpgradeData)
    case TPM_CC_FieldUpgradeData:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(FieldUpgradeStart)
    case TPM_CC_FieldUpgradeStart:
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(FirmwareRead)
    case TPM_CC_FirmwareRead:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(FlushContext)
    case TPM_CC_FlushContext:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(GetCapability)
    case TPM_CC_GetCapability:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(GetCommandAuditDigest)
    case TPM_CC_GetCommandAuditDigest:
      result = TPMI_RH_ENDORSEMENT_Unmarshal(
          (TPMI_RH_ENDORSEMENT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(GetRandom)
    case TPM_CC_GetRandom:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(GetSessionAuditDigest)
    case TPM_CC_GetSessionAuditDigest:
      result = TPMI_RH_ENDORSEMENT_Unmarshal(
          (TPMI_RH_ENDORSEMENT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_SH_HMAC_Unmarshal(
          (TPMI_SH_HMAC*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(GetTestResult)
    case TPM_CC_GetTestResult:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(GetTime)
    case TPM_CC_GetTime:
      result = TPMI_RH_ENDORSEMENT_Unmarshal(
          (TPMI_RH_ENDORSEMENT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(HMAC)
    case TPM_CC_HMAC:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(HMAC_Start)
    case TPM_CC_HMAC_Start:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Hash)
    case TPM_CC_Hash:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(HashSequenceStart)
    case TPM_CC_HashSequenceStart:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(HierarchyChangeAuth)
    case TPM_CC_HierarchyChangeAuth:
      result = TPMI_RH_HIERARCHY_AUTH_Unmarshal(
          (TPMI_RH_HIERARCHY_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(HierarchyControl)
    case TPM_CC_HierarchyControl:
      result = TPMI_RH_HIERARCHY_Unmarshal(
          (TPMI_RH_HIERARCHY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Import)
    case TPM_CC_Import:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(IncrementalSelfTest)
    case TPM_CC_IncrementalSelfTest:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Load)
    case TPM_CC_Load:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(LoadExternal)
    case TPM_CC_LoadExternal:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(MakeCredential)
    case TPM_CC_MakeCredential:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_Certify)
    case TPM_CC_NV_Certify:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_ChangeAuth)
    case TPM_CC_NV_ChangeAuth:
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_DefineSpace)
    case TPM_CC_NV_DefineSpace:
      result = TPMI_RH_PROVISION_Unmarshal(
          (TPMI_RH_PROVISION*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_Extend)
    case TPM_CC_NV_Extend:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_GlobalWriteLock)
    case TPM_CC_NV_GlobalWriteLock:
      result = TPMI_RH_PROVISION_Unmarshal(
          (TPMI_RH_PROVISION*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_Increment)
    case TPM_CC_NV_Increment:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_Read)
    case TPM_CC_NV_Read:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_ReadLock)
    case TPM_CC_NV_ReadLock:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_ReadPublic)
    case TPM_CC_NV_ReadPublic:
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_SetBits)
    case TPM_CC_NV_SetBits:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_UndefineSpace)
    case TPM_CC_NV_UndefineSpace:
      result = TPMI_RH_PROVISION_Unmarshal(
          (TPMI_RH_PROVISION*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_UndefineSpaceSpecial)
    case TPM_CC_NV_UndefineSpaceSpecial:
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_Write)
    case TPM_CC_NV_Write:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(NV_WriteLock)
    case TPM_CC_NV_WriteLock:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ObjectChangeAuth)
    case TPM_CC_ObjectChangeAuth:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PCR_Allocate)
    case TPM_CC_PCR_Allocate:
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PCR_Event)
    case TPM_CC_PCR_Event:
      result = TPMI_DH_PCR_Unmarshal(
          (TPMI_DH_PCR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PCR_Extend)
    case TPM_CC_PCR_Extend:
      result = TPMI_DH_PCR_Unmarshal(
          (TPMI_DH_PCR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PCR_Read)
    case TPM_CC_PCR_Read:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PCR_Reset)
    case TPM_CC_PCR_Reset:
      result = TPMI_DH_PCR_Unmarshal(
          (TPMI_DH_PCR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PCR_SetAuthPolicy)
    case TPM_CC_PCR_SetAuthPolicy:
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_PCR_Unmarshal(
          (TPMI_DH_PCR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PCR_SetAuthValue)
    case TPM_CC_PCR_SetAuthValue:
      result = TPMI_DH_PCR_Unmarshal(
          (TPMI_DH_PCR*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PP_Commands)
    case TPM_CC_PP_Commands:
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyAuthValue)
    case TPM_CC_PolicyAuthValue:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyAuthorize)
    case TPM_CC_PolicyAuthorize:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyCommandCode)
    case TPM_CC_PolicyCommandCode:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyCounterTimer)
    case TPM_CC_PolicyCounterTimer:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyCpHash)
    case TPM_CC_PolicyCpHash:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyDuplicationSelect)
    case TPM_CC_PolicyDuplicationSelect:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyGetDigest)
    case TPM_CC_PolicyGetDigest:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyLocality)
    case TPM_CC_PolicyLocality:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyNV)
    case TPM_CC_PolicyNV:
      result = TPMI_RH_NV_AUTH_Unmarshal(
          (TPMI_RH_NV_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_RH_NV_INDEX_Unmarshal(
          (TPMI_RH_NV_INDEX*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyNameHash)
    case TPM_CC_PolicyNameHash:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyNvWritten)
    case TPM_CC_PolicyNvWritten:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyOR)
    case TPM_CC_PolicyOR:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyPCR)
    case TPM_CC_PolicyPCR:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyPassword)
    case TPM_CC_PolicyPassword:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyPhysicalPresence)
    case TPM_CC_PolicyPhysicalPresence:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyRestart)
    case TPM_CC_PolicyRestart:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicySecret)
    case TPM_CC_PolicySecret:
      result = TPMI_DH_ENTITY_Unmarshal(
          (TPMI_DH_ENTITY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicySigned)
    case TPM_CC_PolicySigned:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(PolicyTicket)
    case TPM_CC_PolicyTicket:
      result = TPMI_SH_POLICY_Unmarshal(
          (TPMI_SH_POLICY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Quote)
    case TPM_CC_Quote:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(RSA_Decrypt)
    case TPM_CC_RSA_Decrypt:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(RSA_Encrypt)
    case TPM_CC_RSA_Encrypt:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ReadClock)
    case TPM_CC_ReadClock:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ReadPublic)
    case TPM_CC_ReadPublic:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Rewrap)
    case TPM_CC_Rewrap:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(SelfTest)
    case TPM_CC_SelfTest:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(SequenceComplete)
    case TPM_CC_SequenceComplete:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(SequenceUpdate)
    case TPM_CC_SequenceUpdate:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(SetAlgorithmSet)
    case TPM_CC_SetAlgorithmSet:
      result = TPMI_RH_PLATFORM_Unmarshal(
          (TPMI_RH_PLATFORM*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(SetCommandCodeAuditStatus)
    case TPM_CC_SetCommandCodeAuditStatus:
      result = TPMI_RH_PROVISION_Unmarshal(
          (TPMI_RH_PROVISION*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(SetPrimaryPolicy)
    case TPM_CC_SetPrimaryPolicy:
      result = TPMI_RH_HIERARCHY_AUTH_Unmarshal(
          (TPMI_RH_HIERARCHY_AUTH*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Shutdown)
    case TPM_CC_Shutdown:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Sign)
    case TPM_CC_Sign:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(StartAuthSession)
    case TPM_CC_StartAuthSession:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      result = TPMI_DH_ENTITY_Unmarshal(
          (TPMI_DH_ENTITY*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, TRUE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Startup)
    case TPM_CC_Startup:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(StirRandom)
    case TPM_CC_StirRandom:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(TestParms)
    case TPM_CC_TestParms:
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(Unseal)
    case TPM_CC_Unseal:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(VerifySignature)
    case TPM_CC_VerifySignature:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
#if IS_CC_ENABLED(ZGen_2Phase)
    case TPM_CC_ZGen_2Phase:
      result = TPMI_DH_OBJECT_Unmarshal(
          (TPMI_DH_OBJECT*)&request_handles[*num_request_handles],
          request_handle_buffer_start, request_buffer_remaining_size, FALSE);
      if (result != TPM_RC_SUCCESS) {
        return result;
      }
      ++(*num_request_handles);
      return TPM_RC_SUCCESS;
#endif
    default:
      return TPM_RC_COMMAND_CODE;
  }
}