// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// THIS CODE IS GENERATED - DO NOT MODIFY!

#include "GetCommandCodeString_fp.h"

const char* GetCommandCodeString(TPM_CC command_code) {
  if (command_code & TPM_CCE_BIT_MASK) {
    switch (command_code) {
#if IS_CCE_ENABLED(PolicyFidoSigned)
    case TPM_CCE_PolicyFidoSigned:
      return "PolicyFidoSigned";
#endif
    default:
      break;
    }
    return "Unknown ext command";
  }

  switch (command_code) {
#if IS_CC_ENABLED(ActivateCredential)
    case TPM_CC_ActivateCredential:
      return "ActivateCredential";
#endif
#if IS_CC_ENABLED(Certify)
    case TPM_CC_Certify:
      return "Certify";
#endif
#if IS_CC_ENABLED(CertifyCreation)
    case TPM_CC_CertifyCreation:
      return "CertifyCreation";
#endif
#if IS_CC_ENABLED(ChangeEPS)
    case TPM_CC_ChangeEPS:
      return "ChangeEPS";
#endif
#if IS_CC_ENABLED(ChangePPS)
    case TPM_CC_ChangePPS:
      return "ChangePPS";
#endif
#if IS_CC_ENABLED(Clear)
    case TPM_CC_Clear:
      return "Clear";
#endif
#if IS_CC_ENABLED(ClearControl)
    case TPM_CC_ClearControl:
      return "ClearControl";
#endif
#if IS_CC_ENABLED(ClockRateAdjust)
    case TPM_CC_ClockRateAdjust:
      return "ClockRateAdjust";
#endif
#if IS_CC_ENABLED(ClockSet)
    case TPM_CC_ClockSet:
      return "ClockSet";
#endif
#if IS_CC_ENABLED(Commit)
    case TPM_CC_Commit:
      return "Commit";
#endif
#if IS_CC_ENABLED(ContextLoad)
    case TPM_CC_ContextLoad:
      return "ContextLoad";
#endif
#if IS_CC_ENABLED(ContextSave)
    case TPM_CC_ContextSave:
      return "ContextSave";
#endif
#if IS_CC_ENABLED(Create)
    case TPM_CC_Create:
      return "Create";
#endif
#if IS_CC_ENABLED(CreatePrimary)
    case TPM_CC_CreatePrimary:
      return "CreatePrimary";
#endif
#if IS_CC_ENABLED(DictionaryAttackLockReset)
    case TPM_CC_DictionaryAttackLockReset:
      return "DictionaryAttackLockReset";
#endif
#if IS_CC_ENABLED(DictionaryAttackParameters)
    case TPM_CC_DictionaryAttackParameters:
      return "DictionaryAttackParameters";
#endif
#if IS_CC_ENABLED(Duplicate)
    case TPM_CC_Duplicate:
      return "Duplicate";
#endif
#if IS_CC_ENABLED(ECC_Parameters)
    case TPM_CC_ECC_Parameters:
      return "ECC_Parameters";
#endif
#if IS_CC_ENABLED(ECDH_KeyGen)
    case TPM_CC_ECDH_KeyGen:
      return "ECDH_KeyGen";
#endif
#if IS_CC_ENABLED(ECDH_ZGen)
    case TPM_CC_ECDH_ZGen:
      return "ECDH_ZGen";
#endif
#if IS_CC_ENABLED(EC_Ephemeral)
    case TPM_CC_EC_Ephemeral:
      return "EC_Ephemeral";
#endif
#if IS_CC_ENABLED(EncryptDecrypt)
    case TPM_CC_EncryptDecrypt:
      return "EncryptDecrypt";
#endif
#if IS_CC_ENABLED(EventSequenceComplete)
    case TPM_CC_EventSequenceComplete:
      return "EventSequenceComplete";
#endif
#if IS_CC_ENABLED(EvictControl)
    case TPM_CC_EvictControl:
      return "EvictControl";
#endif
#if IS_CC_ENABLED(FieldUpgradeData)
    case TPM_CC_FieldUpgradeData:
      return "FieldUpgradeData";
#endif
#if IS_CC_ENABLED(FieldUpgradeStart)
    case TPM_CC_FieldUpgradeStart:
      return "FieldUpgradeStart";
#endif
#if IS_CC_ENABLED(FirmwareRead)
    case TPM_CC_FirmwareRead:
      return "FirmwareRead";
#endif
#if IS_CC_ENABLED(FlushContext)
    case TPM_CC_FlushContext:
      return "FlushContext";
#endif
#if IS_CC_ENABLED(GetCapability)
    case TPM_CC_GetCapability:
      return "GetCapability";
#endif
#if IS_CC_ENABLED(GetCommandAuditDigest)
    case TPM_CC_GetCommandAuditDigest:
      return "GetCommandAuditDigest";
#endif
#if IS_CC_ENABLED(GetRandom)
    case TPM_CC_GetRandom:
      return "GetRandom";
#endif
#if IS_CC_ENABLED(GetSessionAuditDigest)
    case TPM_CC_GetSessionAuditDigest:
      return "GetSessionAuditDigest";
#endif
#if IS_CC_ENABLED(GetTestResult)
    case TPM_CC_GetTestResult:
      return "GetTestResult";
#endif
#if IS_CC_ENABLED(GetTime)
    case TPM_CC_GetTime:
      return "GetTime";
#endif
#if IS_CC_ENABLED(HMAC)
    case TPM_CC_HMAC:
      return "HMAC";
#endif
#if IS_CC_ENABLED(HMAC_Start)
    case TPM_CC_HMAC_Start:
      return "HMAC_Start";
#endif
#if IS_CC_ENABLED(Hash)
    case TPM_CC_Hash:
      return "Hash";
#endif
#if IS_CC_ENABLED(HashSequenceStart)
    case TPM_CC_HashSequenceStart:
      return "HashSequenceStart";
#endif
#if IS_CC_ENABLED(HierarchyChangeAuth)
    case TPM_CC_HierarchyChangeAuth:
      return "HierarchyChangeAuth";
#endif
#if IS_CC_ENABLED(HierarchyControl)
    case TPM_CC_HierarchyControl:
      return "HierarchyControl";
#endif
#if IS_CC_ENABLED(Import)
    case TPM_CC_Import:
      return "Import";
#endif
#if IS_CC_ENABLED(IncrementalSelfTest)
    case TPM_CC_IncrementalSelfTest:
      return "IncrementalSelfTest";
#endif
#if IS_CC_ENABLED(Load)
    case TPM_CC_Load:
      return "Load";
#endif
#if IS_CC_ENABLED(LoadExternal)
    case TPM_CC_LoadExternal:
      return "LoadExternal";
#endif
#if IS_CC_ENABLED(MakeCredential)
    case TPM_CC_MakeCredential:
      return "MakeCredential";
#endif
#if IS_CC_ENABLED(NV_Certify)
    case TPM_CC_NV_Certify:
      return "NV_Certify";
#endif
#if IS_CC_ENABLED(NV_ChangeAuth)
    case TPM_CC_NV_ChangeAuth:
      return "NV_ChangeAuth";
#endif
#if IS_CC_ENABLED(NV_DefineSpace)
    case TPM_CC_NV_DefineSpace:
      return "NV_DefineSpace";
#endif
#if IS_CC_ENABLED(NV_Extend)
    case TPM_CC_NV_Extend:
      return "NV_Extend";
#endif
#if IS_CC_ENABLED(NV_GlobalWriteLock)
    case TPM_CC_NV_GlobalWriteLock:
      return "NV_GlobalWriteLock";
#endif
#if IS_CC_ENABLED(NV_Increment)
    case TPM_CC_NV_Increment:
      return "NV_Increment";
#endif
#if IS_CC_ENABLED(NV_Read)
    case TPM_CC_NV_Read:
      return "NV_Read";
#endif
#if IS_CC_ENABLED(NV_ReadLock)
    case TPM_CC_NV_ReadLock:
      return "NV_ReadLock";
#endif
#if IS_CC_ENABLED(NV_ReadPublic)
    case TPM_CC_NV_ReadPublic:
      return "NV_ReadPublic";
#endif
#if IS_CC_ENABLED(NV_SetBits)
    case TPM_CC_NV_SetBits:
      return "NV_SetBits";
#endif
#if IS_CC_ENABLED(NV_UndefineSpace)
    case TPM_CC_NV_UndefineSpace:
      return "NV_UndefineSpace";
#endif
#if IS_CC_ENABLED(NV_UndefineSpaceSpecial)
    case TPM_CC_NV_UndefineSpaceSpecial:
      return "NV_UndefineSpaceSpecial";
#endif
#if IS_CC_ENABLED(NV_Write)
    case TPM_CC_NV_Write:
      return "NV_Write";
#endif
#if IS_CC_ENABLED(NV_WriteLock)
    case TPM_CC_NV_WriteLock:
      return "NV_WriteLock";
#endif
#if IS_CC_ENABLED(ObjectChangeAuth)
    case TPM_CC_ObjectChangeAuth:
      return "ObjectChangeAuth";
#endif
#if IS_CC_ENABLED(PCR_Allocate)
    case TPM_CC_PCR_Allocate:
      return "PCR_Allocate";
#endif
#if IS_CC_ENABLED(PCR_Event)
    case TPM_CC_PCR_Event:
      return "PCR_Event";
#endif
#if IS_CC_ENABLED(PCR_Extend)
    case TPM_CC_PCR_Extend:
      return "PCR_Extend";
#endif
#if IS_CC_ENABLED(PCR_Read)
    case TPM_CC_PCR_Read:
      return "PCR_Read";
#endif
#if IS_CC_ENABLED(PCR_Reset)
    case TPM_CC_PCR_Reset:
      return "PCR_Reset";
#endif
#if IS_CC_ENABLED(PCR_SetAuthPolicy)
    case TPM_CC_PCR_SetAuthPolicy:
      return "PCR_SetAuthPolicy";
#endif
#if IS_CC_ENABLED(PCR_SetAuthValue)
    case TPM_CC_PCR_SetAuthValue:
      return "PCR_SetAuthValue";
#endif
#if IS_CC_ENABLED(PP_Commands)
    case TPM_CC_PP_Commands:
      return "PP_Commands";
#endif
#if IS_CC_ENABLED(PolicyAuthValue)
    case TPM_CC_PolicyAuthValue:
      return "PolicyAuthValue";
#endif
#if IS_CC_ENABLED(PolicyAuthorize)
    case TPM_CC_PolicyAuthorize:
      return "PolicyAuthorize";
#endif
#if IS_CC_ENABLED(PolicyCommandCode)
    case TPM_CC_PolicyCommandCode:
      return "PolicyCommandCode";
#endif
#if IS_CC_ENABLED(PolicyCounterTimer)
    case TPM_CC_PolicyCounterTimer:
      return "PolicyCounterTimer";
#endif
#if IS_CC_ENABLED(PolicyCpHash)
    case TPM_CC_PolicyCpHash:
      return "PolicyCpHash";
#endif
#if IS_CC_ENABLED(PolicyDuplicationSelect)
    case TPM_CC_PolicyDuplicationSelect:
      return "PolicyDuplicationSelect";
#endif
#if IS_CC_ENABLED(PolicyGetDigest)
    case TPM_CC_PolicyGetDigest:
      return "PolicyGetDigest";
#endif
#if IS_CC_ENABLED(PolicyLocality)
    case TPM_CC_PolicyLocality:
      return "PolicyLocality";
#endif
#if IS_CC_ENABLED(PolicyNV)
    case TPM_CC_PolicyNV:
      return "PolicyNV";
#endif
#if IS_CC_ENABLED(PolicyNameHash)
    case TPM_CC_PolicyNameHash:
      return "PolicyNameHash";
#endif
#if IS_CC_ENABLED(PolicyNvWritten)
    case TPM_CC_PolicyNvWritten:
      return "PolicyNvWritten";
#endif
#if IS_CC_ENABLED(PolicyOR)
    case TPM_CC_PolicyOR:
      return "PolicyOR";
#endif
#if IS_CC_ENABLED(PolicyPCR)
    case TPM_CC_PolicyPCR:
      return "PolicyPCR";
#endif
#if IS_CC_ENABLED(PolicyPassword)
    case TPM_CC_PolicyPassword:
      return "PolicyPassword";
#endif
#if IS_CC_ENABLED(PolicyPhysicalPresence)
    case TPM_CC_PolicyPhysicalPresence:
      return "PolicyPhysicalPresence";
#endif
#if IS_CC_ENABLED(PolicyRestart)
    case TPM_CC_PolicyRestart:
      return "PolicyRestart";
#endif
#if IS_CC_ENABLED(PolicySecret)
    case TPM_CC_PolicySecret:
      return "PolicySecret";
#endif
#if IS_CC_ENABLED(PolicySigned)
    case TPM_CC_PolicySigned:
      return "PolicySigned";
#endif
#if IS_CC_ENABLED(PolicyTicket)
    case TPM_CC_PolicyTicket:
      return "PolicyTicket";
#endif
#if IS_CC_ENABLED(Quote)
    case TPM_CC_Quote:
      return "Quote";
#endif
#if IS_CC_ENABLED(RSA_Decrypt)
    case TPM_CC_RSA_Decrypt:
      return "RSA_Decrypt";
#endif
#if IS_CC_ENABLED(RSA_Encrypt)
    case TPM_CC_RSA_Encrypt:
      return "RSA_Encrypt";
#endif
#if IS_CC_ENABLED(ReadClock)
    case TPM_CC_ReadClock:
      return "ReadClock";
#endif
#if IS_CC_ENABLED(ReadPublic)
    case TPM_CC_ReadPublic:
      return "ReadPublic";
#endif
#if IS_CC_ENABLED(Rewrap)
    case TPM_CC_Rewrap:
      return "Rewrap";
#endif
#if IS_CC_ENABLED(SelfTest)
    case TPM_CC_SelfTest:
      return "SelfTest";
#endif
#if IS_CC_ENABLED(SequenceComplete)
    case TPM_CC_SequenceComplete:
      return "SequenceComplete";
#endif
#if IS_CC_ENABLED(SequenceUpdate)
    case TPM_CC_SequenceUpdate:
      return "SequenceUpdate";
#endif
#if IS_CC_ENABLED(SetAlgorithmSet)
    case TPM_CC_SetAlgorithmSet:
      return "SetAlgorithmSet";
#endif
#if IS_CC_ENABLED(SetCommandCodeAuditStatus)
    case TPM_CC_SetCommandCodeAuditStatus:
      return "SetCommandCodeAuditStatus";
#endif
#if IS_CC_ENABLED(SetPrimaryPolicy)
    case TPM_CC_SetPrimaryPolicy:
      return "SetPrimaryPolicy";
#endif
#if IS_CC_ENABLED(Shutdown)
    case TPM_CC_Shutdown:
      return "Shutdown";
#endif
#if IS_CC_ENABLED(Sign)
    case TPM_CC_Sign:
      return "Sign";
#endif
#if IS_CC_ENABLED(StartAuthSession)
    case TPM_CC_StartAuthSession:
      return "StartAuthSession";
#endif
#if IS_CC_ENABLED(Startup)
    case TPM_CC_Startup:
      return "Startup";
#endif
#if IS_CC_ENABLED(StirRandom)
    case TPM_CC_StirRandom:
      return "StirRandom";
#endif
#if IS_CC_ENABLED(TestParms)
    case TPM_CC_TestParms:
      return "TestParms";
#endif
#if IS_CC_ENABLED(Unseal)
    case TPM_CC_Unseal:
      return "Unseal";
#endif
#if IS_CC_ENABLED(VerifySignature)
    case TPM_CC_VerifySignature:
      return "VerifySignature";
#endif
#if IS_CC_ENABLED(ZGen_2Phase)
    case TPM_CC_ZGen_2Phase:
      return "ZGen_2Phase";
#endif
    default:
      return "Unknown command";
  }
}