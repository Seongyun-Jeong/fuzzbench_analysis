/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "tpm_manufacture.h"

#include "Global.h"
#include "NV_fp.h"
#include "PCR_Extend_fp.h"
#include "Platform.h"
#include "TPM_Types.h"

#define EK_CERT_NV_START_INDEX 0x01C00000

int tpm_manufactured(void) {
  const uint32_t rsa_ek_nv_index = EK_CERT_NV_START_INDEX;
  const uint32_t ecc_ek_nv_index = EK_CERT_NV_START_INDEX + 1;

  /*
   * If either endorsement certificate is not installed, consider
   * the chip un-manufactured.
   */
  if ((NvIsUndefinedIndex(rsa_ek_nv_index) == TPM_RC_SUCCESS) ||
      (NvIsUndefinedIndex(ecc_ek_nv_index) == TPM_RC_SUCCESS)) {
    return 0;
  }

  return 1;
}

TPM_RC extend_pcr(unsigned int pcr_index, const char *mode_digest) {
  PCR_Extend_In pcr_in;

  if (pcr_index >= IMPLEMENTATION_PCR)
    return TPM_RC_FAILURE;

  pcr_in.pcrHandle = HR_PCR + pcr_index;
  pcr_in.digests.count = 1;
  pcr_in.digests.digests[0].hashAlg = TPM_ALG_SHA256;
  memcpy(pcr_in.digests.digests[0].digest.sha256, mode_digest,
         SHA256_DIGEST_SIZE);
  return TPM2_PCR_Extend(&pcr_in);
}
