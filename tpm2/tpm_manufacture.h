/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * This header declares the TPM manufacture related interface.
 * It should only be used by tpm2-simulator.
 */

#ifndef TPM_MANUFACTURE_H
#define TPM_MANUFACTURE_H

#include "tpm_generated.h"

/*
 * Returns non-zero if the TPM manufacture steps have been completed.
 * Looks for the endorsement certificates to validate this assessment.
 */
int tpm_manufactured(void);

/*
 * Installs a fixed endorsement seed with its corresponding RSA and ECC
 * certificates into a simulated tpm2 device. For testing use only.
 */
int tpm_endorse(void);

/*
 * Extends the indicated PCR with the provided value.
 * The input length must be of SHA256_DIGEST_SIZE.
 */
TPM_RC extend_pcr(unsigned int pcr_index, const char *mode_digest);

#endif /* TPM_MANUFACTURE_H */
