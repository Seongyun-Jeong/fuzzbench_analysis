/*
 * Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "InternalRoutines.h"
#include "PolicyFidoSigned_fp.h"

/*
 * PolicyFidoContextUpdate
 *
 * @param commandCode      IN: TPM Ext command code
 * @param name             IN: name of entity
 * @param in               IN: input buffer of the command
 * @param policyTimeout    IN: policy timeout
 * @param session          IN/OUT: policy session to be updated
 * @return none
 */
static void PolicyFidoContextUpdate(TPM_CC commandCode,
                                    TPM2B_NAME *entityName,
                                    PolicyFidoSigned_In *in,
                                    SESSION *session)
{
  HASH_STATE hashState;
  UINT16 policyDigestSize;
  int i;

  /* Start hash */
  policyDigestSize = CryptStartHash(session->authHashAlg, &hashState);

  /*
   * policyDigest size should always be the digest size of session hash
   * algorithm.
   */
  pAssert(session->u2.policyDigest.t.size == policyDigestSize);

  /* add old digest */
  CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

  /* add commandCode */
  CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

  /* add name if applicable */
  if (entityName != NULL)
    CryptUpdateDigest2B(&hashState, &entityName->b);

  /* Complete the digest and get the results */
  CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

  /* Start second hash computation */
  CryptStartHash(session->authHashAlg, &hashState);

  /* add policy digest */
  CryptUpdateDigest2B(&hashState, &session->u2.policyDigest.b);

  /* add authDataDescr */
  CryptUpdateDigest(&hashState,
                    in->authDataDescrCount * sizeof(DATA_OFFSET),
                    (BYTE *)in->authDataDescr);

  /* add authData[authDataDescr] */
  for (i = 0; i < in->authDataDescrCount; i++) {
    CryptUpdateDigest(&hashState,
                      in->authDataDescr[i].size,
                      &(in->authData.t.buffer[in->authDataDescr[i].offset]));
  }

  /* Complete second digest */
  CryptCompleteHash2B(&hashState, &session->u2.policyDigest.b);

  return;
}

TPM_RC TPM2_PolicyFidoSigned(PolicyFidoSigned_In *in,
                             PolicyFidoSigned_Out *out)
{
  TPM_RC result = TPM_RC_SUCCESS;
  SESSION *session;
  TPM2B_NAME entityName;

  session = SessionGet(in->policySession);

  /* Only do input validation if this is not a trial policy session */
  if (session->attributes.isTrialPolicy == CLEAR) {
    TPM2B_DIGEST authHash;
    HASH_STATE hashState;

    /*
     * Re-compute the digest being signed:
     *
     * aHash := hash (authenticatorData[] || nonceTPM)
     *
     * Start hash
     */
    authHash.t.size = CryptStartHash(CryptGetSignHashAlg(&in->auth),
                                     &hashState);

    /* add authData */
    CryptUpdateDigest(&hashState,
                      in->authData.t.size,
                      (BYTE *)in->authData.t.buffer);

    /* Add the sesson nonce */
    CryptUpdateDigest2B(&hashState, &session->nonceTPM.b);

    /* Complete digest */
    CryptCompleteHash2B(&hashState, &authHash.b);

    /*
     * Validate Signature. A TPM_RC_SCHEME, TPM_RC_HANDLE or
     * TPM_RC_SIGNATURE error may be returned at this point.
     */
    result = CryptVerifySignature(in->authObject, &authHash, &in->auth);
    if (result != TPM_RC_SUCCESS)
      return RcSafeAddToResult(result, RC_PolicySigned_auth);
  }

  /* Internal Data Update */

  /* Need the Name of the signing entity */
  entityName.t.size = EntityGetName(in->authObject, &entityName.t.name);

  /*
   * Update policy with input policyRef and name of auth key
   * These values are updated even if the session is a trial session
   */
  PolicyFidoContextUpdate(TPM_CCE_PolicyFidoSigned,
                          &entityName,
                          in,
                          session);

  /*
   * Command Output
   *
   *   No output to generate.
   */

  return TPM_RC_SUCCESS;
}
