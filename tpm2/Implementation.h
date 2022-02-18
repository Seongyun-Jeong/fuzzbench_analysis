// This file was extracted from the TCG Published
// Trusted Platform Module Library
// Part 4: Supporting Routines
// Family "2.0"
// Level 00 Revision 01.16
// October 30, 2014

#ifndef _IMPLEMENTATION_H_
#define _IMPLEMENTATION_H_
#include     "BaseTypes.h"
#include     "TPMB.h"
#undef TRUE
#undef FALSE
//
//     This table is built in to TpmStructures() Change these definitions
//     to turn all algorithms or commands on or off
//
#define         ALG_YES         YES
#define         ALG_NO          NO
#define         CC_YES          YES
#define         CC_NO           NO
//
//     From TPM 2.0 Part 2: Table 4 - Defines for Logic Values
//
#define    TRUE       1
#define    FALSE      0
#define    YES        1
#define    NO         0
#define    SET        1
#define    CLEAR      0
//
//     From Vendor-Specific: Table 1 - Defines for Processor Values
//
#define    BIG_ENDIAN_TPM             NO
#define    LITTLE_ENDIAN_TPM          YES
#define    NO_AUTO_ALIGN              NO
//
//     From Vendor-Specific: Table 2 - Defines for Implemented Algorithms
//
#define    ALG_RSA                     ALG_YES
#define    ALG_SHA1                    ALG_YES
#define    ALG_HMAC                    ALG_YES
#define    ALG_AES                     ALG_YES
#define    ALG_MGF1                    ALG_YES
#define    ALG_XOR                     ALG_YES
#define    ALG_KEYEDHASH               ALG_YES
#define    ALG_SHA256                  ALG_YES
#define    ALG_SHA384                  ALG_YES
#define    ALG_SHA512                  ALG_YES
#define    ALG_SM3_256                 ALG_NO
#define    ALG_SM4                     ALG_NO
#define    ALG_RSASSA                  (ALG_YES*ALG_RSA)
#define    ALG_RSAES                   (ALG_YES*ALG_RSA)
#define    ALG_RSAPSS                  (ALG_YES*ALG_RSA)
#define   ALG_OAEP                  (ALG_YES*ALG_RSA)
#define   ALG_ECC                   ALG_YES
#define   ALG_ECDH                  (ALG_YES*ALG_ECC)
#define   ALG_ECDSA                 (ALG_YES*ALG_ECC)
#ifdef EMBEDDED_MODE
#define   ALG_ECDAA                 (ALG_NO*ALG_ECC)
#define   ALG_SM2                   (ALG_NO*ALG_ECC)
#define   ALG_ECSCHNORR             (ALG_NO*ALG_ECC)
#else
#define   ALG_ECDAA                 (ALG_YES*ALG_ECC)
#define   ALG_SM2                   (ALG_YES*ALG_ECC)
#define   ALG_ECSCHNORR             (ALG_YES*ALG_ECC)
#endif
#define   ALG_ECMQV                 (ALG_NO*ALG_ECC)
#define   ALG_SYMCIPHER             ALG_YES
#define   ALG_KDF1_SP800_56A        (ALG_YES*ALG_ECC)
#define   ALG_KDF2                  ALG_NO
#define   ALG_KDF1_SP800_108        ALG_YES
#define   ALG_CTR                   ALG_YES
#define   ALG_OFB                   ALG_YES
#define   ALG_CBC                   ALG_YES
#define   ALG_CFB                   ALG_YES
#define   ALG_ECB                   ALG_YES
//
//     From Vendor-Specific: Table 4 - Defines for Key Size Constants
//
#define RSA_KEY_SIZES_BITS          {1024,2048}
#define RSA_KEY_SIZE_BITS_1024      RSA_ALLOWED_KEY_SIZE_1024
#define RSA_KEY_SIZE_BITS_2048      RSA_ALLOWED_KEY_SIZE_2048
#define MAX_RSA_KEY_BITS            2048
#define MAX_RSA_KEY_BYTES           256
#define AES_KEY_SIZES_BITS          {128,256}
#define AES_KEY_SIZE_BITS_128       AES_ALLOWED_KEY_SIZE_128
#define AES_KEY_SIZE_BITS_256       AES_ALLOWED_KEY_SIZE_256
#define MAX_AES_KEY_BITS            256
#define MAX_AES_KEY_BYTES           32
#define MAX_AES_BLOCK_SIZE_BYTES                               \
           MAX(AES_128_BLOCK_SIZE_BYTES,                      \
           MAX(AES_256_BLOCK_SIZE_BYTES, 0))
#define SM4_KEY_SIZES_BITS          {128}
#define SM4_KEY_SIZE_BITS_128       SM4_ALLOWED_KEY_SIZE_128
#define MAX_SM4_KEY_BITS            128
#define MAX_SM4_KEY_BYTES           16
#define MAX_SM4_BLOCK_SIZE_BYTES                               \
           MAX(SM4_128_BLOCK_SIZE_BYTES, 0)
#define CAMELLIA_KEY_SIZES_BITS     {128}
#define CAMELLIA_KEY_SIZE_BITS_128      CAMELLIA_ALLOWED_KEY_SIZE_128
#define MAX_CAMELLIA_KEY_BITS       128
#define MAX_CAMELLIA_KEY_BYTES      16
#define MAX_CAMELLIA_BLOCK_SIZE_BYTES                          \
           MAX(CAMELLIA_128_BLOCK_SIZE_BYTES, 0)
//
//     From Vendor-Specific: Table 5 - Defines for Implemented Curves
//
#define ECC_NIST_P256          YES
#define ECC_NIST_P384          YES
#define ECC_BN_P256            YES
#define ECC_CURVES             {\
   TPM_ECC_BN_P256, TPM_ECC_NIST_P256, TPM_ECC_NIST_P384}
#define ECC_KEY_SIZES_BITS     {256, 384}
#define ECC_KEY_SIZE_BITS_256
#define ECC_KEY_SIZE_BITS_384
#define MAX_ECC_KEY_BITS       384
#define MAX_ECC_KEY_BYTES      48
//
//     From Vendor-Specific: Table 6 - Defines for Implemented Commands
//

// Flags to define wherever command is needed for a particular environment:
// - Commands mandatory for Chrome OS
#define CC_S_CROS_MUST (1 << 1)
// - Commands required by TCG PC Client Profile
#define CC_S_TCG_MUST  (1 << 2)
// - Commands mandatory for Windows
#define CC_S_WIN_MUST  (1 << 3)
// - Commands recommended for Windows
#define CC_S_WIN_REC   (1 << 4)
// - Commands devoted to firmware upgrade
#define CC_S_FWUPGRADE (1 << 5)
// - Commands required for ChromeOS AP firmware
#define CC_S_COREBOOT  (1 << 6)
// - Other commands: optional for all OS and TCG
#define CC_S_OPTIONAL  (1 << 7)

// Flags to define common combinations of flags:
// - Commands mandatory for ChromeOS and TCG
#define CC_S_CROS_TCG (CC_S_CROS_MUST | CC_S_TCG_MUST)
// - Commands mandatory and recommended for Windows
#define CC_S_WINDOWS (CC_S_WIN_MUST | CC_S_WIN_REC)
// - Commands mandatory for TCG and Windows, including recommended for Windows
#define CC_S_WIN_TCG (CC_S_WINDOWS | CC_S_TCG_MUST)
// - Commands mandatory for ChromeOS, Windows, TCG
#define CC_S_ALL_MUST (CC_S_CROS_MUST | CC_S_WINDOWS | CC_S_TCG_MUST)

// Flags to select supported environment (for CC_ENABLED_SET)
// CC_S_CROS_ONLY - Only ChromeOS / Coreboot
// CC_S_WINDOWS_ONLY - Support only Windows mandatory and recommended
// CC_S_COMMON_SET - Common subset of mandatory and recommended
//          commands, excluding OPTIONAL
#define CC_S_CROS_ONLY (CC_S_CROS_MUST | CC_S_COREBOOT)
#define CC_S_WINDOWS_ONLY (CC_S_WINDOWS | CC_S_COREBOOT)
#define CC_S_COMMON_SET (CC_S_CROS_ONLY | CC_S_WIN_TCG)

// CC_ENABLED_SET defines flags to select supported environment
#ifndef CC_ENABLED_SET
#define CC_ENABLED_SET (CC_S_CROS_ONLY)
#endif

#define CC_SET(mask) ((CC_ENABLED_SET & (mask)) ? CC_YES : CC_NO)
#define IS_CC_ENABLED(cmd) ((CC_##cmd) == CC_YES)

#define    CC_ActivateCredential             CC_SET(CC_S_ALL_MUST)
#define    CC_Certify                        CC_SET(CC_S_ALL_MUST)
#define    CC_CertifyCreation                CC_SET(CC_S_ALL_MUST)
//
#define    CC_ChangeEPS                      CC_SET(CC_S_OPTIONAL)
#define    CC_ChangePPS                      CC_SET(CC_S_OPTIONAL)

#define    CC_Clear                          CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_ClearControl                   CC_SET(CC_S_WIN_TCG)
#define    CC_ClockRateAdjust                CC_SET(CC_S_TCG_MUST)
#define    CC_ClockSet                       CC_SET(CC_S_WINDOWS)
#define    CC_Commit                         CC_SET((CC_S_CROS_TCG * ALG_ECC))
#define    CC_ContextLoad                    CC_SET(CC_S_ALL_MUST)
#define    CC_ContextSave                    CC_SET(CC_S_ALL_MUST)
#define    CC_Create                         CC_SET(CC_S_ALL_MUST)
#define    CC_CreatePrimary                  CC_SET(CC_S_ALL_MUST)
#define    CC_DictionaryAttackLockReset      CC_SET(CC_S_ALL_MUST)
#define    CC_DictionaryAttackParameters     CC_SET(CC_S_ALL_MUST)
#define    CC_Duplicate                      CC_SET(CC_S_WIN_TCG)
#define    CC_ECC_Parameters                 CC_SET((CC_S_CROS_TCG * ALG_ECC))
#define    CC_ECDH_KeyGen                    CC_SET((CC_S_CROS_TCG * ALG_ECC))
#define    CC_ECDH_ZGen                      CC_SET((CC_S_CROS_TCG * ALG_ECC))
#define    CC_EC_Ephemeral                   CC_SET((CC_S_OPTIONAL * ALG_ECC))
#define    CC_EncryptDecrypt                 CC_SET(CC_S_OPTIONAL)
#define    CC_EventSequenceComplete          CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_EvictControl                   CC_SET(CC_S_ALL_MUST)
#define    CC_FieldUpgradeData               CC_SET(CC_S_FWUPGRADE)
#define    CC_FieldUpgradeStart              CC_SET(CC_S_FWUPGRADE)
#define    CC_FirmwareRead                   CC_SET(CC_S_FWUPGRADE)
#define    CC_FlushContext                   CC_SET(CC_S_ALL_MUST)
#define    CC_GetCapability                  CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_GetCommandAuditDigest          CC_SET(CC_S_OPTIONAL)
#define    CC_GetRandom                      CC_SET(CC_S_ALL_MUST)
#define    CC_GetSessionAuditDigest          CC_SET(CC_S_TCG_MUST)
#define    CC_GetTestResult                  CC_SET(CC_S_ALL_MUST)
#define    CC_GetTime                        CC_SET(CC_S_TCG_MUST)
#define    CC_Hash                           CC_SET(CC_S_ALL_MUST)
#define    CC_HashSequenceStart              CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_HierarchyChangeAuth            CC_SET(CC_S_ALL_MUST)
#define    CC_HierarchyControl               CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_HMAC                           CC_SET(CC_S_CROS_TCG)
#define    CC_HMAC_Start                     CC_SET(CC_S_TCG_MUST)
#define    CC_Import                         CC_SET(CC_S_ALL_MUST)
#define    CC_IncrementalSelfTest            CC_SET(CC_S_TCG_MUST)
#define    CC_Load                           CC_SET(CC_S_ALL_MUST)
#define    CC_LoadExternal                   CC_SET((CC_S_CROS_TCG | CC_S_WIN_REC))
#define    CC_MakeCredential                 CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_NV_Certify                     CC_SET(CC_S_CROS_TCG)
#define    CC_NV_ChangeAuth                  CC_SET(CC_S_WIN_TCG)
#define    CC_NV_DefineSpace                 CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_NV_Extend                      CC_SET(CC_S_CROS_TCG)
#define    CC_NV_GlobalWriteLock             CC_SET(CC_S_OPTIONAL)
#define    CC_NV_Increment                   CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_NV_Read                        CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_NV_ReadLock                    CC_SET(CC_S_CROS_TCG)
#define    CC_NV_ReadPublic                  CC_SET(CC_S_ALL_MUST)
#define    CC_NV_SetBits                     CC_SET(CC_S_TCG_MUST)
#define    CC_NV_UndefineSpace               CC_SET(CC_S_ALL_MUST)
#define    CC_NV_UndefineSpaceSpecial        CC_SET(CC_S_CROS_TCG)
#define    CC_NV_Write                       CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_NV_WriteLock                   CC_SET((CC_S_CROS_TCG | CC_S_COREBOOT))
#define    CC_ObjectChangeAuth               CC_SET(CC_S_ALL_MUST)
#define    CC_PCR_Allocate                   CC_SET(CC_S_CROS_TCG)
#define    CC_PCR_Event                      CC_SET(CC_S_WIN_TCG)
#define    CC_PCR_Extend                     CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_PCR_Read                       CC_SET(CC_S_ALL_MUST)
#define    CC_PCR_Reset                      CC_SET((CC_S_WIN_TCG | CC_S_CROS_MUST))
#define    CC_PCR_SetAuthPolicy              CC_SET(CC_S_OPTIONAL)
#define    CC_PCR_SetAuthValue               CC_SET(CC_S_OPTIONAL)
#define    CC_PolicyAuthorize                CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_PolicyAuthValue                CC_SET(CC_S_ALL_MUST)
#define    CC_PolicyCommandCode              CC_SET(CC_S_ALL_MUST)
#define    CC_PolicyCounterTimer             CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_PolicyCpHash                   CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_PolicyDuplicationSelect        CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_PolicyGetDigest                CC_SET(CC_S_ALL_MUST)
#define    CC_PolicyLocality                 CC_SET(CC_S_TCG_MUST)
#define    CC_PolicyNameHash                 CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_PolicyNV                       CC_SET((CC_S_TCG_MUST | CC_S_WINDOWS))
#define    CC_PolicyNvWritten                CC_SET(CC_S_TCG_MUST)
#define    CC_PolicyOR                       CC_SET(CC_S_ALL_MUST)
#define    CC_PolicyPassword                 CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_PolicyPCR                      CC_SET(CC_S_ALL_MUST)
#define    CC_PolicyPhysicalPresence         CC_SET(CC_S_OPTIONAL)
#define    CC_PolicyRestart                  CC_SET(CC_S_ALL_MUST)
#define    CC_PolicySecret                   CC_SET(CC_S_ALL_MUST)
#define    CC_PolicySigned                   CC_SET((CC_S_CROS_TCG | CC_S_WIN_REC))
#define    CC_PolicyTicket                   CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_PP_Commands                    CC_SET(CC_S_OPTIONAL)
#define    CC_Quote                          CC_SET(CC_S_ALL_MUST)
#define    CC_ReadClock                      CC_SET(CC_S_WIN_TCG)
#define    CC_ReadPublic                     CC_SET(CC_S_ALL_MUST)
#define    CC_Rewrap                         CC_SET(CC_S_OPTIONAL)
#define    CC_RSA_Decrypt                    CC_SET((CC_S_ALL_MUST * ALG_RSA))
#define    CC_RSA_Encrypt                    CC_SET((CC_S_CROS_TCG * ALG_RSA))
#define    CC_SelfTest                       CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_SequenceComplete               CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_SequenceUpdate                 CC_SET((CC_S_TCG_MUST | CC_S_WIN_REC))
#define    CC_SetAlgorithmSet                CC_SET(CC_S_OPTIONAL)
#define    CC_SetCommandCodeAuditStatus      CC_SET(CC_S_OPTIONAL)
#define    CC_SetPrimaryPolicy               CC_SET(CC_S_TCG_MUST)
#define    CC_Shutdown                       CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_Sign                           CC_SET(CC_S_ALL_MUST)
#define    CC_StartAuthSession               CC_SET(CC_S_ALL_MUST)
#define    CC_Startup                        CC_SET((CC_S_ALL_MUST | CC_S_COREBOOT))
#define    CC_StirRandom                     CC_SET(CC_S_ALL_MUST)
#define    CC_TestParms                      CC_SET(CC_S_TCG_MUST)
#define    CC_Unseal                         CC_SET(CC_S_ALL_MUST)
#define    CC_Vendor_TCG_Test                CC_SET(CC_S_OPTIONAL)
#define    CC_VerifySignature                CC_SET((CC_S_CROS_TCG | CC_S_WIN_REC))
#define    CC_ZGen_2Phase                    CC_SET((CC_S_OPTIONAL * ALG_ECC))

#define IS_CCE_ENABLED(cmd) ((CCE_##cmd) == CC_YES)
#define    CCE_PolicyFidoSigned              CC_SET(CC_S_CROS_TCG)

//
//      From Vendor-Specific: Table 7 - Defines for Implementation Values
//
#define   FIELD_UPGRADE_IMPLEMENTED              NO
#define   BSIZE                                  UINT16
#define   BUFFER_ALIGNMENT                       4
#define   IMPLEMENTATION_PCR                     24
#define   PLATFORM_PCR                           24
#define   DRTM_PCR                               17
#define   HCRTM_PCR                              0
#define   NUM_LOCALITIES                         5
#define   MAX_HANDLE_NUM                         3
#define   MAX_ACTIVE_SESSIONS                    64
#define   CONTEXT_SLOT                           UINT16
#define   CONTEXT_COUNTER                        UINT64
#define   MAX_LOADED_SESSIONS                    3
#define   MAX_SESSION_NUM                        3
#define   MAX_LOADED_OBJECTS                     3
#define   MIN_EVICT_OBJECTS                      2
#define   PCR_SELECT_MIN                         ((PLATFORM_PCR+7)/8)
#define   PCR_SELECT_MAX                         ((IMPLEMENTATION_PCR+7)/8)
#define   NUM_POLICY_PCR_GROUP                   1
#define   NUM_AUTHVALUE_PCR_GROUP                1
#define   MAX_CONTEXT_SIZE                       2048
#define   MAX_DIGEST_BUFFER                      1024
#define   MAX_NV_INDEX_SIZE                      2048
//
#define MAX_NV_BUFFER_SIZE                1024
#define MAX_CAP_BUFFER                    1024
#ifdef EMBEDDED_MODE
// This must be matched by the package using this library!
#define NV_MEMORY_SIZE                    11980
// Versioning NV storage format will allow to smoothly migrate NVRAM contents.
// Versions:
// 1 - full non-serialized objects in NVMEM, max SHA digest is SHA-256
// 2 - a mix of serialized and non-serialized objects in NVMEM, max SHA digest
//     is SHA-512. Eviction objects can be stored either serialized or
//     non-serialized. The size of the stored entity smaller than
//     sizeof(OBJECT) is considered an indication of the serialized form.

#define NV_FORMAT_VERSION                 2
#else
#define NV_MEMORY_SIZE                    16384
#endif
#define NUM_STATIC_PCR                    16
#define MAX_ALG_LIST_SIZE                 64
#define TIMER_PRESCALE                    100000
#define PRIMARY_SEED_SIZE                 32
#define CONTEXT_ENCRYPT_ALG               TPM_ALG_AES
#define CONTEXT_ENCRYPT_KEY_BITS          MAX_SYM_KEY_BITS
#define CONTEXT_ENCRYPT_KEY_BYTES         ((CONTEXT_ENCRYPT_KEY_BITS+7)/8)
#define CONTEXT_INTEGRITY_HASH_ALG        TPM_ALG_SHA256
#define CONTEXT_INTEGRITY_HASH_SIZE       SHA256_DIGEST_SIZE
#define PROOF_SIZE                        CONTEXT_INTEGRITY_HASH_SIZE
#define NV_CLOCK_UPDATE_INTERVAL          12
#define NUM_POLICY_PCR                    1
#define MAX_COMMAND_SIZE                  2048
#define MAX_RESPONSE_SIZE                 2048
#define ORDERLY_BITS                      8
#define MAX_ORDERLY_COUNT                 ((1<<ORDERLY_BITS)-1)
#define ALG_ID_FIRST                      TPM_ALG_FIRST
#define ALG_ID_LAST                       TPM_ALG_LAST
#define MAX_SYM_DATA                      128
#define MAX_RNG_ENTROPY_SIZE              64
#define RAM_INDEX_SPACE                   512
#define RSA_DEFAULT_PUBLIC_EXPONENT       0x00010001
#define ENABLE_PCR_NO_INCREMENT           YES
#define CRT_FORMAT_RSA                    YES
#define PRIVATE_VENDOR_SPECIFIC_BYTES     \
   ((MAX_RSA_KEY_BYTES/2)*(3+CRT_FORMAT_RSA*2))
//
//      From TCG Algorithm Registry: Table 2 - Definition of TPM_ALG_ID Constants
//
typedef UINT16              TPM_ALG_ID;
#define TPM_ALG_ERROR                (TPM_ALG_ID)(0x0000)
#define ALG_ERROR_VALUE              0x0000
#if defined ALG_RSA && ALG_RSA == YES
#define TPM_ALG_RSA                  (TPM_ALG_ID)(0x0001)
#endif
#define ALG_RSA_VALUE                0x0001
#if defined ALG_SHA && ALG_SHA == YES
#define TPM_ALG_SHA                  (TPM_ALG_ID)(0x0004)
#endif
#define ALG_SHA_VALUE                0x0004
#if defined ALG_SHA1 && ALG_SHA1 == YES
#define TPM_ALG_SHA1                 (TPM_ALG_ID)(0x0004)
#endif
#define ALG_SHA1_VALUE               0x0004
#if defined ALG_HMAC && ALG_HMAC == YES
#define TPM_ALG_HMAC                  (TPM_ALG_ID)(0x0005)
#endif
#define ALG_HMAC_VALUE               0x0005
#if defined ALG_AES && ALG_AES == YES
#define TPM_ALG_AES                  (TPM_ALG_ID)(0x0006)
#endif
#define ALG_AES_VALUE                0x0006
#if defined ALG_MGF1 && ALG_MGF1 == YES
#define TPM_ALG_MGF1                 (TPM_ALG_ID)(0x0007)
#endif
#define ALG_MGF1_VALUE               0x0007
#if defined ALG_KEYEDHASH && ALG_KEYEDHASH == YES
#define TPM_ALG_KEYEDHASH            (TPM_ALG_ID)(0x0008)
#endif
#define ALG_KEYEDHASH_VALUE          0x0008
#if defined ALG_XOR && ALG_XOR == YES
#define TPM_ALG_XOR                  (TPM_ALG_ID)(0x000A)
//
#endif
#define ALG_XOR_VALUE                0x000A
#if defined ALG_SHA256 && ALG_SHA256 == YES
#define TPM_ALG_SHA256               (TPM_ALG_ID)(0x000B)
#endif
#define ALG_SHA256_VALUE             0x000B
#if defined ALG_SHA384 && ALG_SHA384 == YES
#define TPM_ALG_SHA384               (TPM_ALG_ID)(0x000C)
#endif
#define ALG_SHA384_VALUE             0x000C
#if defined ALG_SHA512 && ALG_SHA512 == YES
#define TPM_ALG_SHA512               (TPM_ALG_ID)(0x000D)
#endif
#define ALG_SHA512_VALUE             0x000D
#define TPM_ALG_NULL                 (TPM_ALG_ID)(0x0010)
#define ALG_NULL_VALUE               0x0010
#if defined ALG_SM3_256 && ALG_SM3_256 == YES
#define TPM_ALG_SM3_256              (TPM_ALG_ID)(0x0012)
#endif
#define ALG_SM3_256_VALUE            0x0012
#if defined ALG_SM4 && ALG_SM4 == YES
#define TPM_ALG_SM4                  (TPM_ALG_ID)(0x0013)
#endif
#define ALG_SM4_VALUE                0x0013
#if defined ALG_RSASSA && ALG_RSASSA == YES
#define TPM_ALG_RSASSA               (TPM_ALG_ID)(0x0014)
#define SUPPORT_PADDING_ONLY_RSASSA  YES
#endif
#define ALG_RSASSA_VALUE             0x0014
#if defined ALG_RSAES && ALG_RSAES == YES
#define TPM_ALG_RSAES                (TPM_ALG_ID)(0x0015)
#endif
#define ALG_RSAES_VALUE              0x0015
#if defined ALG_RSAPSS && ALG_RSAPSS == YES
#define TPM_ALG_RSAPSS               (TPM_ALG_ID)(0x0016)
#endif
#define ALG_RSAPSS_VALUE             0x0016
#if defined ALG_OAEP && ALG_OAEP == YES
#define TPM_ALG_OAEP                 (TPM_ALG_ID)(0x0017)
#endif
#define ALG_OAEP_VALUE               0x0017
#if defined ALG_ECDSA && ALG_ECDSA == YES
#define TPM_ALG_ECDSA                (TPM_ALG_ID)(0x0018)
#endif
#define ALG_ECDSA_VALUE              0x0018
#if defined ALG_ECDH && ALG_ECDH == YES
#define TPM_ALG_ECDH                 (TPM_ALG_ID)(0x0019)
#endif
#define ALG_ECDH_VALUE               0x0019
#if defined ALG_ECDAA && ALG_ECDAA == YES
#define TPM_ALG_ECDAA                (TPM_ALG_ID)(0x001A)
#endif
#define ALG_ECDAA_VALUE              0x001A
#if defined ALG_SM2 && ALG_SM2 == YES
#define TPM_ALG_SM2                  (TPM_ALG_ID)(0x001B)
#endif
#define ALG_SM2_VALUE                0x001B
#if defined ALG_ECSCHNORR && ALG_ECSCHNORR == YES
#define TPM_ALG_ECSCHNORR            (TPM_ALG_ID)(0x001C)
#endif
#define ALG_ECSCHNORR_VALUE          0x001C
#if defined ALG_ECMQV && ALG_ECMQV == YES
#define TPM_ALG_ECMQV                (TPM_ALG_ID)(0x001D)
#endif
#define ALG_ECMQV_VALUE              0x001D
#if defined ALG_KDF1_SP800_56A && ALG_KDF1_SP800_56A == YES
#define TPM_ALG_KDF1_SP800_56A       (TPM_ALG_ID)(0x0020)
#endif
#define ALG_KDF1_SP800_56A_VALUE     0x0020
#if defined ALG_KDF2 && ALG_KDF2 == YES
#define TPM_ALG_KDF2                 (TPM_ALG_ID)(0x0021)
#endif
#define ALG_KDF2_VALUE               0x0021
#if defined ALG_KDF1_SP800_108 && ALG_KDF1_SP800_108 == YES
#define TPM_ALG_KDF1_SP800_108       (TPM_ALG_ID)(0x0022)
#endif
#define ALG_KDF1_SP800_108_VALUE     0x0022
#if defined ALG_ECC && ALG_ECC == YES
#define TPM_ALG_ECC                  (TPM_ALG_ID)(0x0023)
#endif
#define ALG_ECC_VALUE                0x0023
#if defined ALG_SYMCIPHER && ALG_SYMCIPHER == YES
#define TPM_ALG_SYMCIPHER            (TPM_ALG_ID)(0x0025)
#endif
#define ALG_SYMCIPHER_VALUE          0x0025
#if defined ALG_CAMELLIA && ALG_CAMELLIA == YES
#define TPM_ALG_CAMELLIA             (TPM_ALG_ID)(0x0026)
#endif
#define ALG_CAMELLIA_VALUE           0x0026
#if defined ALG_CTR && ALG_CTR == YES
#define TPM_ALG_CTR                  (TPM_ALG_ID)(0x0040)
#endif
#define ALG_CTR_VALUE                0x0040
#if defined ALG_OFB && ALG_OFB == YES
#define TPM_ALG_OFB                   (TPM_ALG_ID)(0x0041)
#endif
#define ALG_OFB_VALUE                0x0041
#if defined ALG_CBC && ALG_CBC == YES
#define TPM_ALG_CBC                  (TPM_ALG_ID)(0x0042)
#endif
#define ALG_CBC_VALUE                0x0042
#if defined ALG_CFB && ALG_CFB == YES
#define TPM_ALG_CFB                  (TPM_ALG_ID)(0x0043)
#endif
#define ALG_CFB_VALUE                0x0043
#if defined ALG_ECB && ALG_ECB == YES
#define TPM_ALG_ECB                  (TPM_ALG_ID)(0x0044)
#endif
#define ALG_ECB_VALUE                0x0044
#define TPM_ALG_FIRST                (TPM_ALG_ID)(0x0001)
#define ALG_FIRST_VALUE              0x0001
#define TPM_ALG_LAST                 (TPM_ALG_ID)(0x0044)
#define ALG_LAST_VALUE               0x0044
//
//      From TCG Algorithm Registry: Table 3 - Definition of TPM_ECC_CURVE Constants
//
typedef    UINT16                 TPM_ECC_CURVE;
#define    TPM_ECC_NONE             (TPM_ECC_CURVE)(0x0000)
#define    TPM_ECC_NIST_P192        (TPM_ECC_CURVE)(0x0001)
#define    TPM_ECC_NIST_P224        (TPM_ECC_CURVE)(0x0002)
#define    TPM_ECC_NIST_P256        (TPM_ECC_CURVE)(0x0003)
#define    TPM_ECC_NIST_P384        (TPM_ECC_CURVE)(0x0004)
#define    TPM_ECC_NIST_P521        (TPM_ECC_CURVE)(0x0005)
#define    TPM_ECC_BN_P256          (TPM_ECC_CURVE)(0x0010)
#define    TPM_ECC_BN_P638          (TPM_ECC_CURVE)(0x0011)
#define    TPM_ECC_SM2_P256         (TPM_ECC_CURVE)(0x0020)
//
//      From TCG Algorithm Registry: Table 4 - Defines for NIST_P192 ECC Values Data in CrpiEccData.c From
//      TCG Algorithm Registry: Table 5 - Defines for NIST_P224 ECC Values Data in CrpiEccData.c From TCG
//      Algorithm Registry: Table 6 - Defines for NIST_P256 ECC Values Data in CrpiEccData.c From TCG
//      Algorithm Registry: Table 7 - Defines for NIST_P384 ECC Values Data in CrpiEccData.c From TCG
//
//      Algorithm Registry: Table 8 - Defines for NIST_P521 ECC Values Data in CrpiEccData.c     From   TCG
//      Algorithm Registry: Table 9 - Defines for BN_P256 ECC Values Data in CrpiEccData.c       From   TCG
//      Algorithm Registry: Table 10 - Defines for BN_P638 ECC Values Data in CrpiEccData.c      From   TCG
//      Algorithm Registry: Table 11 - Defines for SM2_P256 ECC Values Data in CrpiEccData.c     From   TCG
//      Algorithm Registry: Table 12 - Defines for SHA1 Hash Values
//
#define SHA1_DIGEST_SIZE     20
#define SHA_DIGEST_SIZE      SHA1_DIGEST_SIZE
#define SHA1_BLOCK_SIZE      64
#define SHA1_DER_SIZE        15
#define SHA1_DER             \
   0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14
//
//      From TCG Algorithm Registry: Table 13 - Defines for SHA256 Hash Values
//
#define   SHA256_DIGEST_SIZE       32
#define   SHA256_BLOCK_SIZE        64
#define   SHA256_DER_SIZE          19
#define   SHA256_DER               \
   0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,\
   0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
//
//      From TCG Algorithm Registry: Table 14 - Defines for SHA384 Hash Values
//
#define   SHA384_DIGEST_SIZE       48
#define   SHA384_BLOCK_SIZE        128
#define   SHA384_DER_SIZE          19
#define   SHA384_DER               \
   0x30,0x41,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,\
   0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30
//
//      From TCG Algorithm Registry: Table 15 - Defines for SHA512 Hash Values
//
#define   SHA512_DIGEST_SIZE       64
#define   SHA512_BLOCK_SIZE        128
#define   SHA512_DER_SIZE          19
#define   SHA512_DER               \
   0x30,0x51,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,\
   0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40
//
//      From TCG Algorithm Registry: Table 16 - Defines for SM3_256 Hash Values
//
#define   SM3_256_DIGEST_SIZE       32
#define   SM3_256_BLOCK_SIZE        64
#define   SM3_256_DER_SIZE          18
#define   SM3_256_DER               \
   0x30,0x30,0x30,0x0C,0x06,0x08,0x2A,0x81,0x1C,\
   0x81,0x45,0x01,0x83,0x11,0x05,0x00,0x04,0x20
//
//      From TCG Algorithm Registry: Table 17 - Defines for AES Symmetric Cipher Algorithm Constants
//
#define   AES_ALLOWED_KEY_SIZE_128        YES
#define   AES_ALLOWED_KEY_SIZE_192        YES
#define   AES_ALLOWED_KEY_SIZE_256        YES
#define   AES_128_BLOCK_SIZE_BYTES        16
#define   AES_192_BLOCK_SIZE_BYTES        16
#define   AES_256_BLOCK_SIZE_BYTES        16
//
//      From TCG Algorithm Registry: Table 18 - Defines for SM4 Symmetric Cipher Algorithm Constants
#define    SM4_ALLOWED_KEY_SIZE_128       YES
#define    SM4_128_BLOCK_SIZE_BYTES       16
//
//      From TCG Algorithm Registry: Table 19 - Defines for CAMELLIA Symmetric Cipher Algorithm Constants
//
#define    CAMELLIA_ALLOWED_KEY_SIZE_128        YES
#define    CAMELLIA_ALLOWED_KEY_SIZE_192        YES
#define    CAMELLIA_ALLOWED_KEY_SIZE_256        YES
#define    CAMELLIA_128_BLOCK_SIZE_BYTES        16
#define    CAMELLIA_192_BLOCK_SIZE_BYTES        16
#define    CAMELLIA_256_BLOCK_SIZE_BYTES        16
//
//      From TPM 2.0 Part 2: Table 13 - Definition of TPM_CC Constants
//
typedef UINT32              TPM_CC;
#define TPM_CC_FIRST                          (TPM_CC)(0x0000011F)
#define TPM_CC_PP_FIRST                       (TPM_CC)(0x0000011F)
#define TPM_CC_NV_UndefineSpaceSpecial        (TPM_CC)(0x0000011F)
#define TPM_CC_EvictControl                   (TPM_CC)(0x00000120)
#define TPM_CC_HierarchyControl               (TPM_CC)(0x00000121)
#define TPM_CC_NV_UndefineSpace               (TPM_CC)(0x00000122)
#define TPM_CC_ChangeEPS                      (TPM_CC)(0x00000124)
#define TPM_CC_ChangePPS                      (TPM_CC)(0x00000125)
#define TPM_CC_Clear                          (TPM_CC)(0x00000126)
#define TPM_CC_ClearControl                   (TPM_CC)(0x00000127)
#define TPM_CC_ClockSet                       (TPM_CC)(0x00000128)
#define TPM_CC_HierarchyChangeAuth            (TPM_CC)(0x00000129)
#define TPM_CC_NV_DefineSpace                 (TPM_CC)(0x0000012A)
#define TPM_CC_PCR_Allocate                   (TPM_CC)(0x0000012B)
#define TPM_CC_PCR_SetAuthPolicy              (TPM_CC)(0x0000012C)
#define TPM_CC_PP_Commands                    (TPM_CC)(0x0000012D)
#define TPM_CC_SetPrimaryPolicy               (TPM_CC)(0x0000012E)
#define TPM_CC_FieldUpgradeStart              (TPM_CC)(0x0000012F)
#define TPM_CC_ClockRateAdjust                (TPM_CC)(0x00000130)
#define TPM_CC_CreatePrimary                  (TPM_CC)(0x00000131)
#define TPM_CC_NV_GlobalWriteLock             (TPM_CC)(0x00000132)
#define TPM_CC_PP_LAST                        (TPM_CC)(0x00000132)
#define TPM_CC_GetCommandAuditDigest          (TPM_CC)(0x00000133)
#define TPM_CC_NV_Increment                   (TPM_CC)(0x00000134)
#define TPM_CC_NV_SetBits                     (TPM_CC)(0x00000135)
#define TPM_CC_NV_Extend                      (TPM_CC)(0x00000136)
#define TPM_CC_NV_Write                       (TPM_CC)(0x00000137)
#define TPM_CC_NV_WriteLock                   (TPM_CC)(0x00000138)
#define TPM_CC_DictionaryAttackLockReset      (TPM_CC)(0x00000139)
#define TPM_CC_DictionaryAttackParameters     (TPM_CC)(0x0000013A)
#define TPM_CC_NV_ChangeAuth                  (TPM_CC)(0x0000013B)
#define TPM_CC_PCR_Event                      (TPM_CC)(0x0000013C)
#define TPM_CC_PCR_Reset                      (TPM_CC)(0x0000013D)
#define TPM_CC_SequenceComplete               (TPM_CC)(0x0000013E)
#define TPM_CC_SetAlgorithmSet                (TPM_CC)(0x0000013F)
#define TPM_CC_SetCommandCodeAuditStatus      (TPM_CC)(0x00000140)
#define TPM_CC_FieldUpgradeData               (TPM_CC)(0x00000141)
#define TPM_CC_IncrementalSelfTest            (TPM_CC)(0x00000142)
#define TPM_CC_SelfTest                       (TPM_CC)(0x00000143)
#define TPM_CC_Startup                        (TPM_CC)(0x00000144)
#define TPM_CC_Shutdown                       (TPM_CC)(0x00000145)
#define TPM_CC_StirRandom                     (TPM_CC)(0x00000146)
#define TPM_CC_ActivateCredential             (TPM_CC)(0x00000147)
#define TPM_CC_Certify                        (TPM_CC)(0x00000148)
#define TPM_CC_PolicyNV                       (TPM_CC)(0x00000149)
#define TPM_CC_CertifyCreation                (TPM_CC)(0x0000014A)
#define TPM_CC_Duplicate                      (TPM_CC)(0x0000014B)
#define TPM_CC_GetTime                        (TPM_CC)(0x0000014C)
#define TPM_CC_GetSessionAuditDigest          (TPM_CC)(0x0000014D)
#define TPM_CC_NV_Read                        (TPM_CC)(0x0000014E)
#define TPM_CC_NV_ReadLock                    (TPM_CC)(0x0000014F)
#define TPM_CC_ObjectChangeAuth               (TPM_CC)(0x00000150)
#define TPM_CC_PolicySecret                   (TPM_CC)(0x00000151)
#define TPM_CC_Rewrap                         (TPM_CC)(0x00000152)
#define TPM_CC_Create                         (TPM_CC)(0x00000153)
#define TPM_CC_ECDH_ZGen                      (TPM_CC)(0x00000154)
#define TPM_CC_HMAC                           (TPM_CC)(0x00000155)
#define TPM_CC_Import                         (TPM_CC)(0x00000156)
#define TPM_CC_Load                           (TPM_CC)(0x00000157)
#define TPM_CC_Quote                          (TPM_CC)(0x00000158)
#define TPM_CC_RSA_Decrypt                    (TPM_CC)(0x00000159)
#define TPM_CC_HMAC_Start                     (TPM_CC)(0x0000015B)
#define TPM_CC_SequenceUpdate                 (TPM_CC)(0x0000015C)
#define TPM_CC_Sign                           (TPM_CC)(0x0000015D)
#define TPM_CC_Unseal                         (TPM_CC)(0x0000015E)
#define TPM_CC_PolicySigned                   (TPM_CC)(0x00000160)
#define TPM_CC_ContextLoad                    (TPM_CC)(0x00000161)
#define TPM_CC_ContextSave                    (TPM_CC)(0x00000162)
#define TPM_CC_ECDH_KeyGen                    (TPM_CC)(0x00000163)
#define TPM_CC_EncryptDecrypt                 (TPM_CC)(0x00000164)
#define TPM_CC_FlushContext                   (TPM_CC)(0x00000165)
#define TPM_CC_LoadExternal                   (TPM_CC)(0x00000167)
#define TPM_CC_MakeCredential                 (TPM_CC)(0x00000168)
#define TPM_CC_NV_ReadPublic                  (TPM_CC)(0x00000169)
#define TPM_CC_PolicyAuthorize                (TPM_CC)(0x0000016A)
#define TPM_CC_PolicyAuthValue                (TPM_CC)(0x0000016B)
#define TPM_CC_PolicyCommandCode              (TPM_CC)(0x0000016C)
#define TPM_CC_PolicyCounterTimer             (TPM_CC)(0x0000016D)
#define TPM_CC_PolicyCpHash                   (TPM_CC)(0x0000016E)
#define TPM_CC_PolicyLocality                 (TPM_CC)(0x0000016F)
#define TPM_CC_PolicyNameHash                 (TPM_CC)(0x00000170)
#define TPM_CC_PolicyOR                       (TPM_CC)(0x00000171)
#define TPM_CC_PolicyTicket                   (TPM_CC)(0x00000172)
#define TPM_CC_ReadPublic                     (TPM_CC)(0x00000173)
#define TPM_CC_RSA_Encrypt                    (TPM_CC)(0x00000174)
#define TPM_CC_StartAuthSession               (TPM_CC)(0x00000176)
#define TPM_CC_VerifySignature                (TPM_CC)(0x00000177)
#define TPM_CC_ECC_Parameters                 (TPM_CC)(0x00000178)
#define TPM_CC_FirmwareRead                   (TPM_CC)(0x00000179)
#define TPM_CC_GetCapability                  (TPM_CC)(0x0000017A)
#define TPM_CC_GetRandom                      (TPM_CC)(0x0000017B)
#define TPM_CC_GetTestResult                  (TPM_CC)(0x0000017C)
#define TPM_CC_Hash                           (TPM_CC)(0x0000017D)
#define TPM_CC_PCR_Read                       (TPM_CC)(0x0000017E)
#define TPM_CC_PolicyPCR                      (TPM_CC)(0x0000017F)
#define TPM_CC_PolicyRestart                  (TPM_CC)(0x00000180)
#define TPM_CC_ReadClock                      (TPM_CC)(0x00000181)
#define TPM_CC_PCR_Extend                     (TPM_CC)(0x00000182)
#define TPM_CC_PCR_SetAuthValue               (TPM_CC)(0x00000183)
#define TPM_CC_NV_Certify                     (TPM_CC)(0x00000184)
#define TPM_CC_EventSequenceComplete          (TPM_CC)(0x00000185)
#define TPM_CC_HashSequenceStart              (TPM_CC)(0x00000186)
#define TPM_CC_PolicyPhysicalPresence         (TPM_CC)(0x00000187)
#define TPM_CC_PolicyDuplicationSelect        (TPM_CC)(0x00000188)
#define TPM_CC_PolicyGetDigest                (TPM_CC)(0x00000189)
#define TPM_CC_TestParms                      (TPM_CC)(0x0000018A)
#define TPM_CC_Commit                         (TPM_CC)(0x0000018B)
#define TPM_CC_PolicyPassword                 (TPM_CC)(0x0000018C)
#define TPM_CC_ZGen_2Phase                    (TPM_CC)(0x0000018D)
#define TPM_CC_EC_Ephemeral                   (TPM_CC)(0x0000018E)
#define TPM_CC_PolicyNvWritten                (TPM_CC)(0x0000018F)
#define TPM_CC_LAST                           (TPM_CC)(0x0000018F)

/*
 * Extended TPM Commands
 */
#define TPM_CCE_BIT_MASK                      (TPM_CC)(0x20000000)
#define TPM_CCE_FIRST                         (TPM_CC)(TPM_CCE_BIT_MASK|0x8001)
#define TPM_CCE_PolicyFidoSigned              (TPM_CC)(TPM_CCE_FIRST)
#define TPM_CCE_LAST                          (TPM_CC)(TPM_CCE_BIT_MASK|0x8001)

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#define MAX_HASH_BLOCK_SIZE (                    \
   MAX(ALG_SHA1 * SHA1_BLOCK_SIZE,              \
   MAX(ALG_SHA256 * SHA256_BLOCK_SIZE,          \
   MAX(ALG_SHA384 * SHA384_BLOCK_SIZE,          \
   MAX(ALG_SM3_256 * SM3_256_BLOCK_SIZE,        \
   MAX(ALG_SHA512 * SHA512_BLOCK_SIZE,          \
   0 ))))))
#define MAX_DIGEST_SIZE      (                   \
   MAX(ALG_SHA1 * SHA1_DIGEST_SIZE,             \
   MAX(ALG_SHA256 * SHA256_DIGEST_SIZE,         \
   MAX(ALG_SHA384 * SHA384_DIGEST_SIZE,         \
   MAX(ALG_SM3_256 * SM3_256_DIGEST_SIZE,       \
   MAX(ALG_SHA512 * SHA512_DIGEST_SIZE,         \
   0 ))))))
#if MAX_DIGEST_SIZE == 0 || MAX_HASH_BLOCK_SIZE == 0
#error "Hash data not valid"
#endif
#define HASH_COUNT (ALG_SHA1+ALG_SHA256+ALG_SHA384+ALG_SM3_256+ALG_SHA512)
//
//      Define the 2B structure that would hold any hash block
//
TPM2B_TYPE(MAX_HASH_BLOCK, MAX_HASH_BLOCK_SIZE);
//
//      Folloing typedef is for some old code
//
typedef TPM2B_MAX_HASH_BLOCK    TPM2B_HASH_BLOCK;
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef ALG_CAMELLIA
#   define ALG_CAMELLIA         NO
#endif
#ifndef MAX_CAMELLIA_KEY_BITS
#   define      MAX_CAMELLIA_KEY_BITS 0
#   define      MAX_CAMELLIA_BLOCK_SIZE_BYTES 0
#endif
#ifndef ALG_SM4
#   define ALG_SM4         NO
#endif
#ifndef MAX_SM4_KEY_BITS
#   define      MAX_SM4_KEY_BITS 0
#   define      MAX_SM4_BLOCK_SIZE_BYTES 0
#endif
#ifndef ALG_AES
#   define ALG_AES         NO
#endif
#ifndef MAX_AES_KEY_BITS
#   define      MAX_AES_KEY_BITS 0
#   define      MAX_AES_BLOCK_SIZE_BYTES 0
#endif
#define MAX_SYM_KEY_BITS (                                \
           MAX(MAX_CAMELLIA_KEY_BITS * ALG_CAMELLIA,            \
           MAX(MAX_SM4_KEY_BITS * ALG_SM4,           \
           MAX(MAX_AES_KEY_BITS * ALG_AES,           \
           0))))
#define MAX_SYM_KEY_BYTES ((MAX_SYM_KEY_BITS + 7) / 8)
#define MAX_SYM_BLOCK_SIZE (                              \
           MAX(MAX_CAMELLIA_BLOCK_SIZE_BYTES * ALG_CAMELLIA,    \
           MAX(MAX_SM4_BLOCK_SIZE_BYTES * ALG_SM4,   \
           MAX(MAX_AES_BLOCK_SIZE_BYTES * ALG_AES,   \
           0))))
#if MAX_SYM_KEY_BITS == 0 || MAX_SYM_BLOCK_SIZE == 0
#   error Bad size for MAX_SYM_KEY_BITS or MAX_SYM_BLOCK_SIZE
#endif
//
//      Define the 2B structure for a seed
//
TPM2B_TYPE(SEED, PRIMARY_SEED_SIZE);

#define UNREFERENCED_PARAMETER(x) (void)(x)
#endif // _IMPLEMENTATION_H_
