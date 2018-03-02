/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
**                                                                      **
** Copyright (c) 2014  -  Technicolor Delivery Technologies, SAS        **
** - All Rights Reserved                                                **
**                                                                      **
** Technicolor hereby informs you that certain portions                 **
** of this software module and/or Work are owned by Technicolor         **
** and/or its software providers.                                       **
**                                                                      **
** Distribution copying and modification of all such work are reserved  **
** to Technicolor and/or its affiliates, and are not permitted without  **
** express written authorization from Technicolor.                      **
**                                                                      **
** Technicolor is registered trademark and trade name of Technicolor,   **
** and shall not be used in any manner without express written          **
** authorization from Technicolor                                       **
**                                                                      **
*************************************************************************/

#include "lib_malloc.h"

#include "rip2.h"
#include "rip_ids.h"
#include "otp_api.h"

#include "bcm_sec.h"

#include "efu_privileged.h"
#include "rip2_common.h"

#if (BUILDTYPE == bootloader)
#define efu_printf    xprintf
#else
#error Unsupported buildtype
#endif

//#define ENG_FEAT_UNLOCKER_DEBUG
#ifdef ENG_FEAT_UNLOCKER_DEBUG
#define efu_dbg_printf    efu_printf
#else
#define efu_dbg_printf(...)
#endif /* ENG_FEAT_UNLOCKER_DEBUG */

#define SIGNATURE_SIZE 256
#define HASH_SIZE 32

#if defined(__BIG_ENDIAN)
#define BETOH64(x)    (x)
#elif defined(__LITTLE_ENDIAN)
// Swap all 8 bytes!
#define ntohll(x)	(\
    (((x)>>56) & 0x00000000000000ff) | \
    (((x)>>40) & 0x000000000000ff00) | \
    (((x)>>24) & 0x0000000000ff0000) | \
    (((x)>>8 ) & 0x00000000ff000000) | \
    (((x)<<8 ) & 0x000000ff00000000) | \
    (((x)<<24) & 0x0000ff0000000000) | \
    (((x)<<40) & 0x00ff000000000000) | \
    (((x)<<56) & 0xff00000000000000) \
  )
#define BETOH64(x)    (ntohll(x))
#else
#error Please define the correct endianness
#endif

#define RSA_KEYFORMAT_2048_PUBLICMODULUSONLY  2048

/*
 * Prototypes local functions
 */

/* WARNING: When EFU_RET_SUCCESS is returned, *data_p_p needs to be freed after use!! */
static unsigned int rip2_malloc_and_read(unsigned short id, unsigned char** data_p_p, unsigned long * data_size_p);
static int isSignatureValid(unsigned char* pSignature, const char* serialNumber, EFU_CHIPID_TYPE chipId, unsigned char * data_a, unsigned long data_length);
static inline unsigned int fetchBitmask(unsigned char* unlockTag_a, unsigned long unlockTag_size, EFU_BITMASK_TYPE *bitmask_p);
static unsigned int verifyTag(unsigned char* unlockTag_a, unsigned long unlockTag_size);

/*
 * LOCAL FUNCTIONS: IMPLEMENTATION
 */

/* WARNING: When EFU_RET_SUCCESS is returned, *data_p_p needs to be freed after use!! */
static unsigned int rip2_malloc_and_read(unsigned short id, unsigned char** data_p_p, unsigned long * data_size_p) {
    unsigned int ret = EFU_RET_SUCCESS;
    unsigned char *data_p = NULL;
    unsigned long data_size = 0;
    // REF: Function entered

    if (rip2_drv_read_length(&data_size, id) != RIP2_SUCCESS) {
        ret = EFU_RET_RIPERR;
        goto rip2_malloc_and_read_afterFunctionEntered;
    }
    data_p = KMALLOC(data_size, 0);
    if (data_p == NULL) {
        ret = EFU_RET_NOMEM;
        goto rip2_malloc_and_read_afterFunctionEntered;
    }
    // REF: Datamem Allocated

    if (rip2_drv_read(&data_size, id, data_p) != RIP2_SUCCESS) {
        ret = EFU_RET_RIPERR;
        KFREE(data_p);
    }

rip2_malloc_and_read_afterFunctionEntered:
    if (ret == EFU_RET_SUCCESS) {
        *data_p_p = data_p;
        *data_size_p = data_size;
    }
    else {
        *data_p_p = NULL;
        *data_size_p = 0;
    }
    return ret;
}

static int isSignatureValid(unsigned char* pSignature, const char* serialNumber, EFU_CHIPID_TYPE chipId,
                            unsigned char* data_a, unsigned long data_length) {
    unsigned char pubkey[RSA_KEYFORMAT_2048_PUBLICMODULUSONLY/8];
    unsigned long pubkey_length;
    unsigned char *data_to_sign_a = NULL;
    unsigned int data_to_sign_s;
    int isSignatureValid_b = 0;
    int rsa_ok;
    uint32_t chipIdBigEndian = HTOBE32(chipId);
    // REF: Function entered

#ifdef ENG_FEAT_UNLOCKER_DEBUG
    int pos = 0;
    efu_dbg_printf("SN:  %s\r\n", serialNumber);
    efu_dbg_printf("CID: 0x%08X\r\n", chipId);
    efu_dbg_printf("SIG:\r\n");
    while (pos < SIGNATURE_SIZE) {
        efu_dbg_printf("%02X.", pSignature[pos]);
        pos++;
        if (pos%15 == 0) {
            efu_dbg_printf("\r\n");
        }
    }
    efu_dbg_printf("\r\n");
#endif

    /* Fetch OSIK public key */
    pubkey_length = sizeof(pubkey);
    if (rip2_drv_read(&pubkey_length, RIP_ID_OSIK, (unsigned char*)&pubkey) != RIP2_SUCCESS)
    {
        efu_dbg_printf("EFU: OSIK?");
        goto isSignatureValid_afterFunctionEntered;
    }

    /* Prepare data for signature verification */
    data_to_sign_s = strlen(serialNumber) + sizeof(chipId) + data_length;
    data_to_sign_a = KMALLOC(data_to_sign_s, 0);
    if (data_to_sign_a == NULL) {
        goto isSignatureValid_afterFunctionEntered;
    }
    // REF: DataToSign Allocated
    memcpy(data_to_sign_a, serialNumber, strlen(serialNumber));
    memcpy(data_to_sign_a + strlen(serialNumber), &chipIdBigEndian, sizeof(chipIdBigEndian));
    memcpy(data_to_sign_a + strlen(serialNumber) + sizeof(chipIdBigEndian), data_a, data_length);

    /* Compare hash in signature with calculated hash */
    rsa_ok = (Sec_verify((const uint32_t *)pSignature, SIGNATURE_SIZE,
                         (const uint32_t *)pubkey, pubkey_length,
                         (const uint8_t *)data_to_sign_a, data_to_sign_s) == SEC_S_SUCCESS);
    if (rsa_ok) {
        isSignatureValid_b = true;
        efu_dbg_printf("== SIG VALID ==\r\n");
        goto isSignatureValid_afterDataToSignAllocated;
    }
    else {
        isSignatureValid_b = false;
        efu_dbg_printf("== ! SIG INV ! ==\r\n");
        goto isSignatureValid_afterDataToSignAllocated;
    }

isSignatureValid_afterDataToSignAllocated:
    KFREE(data_to_sign_a);
isSignatureValid_afterFunctionEntered:
    return (isSignatureValid_b);
}

/* WARNING: No input parameter checking!! */
static inline unsigned int fetchBitmask(unsigned char* unlockTag_a, unsigned long unlockTag_size, EFU_BITMASK_TYPE *bitmask_p) {
    EFU_BITMASK_TYPE bitmask;

    // Copy bitmask in final struct, in the RIP everything is stored in Big Endian
    memcpy(&bitmask, unlockTag_a + SIGNATURE_SIZE, EFU_BITMASK_SIZE);
    bitmask = BETOH64(bitmask);
    *bitmask_p = bitmask;

    return EFU_RET_SUCCESS;
}

static unsigned int verifyTag(unsigned char* unlockTag_a, unsigned long unlockTag_size) {
    unsigned char *signature_a = NULL;
    char *serialNumber_a = NULL;
    EFU_BITMASK_TYPE bitmask, expected_hashes_bitmask;
    unsigned int ret = EFU_RET_SUCCESS;
    unsigned int expected_hashes_count;

    /* Here we are going to verify the signature, but also wether all required hashes are present! */

    // At least the signature and bitmask should be present!!
    unsigned int minimumSize = SIGNATURE_SIZE + EFU_BITMASK_SIZE;
    if (unlockTag_size < minimumSize) {
        ret = EFU_RET_BADTAG;
        goto verifyTag_EXIT;
    }

    signature_a = KMALLOC(SIGNATURE_SIZE, 0);
    if (signature_a == NULL) {
        ret = EFU_RET_NOMEM;
        goto verifyTag_EXIT;
    }

    // Copy signature in final struct
    memcpy(signature_a, unlockTag_a, SIGNATURE_SIZE);

    // Copy bitmask in final struct, in the RIP everything is stored in Big Endian
    memcpy(&bitmask, unlockTag_a + SIGNATURE_SIZE, EFU_BITMASK_SIZE);
    bitmask = BETOH64(bitmask);

    // Also, for each supported feature that requires a tag AND is activated in the bitmask,
    // we expect the hash to be present
    expected_hashes_bitmask = bitmask & EFU_SUPPORTEDFEATURES_BITMASK & EFU_REQUIREDHASHES_BITMASK;
    expected_hashes_count = 0;
    while (expected_hashes_bitmask > 0) {
        if (expected_hashes_bitmask & 0x0000000000000001) {
            expected_hashes_count++;
        }
        expected_hashes_bitmask = expected_hashes_bitmask>>1;
    }
    minimumSize += expected_hashes_count * HASH_SIZE;
    // Also all required hashes should be present!!
    if (unlockTag_size < minimumSize) {
        ret = EFU_RET_BADTAG;
        goto verifyTag_EXIT;
    }

    // Warning: serialNumber_a needs to be freed after use!!
    serialNumber_a = EFU_getSerialNumber();
    if (serialNumber_a == NULL) {
        ret = EFU_RET_NOMEM;
        goto verifyTag_EXIT;
    }

    if (isSignatureValid(signature_a, serialNumber_a, EFU_getChipid(), unlockTag_a + SIGNATURE_SIZE, unlockTag_size - SIGNATURE_SIZE)) {
        ret = EFU_RET_SUCCESS;
    }
    else {
        ret = EFU_RET_BADSIG;
        goto verifyTag_EXIT;
    }

verifyTag_EXIT:
    KFREE(serialNumber_a);
    KFREE(signature_a);
    return ret;
}

/*
 * ALL PUBLIC FUNCTIONS: IMPLEMENTATION
 */

unsigned int EFU_getBitmask(EFU_BITMASK_TYPE *bitmask_p) {
    unsigned int ret = EFU_RET_SUCCESS;
    EFU_BITMASK_TYPE bitmask;

    unsigned char *unlockTag_a = NULL;
    unsigned long unlockTag_size;

    // Read the bootloader unlock tag from RIP
    ret = rip2_malloc_and_read(RIP_ID_UNLOCK_TAG, &unlockTag_a, &unlockTag_size);
    if (ret != EFU_RET_SUCCESS) {
        goto EFU_getBitmask_EXIT;
    }

    // Verify the unlock tag
    if (verifyTag(unlockTag_a, unlockTag_size) != EFU_RET_SUCCESS) {
        ret = EFU_RET_BADTAG;
        goto EFU_getBitmask_EXIT;
    }

    // Fetch bitmask
    if (fetchBitmask(unlockTag_a, unlockTag_size, &bitmask) != EFU_RET_SUCCESS) {
        ret = EFU_RET_PARSEERROR;
        goto EFU_getBitmask_EXIT;
    }

    *bitmask_p = bitmask;
    efu_dbg_printf("EFU BITMASK: %08x%08x\r\n", (uint32_t)(bitmask >> 32), (uint32_t)bitmask);

EFU_getBitmask_EXIT:
    KFREE(unlockTag_a);
    return ret;
}

EFU_CHIPID_TYPE EFU_getChipid() {
    return otp_chipid_read();
}

/* WARNING: returns string that needs to be freed after use!! */
char* EFU_getSerialNumber() {
    char *serialNumber_a = NULL;
    unsigned long serialNumber_size = 0;

    unsigned char *factoryId_a = NULL;
    unsigned long factoryId_size = 0;

    unsigned char *pbaSerialNumber_a = NULL;
    unsigned long pbaSerialNumber_size = 0;

    unsigned int ret = EFU_RET_SUCCESS;

    // REF: Function entered

    /* Get Factory ID */
    ret = rip2_malloc_and_read(RIP_ID_FACTORY_ID, &factoryId_a, &factoryId_size);
    if (ret != EFU_RET_SUCCESS) {
        goto EngFeatUnlocker_getSerialNumber_EXIT;
    }

    /* Get PBA Serial */
    ret = rip2_malloc_and_read(RIP_ID_BOARD_SERIAL_NBR, &pbaSerialNumber_a, &pbaSerialNumber_size);
    if (ret != EFU_RET_SUCCESS) {
        goto EngFeatUnlocker_getSerialNumber_EXIT;
    }

    /* Now concatenate both to form Serial Number */
    serialNumber_size = factoryId_size + pbaSerialNumber_size + 1 /* String termination */;
    serialNumber_a = KMALLOC(serialNumber_size, 0);
    if (serialNumber_a == NULL) {
        ret = EFU_RET_NOMEM;
        goto EngFeatUnlocker_getSerialNumber_EXIT;
    }
    // REF: Sermem Allocated

    memcpy(serialNumber_a, factoryId_a, factoryId_size);
    memcpy(&(serialNumber_a[factoryId_size]), pbaSerialNumber_a, pbaSerialNumber_size);
    serialNumber_a[serialNumber_size-1] = '\0';

//EngFeatUnlcoker_getSerialNumber_afterSerialmemAllocated:
    if (ret != EFU_RET_SUCCESS) {
        KFREE(serialNumber_a);
        serialNumber_a = NULL;
    }
EngFeatUnlocker_getSerialNumber_EXIT:
    KFREE(pbaSerialNumber_a);
    KFREE(factoryId_a);
    return serialNumber_a;
}

unsigned int EFU_verifyStoredTag() {
    unsigned int ret = EFU_RET_SUCCESS;
    unsigned char *unlockTag_a = NULL;
    unsigned long unlockTag_size = 0;

    // Read the bootloader unlock tag from RIP
    ret = rip2_malloc_and_read(RIP_ID_UNLOCK_TAG, &unlockTag_a, &unlockTag_size);
    if (ret != EFU_RET_SUCCESS) {
        goto EFU_verifyStoredTag_EXIT;
    }

    // Verify the unlock tag
    if (verifyTag(unlockTag_a, unlockTag_size) != EFU_RET_SUCCESS) {
        ret = EFU_RET_BADTAG;
        goto EFU_verifyStoredTag_EXIT;
    }

EFU_verifyStoredTag_EXIT:
    KFREE(unlockTag_a);
    return ret;
}

