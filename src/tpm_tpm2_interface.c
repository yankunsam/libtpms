/********************************************************************************/
/*										*/
/*			LibTPM TPM 2 call interface functions				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "tpm_error.h"
#include "tpm_memory.h"
#include "tpm_library_intern.h"
#include "tpm_nvfilename.h"

#ifndef LIB_EXPORT
#define LIB_EXPORT
#endif
#include "tpm2/Implementation.h"
#include "tpm2/Manufacture_fp.h"
#include "tpm2/Platform_fp.h"
#include "tpm2/ExecCommand_fp.h"
#include "tpm2/TpmTcpProtocol.h"
#include "tpm2/Simulator_fp.h"
#include "tpm2/_TPM_Hash_Data_fp.h"

/*
 * Check whether the main NVRAM file exists. Return TRUE if it doesn, FALSE otherwise
 */
TPM_BOOL _TPM2_CheckNVRAMFileExists(void)
{
#ifdef TPM_LIBTPMS_CALLBACKS
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
    const char *name = TPM_PERMANENT_ALL_NAME;
    unsigned char *data = NULL;
    uint32_t length = 0;
    uint32_t tpm_number = 0;
    TPM_RESULT ret;

    if (cbs->tpm_nvram_loaddata) {
        ret = cbs->tpm_nvram_loaddata(&data, &length, tpm_number, name);
        TPM_Free(data);
        if (ret == TPM_SUCCESS)
            return TRUE;
    }
#endif /* TPM_LIBTPMS_CALLBACKS */
    return FALSE;
}

TPM_RESULT TPM2_MainInit(void)
{
    TPM_RESULT ret = TPM_SUCCESS;
    static int once = 0;

#ifdef TPM_LIBTPMS_CALLBACKS
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();

    if (cbs->tpm_io_init) {
        ret = cbs->tpm_io_init();
        if (ret != TPM_SUCCESS)
            return ret;
    }

    if (cbs->tpm_nvram_init) {
        ret = cbs->tpm_nvram_init();
        if (ret != TPM_SUCCESS)
            return ret;
    }
#endif /* TPM_LIBTPMS_CALLBACKS */

    _rpc__Signal_PowerOff();

    _plat__NVEnable(NULL);

    /* FIXME: this should probably only be called if no file exists */
    if (!_TPM2_CheckNVRAMFileExists())
        TPM_Manufacture(TRUE);
    else {
        if (!once) {
            TPM_Manufacture(TRUE);
        }
        once = 1;
    }

    _rpc__Signal_PowerOn(FALSE);

    _rpc__Signal_NvOn();

    return ret;
}

void TPM2_Terminate(void)
{
    TPM_TearDown();
}

TPM_RESULT TPM2_Process(unsigned char **respbuffer, uint32_t *resp_size,
                        uint32_t *respbufsize,
		        unsigned char *command, uint32_t command_size)
{
    TPM_RESULT res = 0;
    uint8_t locality = 0;
    _IN_BUFFER req;
    _OUT_BUFFER resp;

#ifdef TPM_LIBTPMS_CALLBACKS
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();

    if (cbs->tpm_io_getlocality) {
        TPM_MODIFIER_INDICATOR locty;

        locality = cbs->tpm_io_getlocality(&locty, 0);

        locality = locty;
    }
#endif /* TPM_LIBTPMS_CALLBACKS */

    req.BufferSize = command_size;
    req.Buffer = command;

    /* have the TPM 2 write directly into the response buffer */
    if (*respbufsize < TPM_BUFFER_MAX) {
        res = TPM_Realloc(respbuffer, TPM_BUFFER_MAX);
        if (res)
            return res;
        *respbufsize = TPM_BUFFER_MAX;
    }
    resp.BufferSize = *respbufsize;
    resp.Buffer = *respbuffer;

    /*
     * signals for cancellation have to come after we start processing
     */
    _rpc__Signal_CancelOff();

    _rpc__Send_Command(locality, req, &resp);

    *resp_size = resp.BufferSize;

    return TPM_SUCCESS;
}

TPM_RESULT TPM2_VolatileAllStore(unsigned char **buffer,
                                 uint32_t *buflen)
{
    // FIXME: Is there a function for this?
    return TPM_FAIL;
}

TPM_RESULT TPM2_CancelCommand(void)
{
    _rpc__Signal_CancelOn();

    return TPM_SUCCESS;
}

TPM_RESULT TPM2_GetTPMProperty(enum TPMLIB_TPMProperty prop,
                               int *result)
{
    switch (prop) {
    case  TPMPROP_TPM_RSA_KEY_LENGTH_MAX:
        *result = MAX_RSA_KEY_BITS;
        break;

    case  TPMPROP_TPM_KEY_HANDLES:
        *result = MAX_HANDLE_NUM;
        break;

    /* not supported for TPM 2 */
    case  TPMPROP_TPM_OWNER_EVICT_KEY_HANDLES:
    case  TPMPROP_TPM_MIN_AUTH_SESSIONS:
    case  TPMPROP_TPM_MIN_TRANS_SESSIONS:
    case  TPMPROP_TPM_MIN_DAA_SESSIONS:
    case  TPMPROP_TPM_MIN_SESSION_LIST:
    case  TPMPROP_TPM_MIN_COUNTERS:
    case  TPMPROP_TPM_NUM_FAMILY_TABLE_ENTRY_MIN:
    case  TPMPROP_TPM_NUM_DELEGATE_TABLE_ENTRY_MIN:
    case  TPMPROP_TPM_SPACE_SAFETY_MARGIN:
    case  TPMPROP_TPM_MAX_NV_SPACE:
    case  TPMPROP_TPM_MAX_SAVESTATE_SPACE:
    case  TPMPROP_TPM_MAX_VOLATILESTATE_SPACE:

    default:
        return TPM_FAIL;
    }

    return TPM_SUCCESS;
}

const struct tpm_interface TPM2Interface = {
    .MainInit = TPM2_MainInit,
    .Terminate = TPM2_Terminate,
    .Process = TPM2_Process,
    .VolatileAllStore = TPM2_VolatileAllStore,
    .CancelCommand = TPM2_CancelCommand,
    .GetTPMProperty = TPM2_GetTPMProperty,
    .TpmEstablishedGet = TPM2_IO_TpmEstablished_Get,
    .TpmEstablishedReset = TPM2_IO_TpmEstablished_Reset,
    .HashStart = TPM2_IO_Hash_Start,
    .HashData = TPM2_IO_Hash_Data,
    .HashEnd = TPM2_IO_Hash_End,
};
