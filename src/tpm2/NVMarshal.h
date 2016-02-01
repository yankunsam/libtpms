/********************************************************************************/
/*										*/
/*			  Command and Response Parameter Structures		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Parameters.h 457 2015-12-08 15:29:45Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

/* TPM and TSS share thses structures */

/* rev 119 */

#ifndef CONVERTER_H
#define CONVERTER_H

#include "TPM_Types.h"

struct _NV_INDEX;
typedef struct _NV_INDEX NV_INDEX;

UINT16 _plat__NvMemoryWriteUINT64(
				unsigned int     startOffset,   // IN: write start
				UINT64		 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadUINT64(
				unsigned int     startOffset,   // IN: read start
				UINT64		 *data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteUINT32(
				unsigned int     startOffset,   // IN: write start
				UINT32		 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadUINT32(
				unsigned int     startOffset,   // IN: read start
				UINT32		 *data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteUINT16(
				unsigned int     startOffset,   // IN: write start
				UINT16		 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadUINT16(
				unsigned int     startOffset,   // IN: read start
				UINT16		 *data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteArray(
				unsigned int     startOffset,   // IN: write start
				unsigned int     size,          // IN: size of array
				void 		 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadArray(
				unsigned int     startOffset,   // IN: write start
				unsigned int     size,          // IN: size of array
				void 		 *data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteTPM2B(
				unsigned int     startOffset,   // IN: write start
				void 		 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadTPM2B(
				unsigned int     startOffset,   // IN: write start
				void 		 *data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteNV_INDEX(
				unsigned int     startOffset,   // IN: write start
				NV_INDEX	 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadNV_INDEX(
				unsigned int     startOffset,   // IN: read start
				NV_INDEX	 *data          // IN: where to write to
				);

UINT16 _plat__NvMemoryWritePCR_POLICY(
				unsigned int     startOffset,   // IN: write start
				PCR_POLICY	 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadPCR_POLICY(
				unsigned int     startOffset,   // IN: write start
				PCR_POLICY	 *data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteORDERLY_DATA(
				unsigned int     startOffset,   // IN: write start
				ORDERLY_DATA	 *data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadORDERLY_DATA(
				unsigned int     startOffset,   // IN: write start
				ORDERLY_DATA	 *data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteTPML_PCR_SELECTION(
				unsigned int     	startOffset,   // IN: write start
				TPML_PCR_SELECTION	*data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadTPML_PCR_SELECTION(
				unsigned int     	startOffset,   // IN: write start
				TPML_PCR_SELECTION	*data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteSTATE_CLEAR_DATA(
				unsigned int     	startOffset,   // IN: write start
				STATE_CLEAR_DATA	*data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadSTATE_CLEAR_DATA(
				unsigned int     	startOffset,   // IN: write start
				STATE_CLEAR_DATA	*data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteSTATE_RESET_DATA(
				unsigned int     	startOffset,   // IN: write start
				STATE_RESET_DATA	*data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadSTATE_RESET_DATA(
				unsigned int     	startOffset,   // IN: write start
				STATE_RESET_DATA	*data          // OUT: where to write to
				);

UINT16 _plat__NvMemoryWriteOBJECT(
				unsigned int   	startOffset,   // IN: write start
				OBJECT		*data          // IN: data to write
				);

unsigned int _plat__NvMemoryReadOBJECT(
				unsigned int   	startOffset,   // IN: write start
				OBJECT		*data          // IN: data to write
				);

UINT16 OBJECT_Marshal(OBJECT *data, BYTE **buffer, INT32 *size);

#endif
