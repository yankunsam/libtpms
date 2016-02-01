/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: NV.h 471 2015-12-22 19:40:24Z kgoldman $			*/
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

/* rev 124 */

#ifndef    _NV_H_
#define    _NV_H_

/* 5.14.1	Attribute Macros */

/* These macros are used to isolate the differences in the way that the index type changed in
   version 1.21 of the specification */

#ifdef  TPM_NT_ORDINARY
#   define IsNvOrdinaryIndex(attributes) (attributes.TPM_NT == TPM_NV_ORDINARY)
#else
#   define IsNvOrdinaryIndex(attributes)			    \
    (   attributes.TPMA_NV_COUNTER == CLEAR				\
	&& attbibutes.TPMA_NV_BITS == CLEAR				\
	&& attribtues.TPMA_NV_BITS == CLEAR)
#   define  TPM_NT_ORDINARY (0)
#endif
#ifdef  TPM_NT_COUNTER
#   define  IsNvCounterIndex(attributes) (attributes.TPM_NT == TPM_NT_COUNTER)
#else
#   define IsNvCounterIndex(attributes) (attributes.TPMA_NV_COUNTER == SET)
#   define  TPM_NT_COUNTER  (1)
#endif
#ifdef  TPM_NT_BITS
#   define  IsNvBitsIndex(attributes) (attributes.TPM_NT == TPM_NT_BITS)
#else
#   define  IsNvBitsIndex(attributes) (attributes.TPMA_NV_BITS == SET)
#   define  TPM_NT_BITS (2)
#endif
#ifdef  TPM_NT_EXTEND
#   define  IsNvExtendIndex(attributes) (attributes.TPM_NT == TPM_NT_EXTEND)
#else
#   define IsNvExtendIndex(attributes) (attributes.TPMA_NV_EXTEND == SET)
#   define  TPM_NT_EXTEND   (4)
#endif

/* 5.14.2	Index Type Definitions */

/* These definitions allow the same code to be used pre and post 1.21. The main action is to
   redefine the index type values from the bit values. */

#ifdef     TPM_NT_ORDINARY
#   define NV_ATTRIBUTES_TO_TYPE(attributes) (attributes.TPM_NT)
#else
#   define NV_ATTRIBUTES_TO_TYPE(attributes)		    \
    (   attributes.TPMA_NV_COUNTER					\
	+   (attributes.TPMA_NV_BITS << 1)				\
	+   (attributes.TPMA_NV_EXTEND << 2)				\
	)
#   define TPM_NT_ORDINARY     (0)
#endif
#endif  // _NV_H_
