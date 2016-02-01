/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Context_spt.c 471 2015-12-22 19:40:24Z kgoldman $		*/
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

// 7.3	Context Management Command Support (Context_spt.c)
// 7.3.1	Includes

#include "InternalRoutines.h"
#include "Context_spt_fp.h"

// 7.3.2	Functions
// 7.3.2.1	ComputeContextProtectionKey()

// This function retrieves the symmetric protection key for context encryption It is used by
// TPM2_ConextSave() and TPM2_ContextLoad() to create the symmetric encryption key and iv

void
ComputeContextProtectionKey(
			    TPMS_CONTEXT    *contextBlob,   // IN: context blob
			    TPM2B_SYM_KEY   *symKey,        // OUT: the symmetric key
			    TPM2B_IV        *iv             // OUT: the IV.
			    )
{
    UINT16           symKeyBits;    // number of bits in the parent's
    //   symmetric key
    TPM2B_AUTH      *proof = NULL;  // the proof value to use. Is null for
    //   everything but a primary object in
    //   the Endorsement Hierarchy
    
    BYTE             kdfResult[sizeof(TPMU_HA) * 2];// Value produced by the KDF
    
    TPM2B_DATA       sequence2B, handle2B;
    
    // Get proof value
    proof = HierarchyGetProof(contextBlob->hierarchy);
    
    // Get sequence value in 2B format
    sequence2B.t.size = sizeof(contextBlob->sequence);
    MemoryCopy(sequence2B.t.buffer, &contextBlob->sequence,
	       sizeof(contextBlob->sequence),
	       sizeof(sequence2B.t.buffer));
    
    // Get handle value in 2B format
    handle2B.t.size = sizeof(contextBlob->savedHandle);
    MemoryCopy(handle2B.t.buffer, &contextBlob->savedHandle,
	       sizeof(contextBlob->savedHandle),
	       sizeof(handle2B.t.buffer));
    
    // Get the symmetric encryption key size
    symKey->t.size = CONTEXT_ENCRYPT_KEY_BYTES;
    symKeyBits = CONTEXT_ENCRYPT_KEY_BITS;
    // Get the size of the IV for the algorithm
    iv->t.size = CryptGetSymmetricBlockSize(CONTEXT_ENCRYPT_ALG, symKeyBits);
    
    // KDFa to generate symmetric key and IV value
    KDFa(CONTEXT_INTEGRITY_HASH_ALG, &proof->b, "CONTEXT", &sequence2B.b,
	 &handle2B.b, (symKey->t.size + iv->t.size) * 8, kdfResult, NULL);
    
    // Copy part of the returned value as the key
    MemoryCopy(symKey->t.buffer, kdfResult, symKey->t.size,
	       sizeof(symKey->t.buffer));
    
    // Copy the rest as the IV
    MemoryCopy(iv->t.buffer, &kdfResult[symKey->t.size], iv->t.size,
	       sizeof(iv->t.buffer));
    
    return;
}

// 7.3.2.2	ComputeContextIntegrity()

// Generate the integrity hash for a context It is used by TPM2_ContextSave() to create an integrity
// hash and by TPM2_ContextLoad() to compare an integrity hash

void
ComputeContextIntegrity(
			TPMS_CONTEXT    *contextBlob,   // IN: context blob
			TPM2B_DIGEST    *integrity      // OUT: integrity
			)
{
    HMAC_STATE          hmacState;
    TPM2B_AUTH          *proof;
    UINT16              integritySize;
    
    // Get proof value
    proof = HierarchyGetProof(contextBlob->hierarchy);
    
    // Start HMAC
    integrity->t.size = CryptStartHMAC2B(CONTEXT_INTEGRITY_HASH_ALG,
					 &proof->b, &hmacState);
    
    // Compute integrity size at the beginning of context blob
    integritySize = sizeof(integrity->t.size) + integrity->t.size;
    
    // Adding total reset counter so that the context cannot be
    // used after a TPM Reset
    CryptUpdateDigestInt(&hmacState, sizeof(gp.totalResetCount),
			 &gp.totalResetCount);
    
    // If this is a ST_CLEAR object, add the clear count
    // so that this contest cannot be loaded after a TPM Restart
    if(contextBlob->savedHandle == 0x80000002)
	CryptUpdateDigestInt(&hmacState, sizeof(gr.clearCount), &gr.clearCount);
    
    // Adding sequence number to the HMAC to make sure that it doesn't
    // get changed
    CryptUpdateDigestInt(&hmacState, sizeof(contextBlob->sequence),
			 &contextBlob->sequence);
    
    // Protect the handle
    CryptUpdateDigestInt(&hmacState, sizeof(contextBlob->savedHandle),
			 &contextBlob->savedHandle);
    
    // Adding sensitive contextData, skip the leading integrity area
    CryptUpdateDigest(&hmacState, contextBlob->contextBlob.t.size - integritySize,
		      contextBlob->contextBlob.t.buffer + integritySize);
    
    // Complete HMAC
    CryptCompleteHMAC2B(&hmacState, &integrity->b);
    
    return;
}

// 7.3.2.3	SequenceDataImportExport()

// This function is used to scan through the sequence object and to modify the hash state data for
// export (contextSave) or to import it into the internal format (contextLoad). 

void
SequenceDataImportExport(
			 HASH_OBJECT         *object,        // IN/OUT: an internal hash object
			 HASH_OBJECT_BUFFER  *exportObject,  // IN/OUT: a sequence context in a buffer
			 IMPORT_EXPORT        direction
			 )
{
    // If the hash object is not an event, then only one hash context is needed
    int                   count = (object->attributes.eventSeq) ? HASH_COUNT : 1;
    
    for(count--; count >= 0; count--)
	{
	    HASH_STATE          *hash = &object->state.hashState[count];
	    size_t               offset = (BYTE *)hash - (BYTE *)object;
	    BYTE                *exportHash = &((BYTE *)exportObject)[offset];
	    
	    CryptHashStateImportExport(hash,
				       (HASH_STATE_BUFFER *)exportHash,
				       direction);
	}
}
