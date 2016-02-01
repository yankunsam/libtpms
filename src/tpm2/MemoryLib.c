/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: MemoryLib.c 141 2015-03-16 17:08:34Z kgoldman $               */
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

/* rev 122 */

// 9.12	MemoryLib.c
// 9.12.1	Description

// This file contains a set of miscellaneous memory manipulation routines. Many of the functions
// have the same semantics as functions defined in string.h. Those functions are not used in the TPM
// in order to avoid namespace contamination.

// 9.12.2	Includes and Data Definitions

#define MEMORY_LIB_C
#include "InternalRoutines.h"

// These buffers are set aside to hold command and response values. In this implementation, it is
// not guaranteed that the code will stop accessing the s_actionInputBuffer before starting to put
// values in the s_actionOutputBuffer so different buffers are required. However, the
// s_actionInputBuffer and s_responseBuffer are not needed at the same time and they could be the
// same buffer.

// In this version, use is made of the functions defined in <string.h>. This is because the math
// libraries use these functions so it is not possible to avoid having them pulled in to the
// build. The difference is that these functions provide checking that is not part of the standard
// library, like checking that the data will fit in the destination.

// 9.12.3	Functions on BYTE Arrays
// 9.12.3.1	MemoryMove()

// This function moves data from one place in memory to another. No safety checks of any type
// are performed. If source and data buffer overlap, then the move is done as if an intermediate
// buffer were used.

// NOTE: This function is used by MemoryCopy(), MemoryCopy2B(), and MemoryConcat2b() and
// requires that the caller know the maximum size of the destination buffer so that there is no
// possibility of buffer overrun.

#if 0 //% Set to 0 to use macros and 1 to use function calls
LIB_EXPORT void
MemoryMove(
	   void            *destination,   // OUT: move destination
	   const void      *source,        // IN: move source
	   UINT32           sSize,         // IN: number of octets to moved
	   UINT32           dSize          // IN: size of the receive buffer
	   )
{
    if(destination == NULL || source == NULL)
	return;
    if (dSize < sSize)
	FAIL(FATAL_ERROR_MOVE_SIZE);
    if(destination != source)
	memmove(destination, source, sSize);
    return;
}
#else //%
//%#define MemoryMove(dest, src, sSize, dSize)
//%            ((sSize > dSize) ? FAIL(FATAL_ERROR_MOVE_SIZE)
//%                            : (void)memmove((dest), (src), (sSize)))
#endif //%

// 9.12.3.2 MemoryCopy() This is an alias for MemoryMove(). If the macro form of MemoryMove() is
// used, the macro form of MemoryCopy() is also used.

#ifndef MemoryMove //%
void
MemoryCopy(
	   void            *destination,           // OUT: copy destination
	   void            *source,                // IN: copy source
	   UINT32           size,                  // IN: number of octets being copied
	   UINT32           dSize                  // IN: size of the receive buffer
	   )
{
    MemoryMove(destination, source, size, dSize);
}
#else //%
//%#define MemoryCopy(destination, source, size, destSize)
//%    MemoryMove((destination), (source), (size), (destSize))
#endif //%

// 9.12.3.3	MemoryEqual()
// This function indicates if two buffers have the same values in the indicated number of bytes.
// Return Value	Meaning
// TRUE	all octets are the same
// FALSE	all octets are not the same

LIB_EXPORT BOOL
MemoryEqual(
	    const void      *buffer1,       // IN: compare buffer1
	    const void      *buffer2,       // IN: compare buffer2
	    UINT32           size           // IN: size of bytes being compared
	    )
{
    BOOL         equal = TRUE;
    const BYTE  *b1, *b2;
    
    b1 = (BYTE *)buffer1;
    b2 = (BYTE *)buffer2;
    
    // Compare all bytes so that there is no leakage of information
    // due to timing differences.
    for(; size > 0; size--)
	equal = (*b1++ == *b2++) && equal;
    
    return equal;
}

// 9.12.3.4	MemoryCopy2B()

// This function copies a TPM2B. This can be used when the TPM2B types are the same or different. No
// size checking is done on the destination so the caller should make sure that the destination is
// large enough.

// This function returns the number of octets in the data buffer of the TPM2B.

LIB_EXPORT INT16
MemoryCopy2B(
	     TPM2B           *dest,          // OUT: receiving TPM2B
	     const TPM2B     *source,        // IN: source TPM2B
	     UINT16           dSize          // IN: size of the receiving buffer
	     )
{
    
    if(dest == NULL)
	return 0;
    if(source == NULL)
	dest->size = 0;
    else
	{
	    dest->size = source->size;
	    MemoryMove(dest->buffer, source->buffer, dest->size, dSize);
	}
    return dest->size;
}

// 9.12.3.5	MemoryConcat2B()

// This function will concatenate the buffer contents of a TPM2B to an the buffer contents of
// another TPM2B and adjust the size accordingly (a := (a | b)).

LIB_EXPORT void
MemoryConcat2B(
	       TPM2B           *aInOut,        // IN/OUT: destination 2B
	       TPM2B           *bIn,           // IN: second 2B
	       UINT16           aSize          // IN: The size of aInOut.buffer (max values for
	       //     aInOut.size)
	       )
{
    MemoryMove(&aInOut->buffer[aInOut->size],
	       &bIn->buffer,
	       bIn->size,
	       aSize - aInOut->size);
    aInOut->size = aInOut->size + bIn->size;
    return;
}

// 9.12.3.6	Memory2BEqual()

// This function will compare two TPM2B structures. To be equal, they need to be the same size and
// the buffer contexts need to be the same in all octets.

//     Return Value	Meaning
//     TRUE	size and buffer contents are the same
//     FALSE	size or buffer contents are not the same

LIB_EXPORT BOOL
Memory2BEqual(
	      const TPM2B     *aIn,           // IN: compare value
	      const TPM2B     *bIn            // IN: compare value
	      )
{
    if(aIn->size != bIn->size)
	return FALSE;
    
    return MemoryEqual(aIn->buffer, bIn->buffer, aIn->size);
}

// 9.12.3.7	MemorySet()

// This function will set all the octets in the specified memory range to the specified octet value.

// NOTE: the dSize parameter forces the caller to know how big the receiving buffer is to make sure
// that there is no possibility that the caller will inadvertently run over the end of the buffer.

#ifndef MemoryMove //%
LIB_EXPORT void
MemorySet(
	  void            *destination,   // OUT: memory destination
	  char             value,         // IN: fill value
	  UINT32           size           // IN: number of octets to fill
	  )
{
    char *p = (char *)destination;
    while (size--)
	*p++ = value;
    return;
}
#else   //%
//%#define MemorySet(destination, value, size)
//%    memset((destination), (value), (size))
#endif //%

// 9.12.3.8	MemoryGetActionInputBuffer()

// This function returns the address of the buffer into which the command parameters will be
// unmarshaled in preparation for calling the command actions.

BYTE *
MemoryGetActionInputBuffer(
			   UINT32           size           // Size, in bytes, required for the input
			   // unmarshaling
			   )
{
    pAssert(size <= sizeof(s_actionInputBuffer));
    // In this implementation, a static buffer is set aside for the command action
    // input buffer.
    memset(s_actionInputBuffer, 0, size);
    return (BYTE *)&s_actionInputBuffer[0];
}

// 9.12.3.9	MemoryGetActionOutputBuffer()
// This function returns the address of the buffer into which the command action code places its output values.

void *
MemoryGetActionOutputBuffer(
			    UINT32           size           // required size of the buffer
			    )
{
    pAssert(size < sizeof(s_actionOutputBuffer));
    // In this implementation, a static buffer is set aside for the command action
    // output buffer.
    memset(s_actionOutputBuffer, 0, size);
    return s_actionOutputBuffer;
}

// 9.12.3.10	MemoryGetResponseBuffer()

// This function returns the address into which the command response is marshaled from values in the
// action output buffer.

BYTE *
MemoryGetResponseBuffer(
			COMMAND_INDEX    commandIndex   // Command that requires the buffer
			)
{
    // In this implementation, a static buffer is set aside for responses.
    // Other implementation may apply additional optimization based on the command
    // code or other factors.
    NOT_REFERENCED(commandIndex);        // Unreferenced parameter
    return s_responseBuffer;
}

// 9.12.3.11	MemoryRemoveTrailingZeros()

// This function is used to adjust the length of an authorization value. It adjusts the size of the
// TPM2B so that it does not include octets at the end of the buffer that contain zero. The function
// returns the number of non-zero octets in the buffer.

UINT16
MemoryRemoveTrailingZeros (
			   TPM2B_AUTH      *auth           // IN/OUT: value to adjust
			   )
{
    BYTE        *a = &auth->t.buffer[auth->t.size-1];
    for(; auth->t.size > 0; auth->t.size--)
	{
	    if(*a--)
		break;
	}
    return auth->t.size;
}
