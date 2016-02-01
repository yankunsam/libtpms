/********************************************************************************/
/*										*/
/*										*/
/*			     Written by Stefan Berger				*/
/*			  Derived from openssl/MathFunctions.c			*/
/*		       IBM Thomas J. Watson Research Center			*/
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

/* rev 119 */

#include <string.h>

// B.5	MathFunctions.c

#include "FreeBLCryptoEngine.h"

// B.5.2.	Externally Accessible Functions
// B.5.2.1.	_math__Normalize2B()

// This function will normalize the value in a TPM2B. If there are leading bytes of zero, the first
// non-zero byte is shifted up.

//     Return Value	Meaning
//     0	no significant bytes, value is zero
//     >0	number of significant bytes

LIB_EXPORT UINT16
_math__Normalize2B(
		   TPM2B           *b              // IN/OUT: number to normalize
		   )
{	
    UINT16      from;
    UINT16      to;
    UINT16      size = b->size;
    
    
    for(from = 0; from < size && b->buffer[from] == 0; from++);
    b->size -= from;
    for(to = 0; from < size; to++, from++ )
	b->buffer[to] = b->buffer[from];
    return b->size;
}

//B.5.2.2.	_math__Denormalize2B()

// This function is used to adjust a TPM2B so that the number has the desired number of bytes. This
// is accomplished by adding bytes of zero at the start of the number.

// Return Value	Meaning
// TRUE	number de-normalized
// FALSE	number already larger than the desired size

LIB_EXPORT BOOL
_math__Denormalize2B(
		     TPM2B           *in,            // IN:OUT TPM2B number to de-normalize
		     UINT32           size           // IN: the desired size
		     )
{	
    UINT32       to;
    UINT32       from;
    // If the current size is greater than the requested size, see if this can be
    // normalized to a value smaller than the requested size and then de-normalize
    if(in->size > size)
	{
	    _math__Normalize2B(in);
	    if(in->size > size)
		return FALSE;
	}
    // If the size is already what is requested, leave
    if(in->size == size)
	return TRUE;
    
    // move the bytes to the 'right'
    for(from = in->size, to = size; from > 0;)
	in->buffer[--to] = in->buffer[--from];
    
    // 'to' will always be greater than 0 because we checked for equal above.
    for(; to > 0;)
	in->buffer[--to] = 0;
    
    in->size = (UINT16)size;
    return TRUE;
}
// B.5.2.3.	_math__sub()
// This function to subtract one unsigned value from another c = a - b. c may be the same as a or b.
//     Return Value	Meaning
//     1	if (a > b) so no borrow
//     0	if (a = b) so no borrow and b == a
//    -1	if (a < b) so there was a borrow

LIB_EXPORT int
_math__sub(
	   const UINT32     aSize,         // IN: size of a
	   const BYTE      *a,             // IN: a
	   const UINT32     bSize,         // IN: size of b
	   const BYTE      *b,             // IN: b
	   UINT16          *cSize,         // OUT: set to MAX(aSize, bSize)
	   BYTE            *c              // OUT: the difference
	   )
{
    int             borrow = 0;
    int             notZero = 0;
    int             i;
    int             i2;
    
    // set c to the longer of a or b
    *cSize = (UINT16)((aSize > bSize) ? aSize : bSize);
    // pick the shorter of a and b
    i = (aSize > bSize) ? bSize : aSize;
    i2 = *cSize - i;
    a = &a[aSize - 1];
    b = &b[bSize - 1];
    c = &c[*cSize - 1];
    for(; i > 0; i--)
	{
	    borrow = *a-- - *b-- + borrow;
	    *c-- = (BYTE)borrow;
	    notZero = notZero || borrow;
	    borrow >>= 8;
	}
    if(aSize > bSize)
	{
	    for(;i2 > 0; i2--)
		{
		    borrow = *a-- + borrow;
		    *c-- = (BYTE)borrow;
		    notZero = notZero || borrow;
		    borrow >>= 8;
		}
	}
    else if(aSize < bSize)
	{
	    for(;i2 > 0; i2--)
		{
		    borrow = 0 - *b-- + borrow;
		    *c-- = (BYTE)borrow;
		    notZero = notZero || borrow;
		    borrow >>= 8;
		}
	}
    // if there is a borrow, then b > a
    if(borrow)
	return -1;
    // either a > b or they are the same
    return notZero;
}

//     B.5.2.4.	_math__Inc()
//     This function increments a large, big-endian number value by one.
//     Return Value	Meaning
//     0	result is zero
//     !0	result is not zero

LIB_EXPORT int
_math__Inc(
	   UINT32           aSize,         // IN: size of a
	   BYTE            *a              // IN: a
	   )
{	
    
    for(a = &a[aSize-1];aSize > 0; aSize--)
	{
	    if((*a-- += 1) != 0)
		return 1;
	}
    return 0;
}

// B.5.2.5.	_math__Dec()
// This function decrements a large, ENDIAN value by one.

LIB_EXPORT void
_math__Dec(
	   UINT32           aSize,         // IN: size of a
	   BYTE            *a              // IN: a
	   )
{
    for(a = &a[aSize-1]; aSize > 0; aSize--)
	{
	    if((*a-- -= 1) != 0xff)
		return;
	}
    return;
}

#if 0   //% Math multiply is not currently used

// B.5.2.6.	_math__Mul()

// This function is used to multiply two large integers: p = a* b. If the size of p is not specified
// (pSize == NULL), the size of the results p is assumed to be aSize + bSize and the results are
// de-normalized so that the resulting size is exactly aSize + bSize. If pSize is provided, then the
// actual size of the result is returned. The initial value for pSize must be at least aSize +
// pSize.

//     Return Value	Meaning
//     < 0	indicates an error
//     >= 0	the size of the product

LIB_EXPORT int
_math__Mul(
	   const UINT32     aSize,         // IN: size of a
	   const BYTE      *a,             // IN: a
	   const UINT32     bSize,         // IN: size of b
	   const BYTE      *b,             // IN: b
	   UINT32          *pSize,         // IN/OUT: size of the product
	   BYTE            *p              // OUT: product. length of product = aSize +
	   //     bSize
	   )
{
    mpz_t           bnA;
    mpz_t           bnB;
    mpz_t           bnP;
    int             retVal = 0;


    // First check that pSize is large enough if present
    if((pSize != NULL) && (*pSize < (aSize + bSize)))
        return CRYPT_PARAMETER;
//    pAssert(*pSize < MAX_2B_BYTES);
    //
    // Allocate space for BIGNUM context
    //
    mpz_init(bnA);
    mpz_init(bnB);
    mpz_init(bnP);

    // Convert the inputs to BIGNUMs
    //
    mpz_bin2mpz(a, aSize, bnA);
    mpz_bin2mpz(b, bSize, bnB);

    // Perform the multiplication
    //
    mpz_mul(bnP, bnA, bnB);


    // If the size of the results is allowed to float, then set the return
    // size. Otherwise, it might be necessary to denormalize the results
    retVal = mpz_num_bytes(bnP);
    if(pSize == NULL)
    {
        mpz_mpz2bin(bnP, &p[aSize + bSize - retVal]);
        memset(p, 0, aSize + bSize - retVal);
        retVal = aSize + bSize;
    }
    else
    {
        mpz_mpz2bin(bnP, p);
        *pSize = retVal;
    }

    mpz_clear(bnP);
    mpz_clear(bnA);
    mpz_clear(bnB);
    return retVal;
}

#endif //%

// B.5.2.7.	_math__Div()

//     Divide an integer (n) by an integer (d) producing a quotient (q) and a remainder (r). If q or
//     r is not needed, then the pointer to them may be set to NULL.

//     Return Value	Meaning
//     CRYPT_SUCCESS	operation complete
//     CRYPT_UNDERFLOW	q or r is too small to receive the result

LIB_EXPORT CRYPT_RESULT
_math__Div(
	   const TPM2B     *n,             // IN: numerator
	   const TPM2B     *d,             // IN: denominator
	   TPM2B           *q,             // OUT: quotient
	   TPM2B           *r              // OUT: remainder
	   )
{
    mpz_t            bnN;
    mpz_t            bnD;
    mpz_t            bnQ;
    mpz_t            bnR;
    CRYPT_RESULT     retVal = CRYPT_SUCCESS;

    // Get structures for the big number representations
    mpz_init(bnN);
    mpz_init(bnD);
    mpz_init(bnQ);
    mpz_init(bnR);

    // Errors in BN_CTX_get() are sticky so only need to check the last allocation
    mpz_bin2mpz(n->buffer, n->size, bnN);
    mpz_bin2mpz(d->buffer, d->size, bnD);

    // Check for divide by zero.
    if(mpz_cmp_ui(bnD, 0UL) == 0)
        FAIL(FATAL_ERROR_DIVIDE_ZERO);

    // Perform the division
    mpz_fdiv_qr(bnQ, bnR, bnN, bnD);
        FAIL(FATAL_ERROR_INTERNAL);


    // Convert the BIGNUM result back to our format
    if(q != NULL)   // If the quotient is being returned
    {
        if(!MpzTo2B(q, bnQ, q->size))
        {
            retVal = CRYPT_UNDERFLOW;
            goto Done;
        }
     }
    if(r != NULL)   // If the remainder is being returned
    {
        if(!MpzTo2B(r, bnR, r->size))
            retVal = CRYPT_UNDERFLOW;
    }

Done:
    mpz_clear(bnN);
    mpz_clear(bnD);
    mpz_clear(bnQ);
    mpz_clear(bnR);

    return retVal;
}

// B.5.2.8.	_math__uComp()
// This function compare two unsigned values.
// Return Value	Meaning
// 1	if (a > b)
// 0	if (a = b)
// -1	if (a < b)

LIB_EXPORT int
_math__uComp(
	     const UINT32     aSize,         // IN: size of a
	     const BYTE      *a,             // IN: a
	     const UINT32     bSize,         // IN: size of b
	     const BYTE      *b              // IN: b
	     )
{
    int             borrow = 0;
    int             notZero = 0;
    int             i;
    // If a has more digits than b, then a is greater than b if
    // any of the more significant bytes is non zero
    if((i = (int)aSize - (int)bSize) > 0)
	for(; i > 0; i--)
	    if(*a++) // means a > b
		return 1;
    // If b has more digits than a, then b is greater if any of the
    // more significant bytes is non zero
    if(i < 0)  // Means that b is longer than a
	for(; i < 0; i++)
	    if(*b++) // means that b > a
		return -1;
    // Either the vales are the same size or the upper bytes of a or b are
    // all zero, so compare the rest
    i = (aSize > bSize) ? bSize : aSize;
    a = &a[i-1];
    b = &b[i-1];
    for(; i > 0; i--)
	{
	    borrow = *a-- - *b-- + borrow;
	    notZero = notZero || borrow;
	    borrow >>= 8;
	}
    // if there is a borrow, then b > a
    if(borrow)
	return -1;
    // either a > b or they are the same
    return notZero;
}

// B.5.2.9.	_math__Comp()
// Compare two signed integers:
// Return Value	Meaning
// 1	if a > b
// 0	if a = b
// -1	if a < b

LIB_EXPORT int
_math__Comp(
	    const UINT32     aSize,         // IN: size of a
	    const BYTE      *a,             // IN: a buffer
	    const UINT32     bSize,         // IN: size of b
	    const BYTE      *b              // IN: b buffer
	    )
{	
    int      signA, signB;       // sign of a and b
    
    // For positive or 0, sign_a is 1
    // for negative, sign_a is 0
    signA = ((a[0] & 0x80) == 0) ? 1 : 0;
    
    // For positive or 0, sign_b is 1
    // for negative, sign_b is 0
    signB = ((b[0] & 0x80) == 0) ? 1 : 0;
    
    if(signA != signB)
	{
	    return signA - signB;
	}
    
    if(signA == 1)
	// do unsigned compare function
	return _math__uComp(aSize, a, bSize, b);
    else
	// do unsigned compare the other way
	return 0 - _math__uComp(aSize, a, bSize, b);
}

// B.5.2.10.	_math__ModExp

// This function is used to do modular exponentiation in support of RSA. The most typical uses are:
// c = m^e mod n (RSA encrypt) and m = c^d mod n (RSA decrypt).  When doing decryption, the e
// parameter of the function will contain the private exponent d instead of the public exponent e.

// If the results will not fit in the provided buffer, an error is returned
// (CRYPT_ERROR_UNDERFLOW). If the results is smaller than the buffer, the results is de-normalized.

// This version is intended for use with RSA and requires that m be less than n.

//     Return Value	Meaning
//     CRYPT_SUCCESS	exponentiation succeeded
//     CRYPT_PARAMETER	number to exponentiate is larger than the modulus
//     CRYPT_UNDERFLOW	result will not fit into the provided buffer

LIB_EXPORT CRYPT_RESULT
_math__ModExp(
	      UINT32           cSize,         // IN: size of the results
	      BYTE            *c,             // OUT: results buffer
	      const UINT32     mSize,         // IN: size of number to be exponentiated
	      const BYTE      *m,             // IN: number to be exponentiated
	      const UINT32     eSize,         // IN: size of power
	      const BYTE      *e,             // IN: power
	      const UINT32     nSize,         // IN: modulus size
	      const BYTE      *n              // IN: modulus
	      )
{
    CRYPT_RESULT     retVal = CRYPT_SUCCESS;
    mpz_t            bnC;
    mpz_t            bnM;
    mpz_t            bnE;
    mpz_t            bnN;
    INT32            i;

    mpz_init(bnC);
    mpz_init(bnM);
    mpz_init(bnE);
    mpz_init(bnN);

    //convert arguments
    mpz_bin2mpz(m, mSize, bnM);
    mpz_bin2mpz(e, eSize, bnE);
    mpz_bin2mpz(n, nSize, bnN);

    // Don't do exponentiation if the number being exponentiated is
    // larger than the modulus.
    if(mpz_cmpabs(bnM, bnN) >= 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }
    // Perform the exponentiation
    mpz_powm(bnC, bnM, bnE, bnN);

    // Convert the results
    // Make sure that the results will fit in the provided buffer.
    if ((unsigned)mpz_num_bytes(bnC) > cSize)
    {
        retVal = CRYPT_UNDERFLOW;
        goto Cleanup;
    }
    i = cSize - mpz_num_bytes(bnC);
    mpz_mpz2bin(bnC, &c[i]);
    memset(c, 0, i);

Cleanup:
    // Free up allocated BN values
    mpz_clear(bnC);
    mpz_clear(bnM);
    mpz_clear(bnE);
    mpz_clear(bnN);
    return retVal;
}

// 	B.5.2.11.	_math__IsPrime()
// 	Check if an 32-bit integer is a prime.
// 	Return Value	Meaning
// 	TRUE	if the integer is probably a prime
// 	FALSE	if the integer is definitely not a prime

LIB_EXPORT BOOL
_math__IsPrime(
	       const UINT32     prime
	       )
{
    int     isPrime;
    mpz_t   p;

    // Assume the size variables are not overflow, which should not happen in
    // the contexts that this function will be called.
    mpz_init(p);

    mpz_set_ui(p, prime);

    //
    // BN_is_prime returning -1 means that it ran into an error.
    // It should only return 0 or 1
    //
    isPrime = mpz_probab_prime_p(p, 7);

    mpz_clear(p);

    return (isPrime >= 1);
}

