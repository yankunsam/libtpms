/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Time.c 471 2015-12-22 19:40:24Z kgoldman $			*/
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

// 8.9	Time.c
// 8.9.1	Introduction

// This file contains the functions relating to the TPM's time functions including the interface to
// the implementation-specific time functions.

// 8.9.2	Includes

#include "InternalRoutines.h"
#include "Platform.h"

// 8.9.3	Functions
// 8.9.3.1	TimePowerOn()
// This function initialize time info at _TPM_Init().

void
TimePowerOn(
	    void
	    )
{
    TPM_SU          orderlyShutDown;
    
    // Read orderly data info from NV memory
    NvReadReserved(NV_ORDERLY_DATA, &go);
    
    // Read orderly shut down state flag
    NvReadReserved(NV_ORDERLY, &orderlyShutDown);
    
    // If the previous cycle is orderly shut down, the value of the safe bit
    // the same as previously saved.  Otherwise, it is not safe.
    if(orderlyShutDown == SHUTDOWN_NONE)
	go.clockSafe= NO;
    else
	go.clockSafe = YES;
    
    // Set the initial state of the DRBG
    CryptDrbgGetPutState(PUT_STATE);
    
    // Clear time since TPM power on
    g_time = 0;
    
    // And reset the DA timers
    DAInit();

    return;
}

// 8.9.3.2	TimeStartup()
// This function updates the resetCount and restartCount components of TPMS_CLOCK_INFO structure at TPM2_Startup().

void
TimeStartup(
	    STARTUP_TYPE     type           // IN: start up type
	    )
{
    if(type == SU_RESUME)
	{
	    // Resume sequence
	    gr.restartCount++;
	}
    else
	{
	    if(type == SU_RESTART)
		{
		    // Hibernate sequence
		    gr.clearCount++;
		    gr.restartCount++;
		}
	    else
		{
		    // Reset sequence
		    // Increase resetCount
		    gp.resetCount++;
		    
		    // Write resetCount to NV
		    NvWriteReserved(NV_RESET_COUNT, &gp.resetCount);
		    gp.totalResetCount++;
		    
		    // We do not expect the total reset counter overflow during the life
		    // time of TPM.  if it ever happens, TPM will be put to failure mode
		    // and there is no way to recover it.
		    // The reason that there is no recovery is that we don't increment
		    // the NV totalResetCount when incrementing would make it 0. When the
		    // TPM starts up again, the old value of totalResetCount will be read
		    // and we will get right back to here with the increment failing.
		    if(gp.totalResetCount == 0)
			FAIL(FATAL_ERROR_INTERNAL);
		    
		    // Write total reset counter to NV
		    NvWriteReserved(NV_TOTAL_RESET_COUNT, &gp.totalResetCount);
		    
		    // Reset restartCount
		    gr.restartCount = 0;
		}
	}
    
    return;
}

// 8.9.3.3	TimeClockUpdate()

// This function updates go.clock. If newTime requries an update of NV, then NV is checked for
// availability. If it is not available or is rate limiting, then go.clock is not updated and the
// function returns an error. If newTime would not cause an NV write, then go.clock is updated. If
// an NV write occurs, then go.safe is SET.

// Error Returns	Meaning
// TPM_RC_NV_RATE	NV cannot be written because it is rate limiting
// TPM_RC_NV_UNAVAILABLE	NV cannot be accessed

TPM_RC
TimeClockUpdate(
		UINT64           newTime
		)
{
    TPM_RC          result;
    
#define CLOCK_UPDATE_MASK  ((1ULL << NV_CLOCK_UPDATE_INTERVAL)- 1)
    
    // Check to see if the update will cause a need for an nvClock update
    if((newTime | CLOCK_UPDATE_MASK) > (go.clock | CLOCK_UPDATE_MASK))
	{
	    result = NvIsAvailable();
	    if(result != TPM_RC_SUCCESS)
		return result;
	    
	    // Going to update the NV time state so SET the safe flag
	    go.clockSafe = YES;
	    
	    // update the time
	    go.clock = newTime;
	    
	    // Get the DRBG state before updating orderly data
	    CryptDrbgGetPutState(GET_STATE);
	    
	    NvWriteReserved(NV_ORDERLY_DATA, &go);
	}
    else
	// No NV udpate needed so just update
	go.clock = newTime;
    
    return TPM_RC_SUCCESS;
    
}

/* 8.9.3.4	TimeUpdateToCurrent() */
/* This function updates the Time and Clock in the global TPMS_TIME_INFO structure. */
/* In this implementation, Time and Clock are updated at the beginning of each command and the
   values are unchanged for the duration of the command. */
/* Because Clock updates may require a write to NV memory, Time and Clock are not allowed to advance
   if NV is not available. When clock is not advancing, any function that uses Clock will fail
   and return TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE. */
/* This implementation does not do rate limiting. If the implementation does do rate limiting, then
   the Clock update should not be inhibited even when doing rate limiting. */

void
TimeUpdateToCurrent(
		    void
		    )
{
    UINT64          newClock;
    UINT64          elapsed;
    
    // Can't update time during the dark interval or when rate limiting. This is
    // checked here because we can't call _plat__ClockTimeElapsed() unless we
    // are going to update the time values based on the value returned. If we got
    // the elapsed time and discarded it we could loose blocks of time. In most
    // cases this is not a problem unless we are doing a lot of rate limiting.
    if(NvIsAvailable() != TPM_RC_SUCCESS)
	return;
    
    // Update the time info to current
    elapsed = _plat__ClockTimeElapsed();
    newClock = go.clock + elapsed;
    g_time += elapsed;
    
    // Don't need to check the result because it has to be success because have
    // already checked that NV is available.
    TimeClockUpdate(newClock);
    
    // Call self healing logic for dictionary attack parameters
    DASelfHeal();
    
    return;
}

// 8.9.3.5	TimeSetAdjustRate()
// This function is used to perform rate adjustment on Time and Clock.

void
TimeSetAdjustRate(
		  TPM_CLOCK_ADJUST     adjust         // IN: adjust constant
		  )
{
    switch(adjust)
	{
	  case TPM_CLOCK_COARSE_SLOWER:
	    _plat__ClockAdjustRate(CLOCK_ADJUST_COARSE);
	    break;
	  case TPM_CLOCK_COARSE_FASTER:
	    _plat__ClockAdjustRate(-CLOCK_ADJUST_COARSE);
	    break;
	  case TPM_CLOCK_MEDIUM_SLOWER:
	    _plat__ClockAdjustRate(CLOCK_ADJUST_MEDIUM);
	    break;
	  case TPM_CLOCK_MEDIUM_FASTER:
	    _plat__ClockAdjustRate(-CLOCK_ADJUST_MEDIUM);
	    break;
	  case TPM_CLOCK_FINE_SLOWER:
	    _plat__ClockAdjustRate(CLOCK_ADJUST_FINE);
	    break;
	  case TPM_CLOCK_FINE_FASTER:
	    _plat__ClockAdjustRate(-CLOCK_ADJUST_FINE);
	    break;
	  case TPM_CLOCK_NO_CHANGE:
	    break;
	  default:
	    pAssert(FALSE);
	    break;
	}
    
    return;
}

// 8.9.3.6	TimeGetRange()

// This function is used to access TPMS_TIME_INFO. The TPMS_TIME_INFO structure is treaded as an
// array of bytes, and a byte offset and length determine what bytes are returned.

//     Error Returns	Meaning
//     TPM_RC_RANGE	invalid data range
//     TPM_RC_VALUE	invalid offset value

TPM_RC
TimeGetRange(
	     UINT16           offset,        // IN: offset in TPMS_TIME_INFO
	     UINT16           size,          // IN: size of data
	     TIME_INFO       *dataBuffer     // OUT: result buffer
	     )
{
    TPMS_TIME_INFO      timeInfo;
    UINT16              infoSize;
    BYTE                infoData[sizeof(TPMS_TIME_INFO)];
    BYTE                *buffer;
    
    // Fill TPMS_TIME_INFO structure
    timeInfo.time = g_time;
    TimeFillInfo(&timeInfo.clockInfo);
    
    // Marshal TPMS_TIME_INFO to canonical form
    buffer = infoData;
    infoSize = TPMS_TIME_INFO_Marshal(&timeInfo, &buffer, NULL);
    
    // Make sure that offset is within range
    if(offset > infoSize)
	return TPM_RC_VALUE;
    
    // Check if the input range is valid
    if(size > (infoSize - offset))
	return TPM_RC_RANGE;
    
    // Copy info data to output buffer
    MemoryCopy(dataBuffer, infoData + offset, size, sizeof(TIME_INFO));
    
    return TPM_RC_SUCCESS;
}

// 8.9.3.7	TimeFillInfo
// This function gathers information to fill in a TPMS_CLOCK_INFO structure.

void
TimeFillInfo(
	     TPMS_CLOCK_INFO     *clockInfo
	     )
{
    clockInfo->clock = go.clock;
    clockInfo->resetCount = gp.resetCount;
    clockInfo->restartCount = gr.restartCount;
    
    // If NV is not available, clock stopped advancing and the value reported is
    // not "safe".
    if(NvIsAvailable() == TPM_RC_SUCCESS)
	clockInfo->safe = go.clockSafe;
    else
	clockInfo->safe = NO;
    
    return;
}
