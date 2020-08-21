#pragma once
#include <windows.h>
#include <inttypes.h>
#include <stdio.h>

enum class breakpointType
{
	SOFTWARE_TYPE = 0,
	HARDWARE_TYPE = 1,
};

class breakpoint 
{
	private:
		bool isOneHit;
		bool apiLog;
		void * address;
		uint64_t hitCount = 0;
		uint8_t originalByte;
		breakpointType type;
	public:
		breakpoint (void *, breakpointType, bool, bool);
		bool set (HANDLE);
		bool restore (HANDLE);
		bool setAgain (HANDLE);
		void incrementHitCount ();
		void * getAddress () { return address; }
		uint8_t getOriginalByte () { return originalByte; }
		breakpointType getType () { return type; }
		bool getIsOneHit () { return isOneHit; }
		bool isApiLog () { return apiLog; }
		uint64_t getHitCount () { return hitCount; } 
		bool operator== (const breakpoint & other);

};