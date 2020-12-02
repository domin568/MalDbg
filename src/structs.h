// From blogpost http://blog.rewolf.pl/blog/?p=573 and https://www.aldeid.com/wiki/LDR_DATA_TABLE_ENTRY
#pragma once
#pragma pack(push)
#pragma pack(1)

typedef struct 
{
  union 
  {
    char e_name[8];
    struct 
    {
      unsigned long e_zeroes;
      unsigned long e_offset;
    } e;
  } e;
  unsigned long e_value;
  short e_scnum;
  unsigned short e_type;
  unsigned char e_sclass;
  unsigned char e_numaux;
} COFFentry;

template <class T>
struct LIST_ENTRY_T
{
	T Flink;
	T Blink;
};
template <class T>
struct UNICODE_STRING_T
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T _Buffer;
};

template <class T>
struct _LDR_DATA_TABLE_ENTRY
{
    //LIST_ENTRY InLoadOrderLinks; /* 0x00 */
    LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
    LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
    PVOID DllBase; /* 0x18 */
    PVOID EntryPoint;
    T SizeOfImage;
    UNICODE_STRING_T<T> FullDllName;
    UNICODE_STRING_T<T> BaseDllName;
    T Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
         LIST_ENTRY HashLinks;
         struct
         {
              PVOID SectionPointer;
              T CheckSum;
         };
    };
    union
    {
         T TimeDateStamp;
         PVOID LoadedImports;
    };
    _ACTIVATION_CONTEXT * EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
};

typedef struct _PEB_LDR_DATA64
{
	ULONG         Length;                            /* Size of structure, used by ntdll.dll as structure version ID */
	uint32_t       Initialized;                       /* If set, loader data section for current process is initialized */
	PVOID         SsHandle;
	DWORD64    InLoadOrderModuleList           [2];             /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in load order */
	DWORD64    InMemoryOrderModuleList         [2];           /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in memory placement order */
	DWORD64    InInitializationOrderModuleList [2];   /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in initialization order */

} PEB_LDR_DATA64,*PPEB_LDR_DATA64; // +0x24
typedef struct _PEB_LDR_DATA32
{
	uint32_t         Length;                            /* Size of structure, used by ntdll.dll as structure version ID */
	uint32_t       Initialized;                       /* If set, loader data section for current process is initialized */
	uint32_t         SsHandle;
	DWORD32    InLoadOrderModuleList           [2];             /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in load order */
	DWORD32    InMemoryOrderModuleList         [2];           /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in memory placement order */
	DWORD32    InInitializationOrderModuleList [2];   /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in initialization order */
} PEB_LDR_DATA32,*PPEB_LDR_DATA32; // +0x24
  
template <class T, class NGF, int A>
struct _PEB_T
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE _SYSTEM_DEPENDENT_01;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T _SYSTEM_DEPENDENT_02;
	T _SYSTEM_DEPENDENT_03;
	T _SYSTEM_DEPENDENT_04;
	union
	{
		T KernelCallbackTable;
		T UserSharedInfoPtr;
	};
	DWORD SystemReserved;
	DWORD _SYSTEM_DEPENDENT_05;
	T _SYSTEM_DEPENDENT_06;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T _SYSTEM_DEPENDENT_07;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	union
	{
		T ImageProcessAffinityMask;
		T ActiveProcessAffinityMask;
	};
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
};

struct exceptionData
{
    DWORD exceptionType;
    DWORD rip;
    bool oneHitBreakpoint;
};
struct function
{
    std::string name;
    uint64_t start;
    uint64_t end;
};
typedef struct _PROCESS_BASIC_INFORMATION64 {
    NTSTATUS ExitStatus;
    UINT32 Reserved0;
    UINT64 PebBaseAddress;
    UINT64 AffinityMask;
    UINT32 BasePriority;
    UINT32 Reserved1;
    UINT64 UniqueProcessId;
    UINT64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;

typedef struct _PROCESS_BASIC_INFORMATION32 {
    NTSTATUS ExitStatus;
    UINT32 PebBaseAddress;
    UINT32 AffinityMask;
    UINT32 BasePriority;
    UINT32 UniqueProcessId;
    UINT32 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;


 
typedef _LDR_DATA_TABLE_ENTRY<DWORD> LDR_TABLE32;
typedef _LDR_DATA_TABLE_ENTRY<DWORD64> LDR_TABLE64;
typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;
#pragma pack(pop)