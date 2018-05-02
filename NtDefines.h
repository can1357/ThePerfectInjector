#pragma once
#include <Windows.h>
#pragma pack(push, 8)
typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[ 256 ];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[ 0 ];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;

#define NtCurrentProcess() ( HANDLE(-1) )
#define SeLoadDriverPrivilege 10ull
#define SystemModuleInformation 0xBull
#define AdjustCurrentProcess 0ull
#define STATUS_SUCCESS 0
#pragma pack(pop)

using fnFreeCall = uint64_t( __fastcall* )( ... );

template<typename ...Params>
static NTSTATUS __NtRoutine( const char* Name, Params &&... params )
{
	auto fn = ( fnFreeCall ) GetProcAddress( GetModuleHandleA( "ntdll.dll" ), Name );
	return fn( std::forward<Params>( params ) ... );
}

#define NtQuerySystemInformation(...) __NtRoutine("NtQuerySystemInformation", __VA_ARGS__)
#define RtlAdjustPrivilege(...) __NtRoutine("RtlAdjustPrivilege", __VA_ARGS__)
#define NtUnloadDriver(...) __NtRoutine("NtUnloadDriver", __VA_ARGS__)
#define NtLoadDriver(...) __NtRoutine("NtLoadDriver", __VA_ARGS__)

static BOOL AcquirePrivilege( DWORD Privilage, DWORD Proc )
{
	BOOLEAN Enabled = 0;
	return !RtlAdjustPrivilege( Privilage, 1ull, Proc, &Enabled ) || Enabled;
}