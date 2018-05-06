#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <map>
#include "Error.h"
#include "MemoryController.h"
#include "SimpleMapper.h"
#include "LockedMemory.h"
#pragma comment(lib, "psapi.lib")

PVOID AllocateKernelMemory( CapcomContext* CpCtx, KernelContext* KrCtx, SIZE_T Size )
{
	NON_PAGED_DATA static auto k_ExAllocatePool = KrCtx->GetProcAddress<fnFreeCall>( "ExAllocatePool" );
	NON_PAGED_DATA static uint64_t MemOut;

	CpCtx->ExecuteInKernel( NON_PAGED_LAMBDA( PVOID Pv )
	{
		MemOut = Khk_CallPassive( k_ExAllocatePool, 0ull, Pv );
	}, ( PVOID ) Size );

	return ( PVOID ) MemOut;
}

BOOL ExposeKernelMemoryToProcess( MemoryController& Mc, PVOID Memory, SIZE_T Size, uint64_t EProcess )
{
	Mc.AttachTo( EProcess );

	BOOL Success = FALSE;

	Mc.IterPhysRegion( Memory, Size, [ & ] ( PVOID Va, uint64_t Pa, SIZE_T Sz )
	{
		auto Info = Mc.QueryPageTableInfo( Va );

		Info.Pml4e->user = TRUE;
		Info.Pdpte->user = TRUE;
		Info.Pde->user = TRUE;

		if ( !Info.Pde || ( Info.Pte && ( !Info.Pte->present ) ) )
		{
			Success = FALSE;
		}
		else
		{
			if ( Info.Pte )
				Info.Pte->user = TRUE;
		}
	} );

	Mc.Detach();

	return Success;
}

PUCHAR FindKernelPadSinglePage( PUCHAR Start, SIZE_T Size )
{
	PUCHAR It = Start;

	MEMORY_BASIC_INFORMATION Mbi;

	PUCHAR StreakStart = 0;
	int Streak = 0;

	do
	{
		if ( ( 0x1000 - ( uint64_t( It ) & 0xFFF ) ) < Size )
		{
			It++;
			continue;
		}

		if ( *It == 0 )
		{
			if ( !Streak )
				StreakStart = It;
			Streak++;
		}
		else
		{
			Streak = 0;
			StreakStart = 0;
		}

		if ( Streak >= Size )
			return StreakStart;

		VirtualQuery( It, &Mbi, sizeof( Mbi ) );

		It++;
	}
	while ( ( Mbi.Protect == PAGE_EXECUTE_READWRITE || Mbi.Protect == PAGE_EXECUTE_READ || Mbi.Protect == PAGE_EXECUTE_WRITECOPY ) );
	return 0;
}

uint32_t FindProcess( const std::string& Name )
{
	PROCESSENTRY32 ProcessEntry;
	ProcessEntry.dwSize = sizeof( PROCESSENTRY32 );
	HANDLE ProcessSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
	if ( Process32First( ProcessSnapshot, &ProcessEntry ) )
	{
		do
		{
			if ( !stricmp( ProcessEntry.szExeFile, Name.data() ) )
			{
				CloseHandle( ProcessSnapshot );
				return ProcessEntry.th32ProcessID;
			}
		}
		while ( Process32Next( ProcessSnapshot, &ProcessEntry ) );
	}
	CloseHandle( ProcessSnapshot );
	return 0;
}


static const char* ConHdr = "=================================================\n"
                            "|             The Perfect Injector              |\n"
	                        "| This software is distributed free of charge.  |\n"
	                        "| If you bought this you have been scammed.     |\n"
	                        "| https://github.com/can1357/ThePerfectInjector |\n"
	                        "=================================================\n\n";

int main( int argc, char**argv )
{
	std::string ProcessName = argc > 1 ? argv[ 1 ] : "";
	std::string DllPath = argc > 2 ? argv[ 2 ] : "";

	// noloadlib, waitkey

	std::map<std::string, bool> Flags;

	if ( argc > 3 )
	{
		for ( int i = 3; i < argc; i++ )
		{
			std::string Str = argv[ i ];
			for ( auto& c : Str )
				c = tolower( c );
			Flags[ Str ] = true;
		}
	}

	SetConsoleTitleA( "The Perfect Injector" );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 0xF );
	printf( ConHdr );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 0x8 );

	if ( !ProcessName.size() )
	{
		printf( "Enter the target process name: " );
		std::cin >> std::ws;
		getline( std::cin, ProcessName );
	}
	if ( !DllPath.size() )
	{
		printf( "Enter the path to the module: " );
		std::cin >> std::ws;
		getline( std::cin, DllPath );
	}

	printf( "\n" );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 13 );


	printf( "Flags:         " );

	for ( int i = 3; i < argc; i++ )
		printf( "'%s' ", argv[ i ] );
	printf( "\n" );

	printf( "Dll Path:      '%s'\n", DllPath.data() );
	printf( "Process Name:  '%s'\n", ProcessName.data() );
	printf( "\n" );

	// Initialize physical memory controller
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 12 );
	KernelContext* KrCtx;
	CapcomContext* CpCtx;
	MemoryController Controller = Mc_InitContext( &CpCtx, &KrCtx );

	if ( Controller.CreationStatus )
		ERROR( "Controller Raised A Creation Status" );

	// Hook a very commonly used function
	PUCHAR _TlsGetValue = ( PUCHAR ) GetProcAddress( GetModuleHandleA( "KERNEL32" ), "TlsGetValue" ); // Not &TlsGetValue to avoid __imp intermodule calls

																									  // kernel32._TlsGetValue - EB 1E                 - jmp kernel32._TlsGetValue+
																									  // KERNEL32._TlsGetValue - E9 CBD70100           - jmp KERNEL32.UTUnRegister+160
	assert( *_TlsGetValue == 0xE9 || *_TlsGetValue == 0xEB );
	PUCHAR Target = ( *_TlsGetValue == 0xEB ) ? ( _TlsGetValue + 2 + *( int8_t* ) ( _TlsGetValue + 1 ) ) : ( _TlsGetValue + 5 + *( int32_t* ) ( _TlsGetValue + 1 ) );

	// Map module to kernel and create a hook stub
	std::vector<std::pair<PVOID, SIZE_T>> UsedRegions;

	TlsLockedHookController* TlsHookController = Mp_MapDllAndCreateHookEntry( DllPath, _TlsGetValue, Target, !Flags[ "noloadlib" ], [ & ] ( SIZE_T Size )
	{
		//return VirtualAlloc( 0, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		PVOID Memory = AllocateKernelMemory( CpCtx, KrCtx, Size );
		ExposeKernelMemoryToProcess( Controller, Memory, Size, Controller.CurrentEProcess );
		ZeroMemory( Memory, Size );
		UsedRegions.push_back( { Memory, Size } );
		return Memory;
	} );

	// Unload driver
	Cl_FreeContext( CpCtx );
	Kr_FreeContext( KrCtx );

	printf( "\n" );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 10 );

	if ( Flags[ "waitkey" ] )
	{
		printf( "Waiting for F2 key...\n" );
		while ( !( GetAsyncKeyState( VK_F2 ) & 0x8000 ) ) Sleep( 10 );
	}

	printf( "Waiting for %s...\n", ProcessName.data() );

	uint64_t Pid = 0;
	while ( !Pid )
	{
		Pid = FindProcess( ProcessName );
		Sleep( 10 );
	}

	printf( "Found %s. Pid 0x%04x!\n", ProcessName.data(), Pid );

	printf( "\n" );
	SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 11 );


	uint64_t EProcess = Controller.FindEProcess( Pid );
	printf( "[-] EProcess:                               %16llx\n", EProcess );

	if ( !EProcess )
		ERROR( "EProcess Not Valid" );

	// Expose region to process
	for ( auto Region : UsedRegions )
	{
		printf( "[-] Exposing %16llx (%08x bytes) to pid:%6llx\n", Region.first, Region.second, Pid );
		ExposeKernelMemoryToProcess( Controller, Region.first, Region.second, EProcess );
	}

	std::vector<BYTE> PidBasedHook =
	{
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,        // mov rax, gs:[0x30]
		0x8B, 0x40, 0x40,                                            // mov eax,[rax+0x40] ; pid
		0x3D, 0xDD, 0xCC, 0xAB, 0x0A,                                // cmp eax, 0xAABCCDD
		0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,                          // jne 0xAABBCC
		0x48, 0xB8, 0xAA, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00,  // mov rax, 0xAABBCCDDEEAA
		0xFF, 0xE0                                                   // jmp rax
	};

	PUCHAR PadSpace = FindKernelPadSinglePage( _TlsGetValue, PidBasedHook.size() );

	if ( !PadSpace )
		ERROR( "Couldn't Find Appropriate Padding" );

	printf( "[-] Hooking TlsGetValue @                   %16llx\n", _TlsGetValue );
	printf( "[-] TlsGetValue Redirection Target:         %16llx\n", Target );
	printf( "[-] Stub located at:                        %16llx\n", PadSpace );
	printf( "[-] Image located at:                       %16llx\n", TlsHookController );

	*( uint32_t* ) ( &PidBasedHook[ 0xD ] ) = Pid; // Pid
	*( int32_t* ) ( &PidBasedHook[ 0x13 ] ) = Target - ( PadSpace + 0x17 ); // Jmp
	*( PUCHAR* ) ( &PidBasedHook[ 0x19 ] ) = &TlsHookController->EntryBytes; // Hook target

																			 // Backup and complete hook
	BYTE Jmp[ 5 ];
	Jmp[ 0 ] = 0xE9;
	*( int32_t* ) ( Jmp + 1 ) = PadSpace - ( _TlsGetValue + 5 );

	std::vector<BYTE> Backup1( PidBasedHook.size(), 0 );
	std::vector<BYTE> Backup2( 5, 0 );

	TlsHookController->NumThreadsWaiting = 0;
	TlsHookController->IsFree = FALSE;

	Controller.Detach();


	auto AssertCoW = [ & ] ( PVOID Page )
	{
		VirtualLock( Page, 0x1 );

		PSAPI_WORKING_SET_EX_INFORMATION Ws;
		Ws.VirtualAddress = Page;
		QueryWorkingSetEx( HANDLE( -1 ), &Ws, sizeof( Ws ) );

		if ( !Ws.VirtualAttributes.Shared )
			ERROR( "Page Not CoW" );

		VirtualUnlock( Page, 0x1 );
	};

	// check maching memory checks AND is CoW check 

	printf( "[-] Writing stub to padding...\n" );
	AssertCoW( PadSpace );
	Controller.AttachIfCanRead( EProcess, PadSpace );
	Controller.ReadVirtual( PadSpace, Backup1.data(), PidBasedHook.size() );
	Controller.WriteVirtual( PidBasedHook.data(), PadSpace, PidBasedHook.size() );

	printf( "[-] Writing the hook to TlsGetValue...\n" );
	AssertCoW( _TlsGetValue );
	Controller.AttachIfCanRead( EProcess, _TlsGetValue );
	Controller.ReadVirtual( _TlsGetValue, Backup2.data(), 5 );
	Controller.WriteVirtual( Jmp, _TlsGetValue, 5 );

	printf( "[-] Hooked! Waiting for threads to spin...\n" );

	// Wait for threads to lock
	uint64_t TStart = GetTickCount64();
	while ( !Controller.ReadVirtual<BYTE>( &TlsHookController->NumThreadsWaiting ) && !( GetAsyncKeyState( VK_F1 ) & 0x8000 ) && ( ( GetTickCount64() - TStart ) < 5000 ) )
		Sleep( 1 );
	printf( "[-] Threads spinning:                       %16llx\n", TlsHookController->NumThreadsWaiting );

	// Restore Backup

	Controller.AttachIfCanRead( EProcess, _TlsGetValue );
	Controller.WriteVirtual( Backup2.data(), _TlsGetValue, 5 );
	
	
	if ( TlsHookController->NumThreadsWaiting )
		printf( "[-] Unhooked and started thread hijacking!\n" );
	else
		printf( "[-] ERROR: Wait timed out...\n" );

	TlsHookController->IsFree = TRUE;
	Sleep( 2000 );

	Controller.AttachIfCanRead( EProcess, PadSpace );
	Controller.WriteVirtual( Backup1.data(), PadSpace, PidBasedHook.size() );

	return system( "pause" );
}
