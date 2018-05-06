#pragma once
#include <Windows.h>
#include <fstream>
#include <vector>
#include <functional>

#pragma pack(push, 1)
struct TlsLockedHookController
{
	BYTE IsFree;
	BYTE NumThreadsWaiting;
	BYTE EntryBytes;
};
#pragma pack(pop)

static std::vector<BYTE> Mp_ReadFile( const std::string& Path )
{
	std::ifstream Stream( Path, std::ios::binary | std::ios::ate );
	std::ifstream::pos_type Pos = Stream.tellg();

	if ( Pos == ( std::ifstream::pos_type ) - 1 )
		return {};

	std::vector<BYTE> Data( Pos );
	Stream.seekg( 0, std::ios::beg );
	Stream.read( ( char* ) &Data[ 0 ], Pos );

	return Data;
}

static void * Mp_RvaToPointer( BYTE* Image, DWORD Va )
{
	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Image;
	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );

	PIMAGE_SECTION_HEADER SectionHeader = ( PIMAGE_SECTION_HEADER )
		( ( ( ULONG_PTR ) &FileHeader->OptionalHeader ) + FileHeader->FileHeader.SizeOfOptionalHeader );

	for ( int i = 0; i < FileHeader->FileHeader.NumberOfSections; i++ )
	{
		char * Name = ( char* ) SectionHeader[ i ].Name;
		DWORD RawData = SectionHeader[ i ].PointerToRawData;
		DWORD VirtualAddress = SectionHeader[ i ].VirtualAddress;
		DWORD RawSize = SectionHeader[ i ].SizeOfRawData;
		DWORD VirtualSize = SectionHeader[ i ].Misc.VirtualSize;

		if ( Va >= VirtualAddress &&
			 Va < ( VirtualAddress + VirtualSize ) )
		{
			return Image + Va - VirtualAddress + RawData;
		}
	}
	return Image + Va;
}

static void Mp_PushBytes( std::vector<BYTE>& Target, const std::vector<BYTE>& Bytes )
{
	int i = Target.size();
	Target.resize( i + Bytes.size() );
	memcpy( &Target[ i ], &Bytes[ 0 ], Bytes.size() );
}

static std::vector<BYTE> Mp_CreateImportShell( BYTE* Image, PVOID MappedAdr, bool LoadLib )
{
	// no handle, no access to modules /shrug
	// could prob read EProcess->Peb but cba sorry

	std::vector<BYTE> Out =
	{ 
		0x48, 0x83, 0xEC, 0x38,                                       // sub    rsp,0x38
		0x4C, 0x8D, 0x3D, 0xDD, 0xCC, 0xBB, 0x00,                     // lea r15, [rip+0xBBCCDD]
		0x48, 0xB8, 0xAA, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00,   // mov rax, 0xAABBCCDDEEAA ; GetModuleHandleA // LoadLibraryA?
		0x49, 0x89, 0xC5,                                             // mov r13, rax
		0x48, 0xB8, 0xAA, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00,   // mov rax, 0xAABBCCDDEEAA ; GetProcAddress
		0x49, 0x89, 0xC4                                              // mov r11, rax
	};

	*( FARPROC* ) &Out[ 0xD ] = LoadLib ? GetProcAddress( GetModuleHandleA( "KERNEL32" ), "LoadLibraryA" ) : GetProcAddress( GetModuleHandleA( "KERNEL32" ), "GetModuleHandleA" ); // avoding __imp's
	*( FARPROC* ) &Out[ 0x1A ] = GetProcAddress( GetModuleHandleA( "KERNEL32" ), "GetProcAddress" );   // avoding __imp's

	std::vector<BYTE> DataContainer = {};

	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Image;
	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &FileHeader->OptionalHeader;

	PIMAGE_IMPORT_DESCRIPTOR  ImportDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR ) Mp_RvaToPointer
	(
		Image,
		FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress
	);

	while ( ImportDescriptor && ImportDescriptor->Name && FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
	{
		PCHAR ModuleName = ( PCHAR ) Mp_RvaToPointer( Image, ImportDescriptor->Name );

		IMAGE_THUNK_DATA * Thunk = NULL;
		IMAGE_THUNK_DATA * Func = NULL;

		uint32_t ModuleNameOffset = DataContainer.size();

		do
			DataContainer.push_back( *ModuleName );
		while ( *ModuleName++ );

		std::vector<BYTE> ModulePusher =
		{ 
			0x49, 0x8D, 0x8F, 0xBB, 0xAA, 0x00, 0x00,  // lea    rcx,[r15+0xaabb]
			0x41, 0xFF, 0xD5,                          // call   r13
			0x48, 0x89, 0xC6                           // mov    rsi,rax
		};

		*( uint32_t* ) ( &ModulePusher[ 3 ] ) = ModuleNameOffset;

		Mp_PushBytes( Out, ModulePusher );

		if ( ImportDescriptor->OriginalFirstThunk )
		{
			Thunk = ( IMAGE_THUNK_DATA* ) Mp_RvaToPointer( Image, ImportDescriptor->OriginalFirstThunk);
			Func = ( IMAGE_THUNK_DATA* ) ( ( PUCHAR ) MappedAdr + ImportDescriptor->FirstThunk );
		}
		else
		{
			Thunk = ( IMAGE_THUNK_DATA* ) Mp_RvaToPointer( Image, ImportDescriptor->FirstThunk);
			Func = ( IMAGE_THUNK_DATA* ) ( ( PUCHAR ) MappedAdr + ImportDescriptor->FirstThunk );
		}

		for ( ; Thunk->u1.AddressOfData; Thunk++, Func++ )
		{
			assert( !( Thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64 ) );

			FARPROC FunctionAddress = NULL;
			IMAGE_IMPORT_BY_NAME* ImageImportByName = ( IMAGE_IMPORT_BY_NAME* )
				Mp_RvaToPointer( Image, *( DWORD* ) Thunk );
			PCHAR ImportName = ( PCHAR ) ImageImportByName->Name;
			ULONGLONG* Target = &Func->u1.Function;

			uint32_t ImportNameOffset = DataContainer.size();

			if ( !strcmpi( ImportName, "AddVectoredExceptionHandler" ) )
				printf( "\n[+] WARNING: Vectored Exception Handling IS NOT SUPPORTED!\n\n" );

			do
				DataContainer.push_back( *ImportName );
			while ( *ImportName++ );

			uint32_t OffsetOffset = DataContainer.size();
			DataContainer.resize( DataContainer.size() + 8 );
			*( uint64_t* ) ( &DataContainer[ OffsetOffset ] ) = ( uint64_t ) Target;

			std::vector<BYTE> ImportFixer =
			{ 
				0x48, 0x89, 0xF1,                          // mov    rcx,rsi
				0x49, 0x8D, 0x97, 0xBB, 0xAA, 0x00, 0x00,  // lea    rdx,[r9+0xaabb]
				0x41, 0xFF, 0xD4,                          // call   r12
				0x49, 0x8B, 0x9F, 0xBB, 0xAA, 0x00, 0x00,  // mov    rbx,QWORD PTR [r9+0xaabb]
				0x48, 0x89, 0x03                           // mov    QWORD PTR [rbx],rax
			};

			*( uint32_t* ) ( &ImportFixer[ 6 ] ) = ImportNameOffset;
			*( uint32_t* ) ( &ImportFixer[ 16 ] ) = OffsetOffset;

			Mp_PushBytes( Out, ImportFixer );

		}
		ImportDescriptor++;
	}

	Mp_PushBytes( Out, { 0x48, 0x83, 0xC4, 0x38 } ); // add rsp, 0x38
	uint32_t JmpSize = Out.size();
	Mp_PushBytes( Out, { 0xE9, 0x00, 0x00, 0x00, 0x00 } ); // jmp 0xAABBCCDD
	*( uint32_t* ) ( &Out[ 7 ] ) = Out.size() - 0xB;
	Mp_PushBytes( Out, DataContainer );
	*( int32_t* ) ( &Out[ JmpSize + 1 ] ) = DataContainer.size();
	return Out;
}

static void Mp_RelocateImage( BYTE* Image, BYTE* Target )
{
	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Image;
	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );
	PIMAGE_SECTION_HEADER SectionHeader = ( PIMAGE_SECTION_HEADER )
		( ( ( ULONG_PTR ) &FileHeader->OptionalHeader ) + FileHeader->FileHeader.SizeOfOptionalHeader );

	// Copy sections
	memcpy( Target, Image, 0x1000 ); // Pe Header

	for ( int i = 0; i < FileHeader->FileHeader.NumberOfSections; i++ )
	{
		char * Name = ( char* ) SectionHeader[ i ].Name;
		uint64_t RawData = SectionHeader[ i ].PointerToRawData;
		uint64_t VirtualAddress = SectionHeader[ i ].VirtualAddress;
		uint64_t RawSize = SectionHeader[ i ].SizeOfRawData;
		uint64_t VirtSize = SectionHeader[ i ].Misc.VirtualSize;
		ZeroMemory( Target + VirtualAddress, VirtSize );
		memcpy( Target + VirtualAddress, Image + RawData, RawSize );

		if ( !strcmpi( Name, ".pdata" ) )
			printf( "\n[+] WARNING: Structured Exception Handling IS NOT SUPPORTED!\n\n" );
		if ( !strcmpi( Name, ".tls" ) )
			printf( "\n[+] WARNING: Thread-local Storage IS NOT SUPPORTED!\n\n" );
	}

	// Reloc sections
	if ( FileHeader->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
		 FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress != 0 )
	{

		PIMAGE_BASE_RELOCATION Reloc = ( PIMAGE_BASE_RELOCATION ) ( Target + FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );
		DWORD RelocSize = FileHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;
		uint64_t Delta = (uint64_t)Target - FileHeader->OptionalHeader.ImageBase;
		int c = 0;
		while ( c < RelocSize )
		{
			size_t p = sizeof( IMAGE_BASE_RELOCATION );
			LPWORD Chains = ( LPWORD ) ( ( PUCHAR ) Reloc + p );
			while ( p < Reloc->SizeOfBlock )
			{
				uint64_t Base = ( uint64_t ) ( Target + Reloc->VirtualAddress );
				switch ( *Chains >> 12 )
				{
					case IMAGE_REL_BASED_HIGHLOW:
						*( uint32_t* ) ( Base + ( *Chains & 0xFFF ) ) += ( uint32_t ) Delta;
						break;
	 				case IMAGE_REL_BASED_DIR64:
						*( uint64_t* ) ( Base + ( *Chains & 0xFFF ) ) += Delta;
						break;
				}
				Chains++;
				p += sizeof( WORD );
			}
			c += Reloc->SizeOfBlock;
			Reloc = ( PIMAGE_BASE_RELOCATION ) ( ( PBYTE ) Reloc + Reloc->SizeOfBlock );
		}
	}

}

static TlsLockedHookController* Mp_MapDllAndCreateHookEntry( const std::string& Path, PVOID ValCheck, PVOID HookOut, bool LoadLib, const std::function<PVOID( SIZE_T )>& MemoryAllocator )
{
	auto File = Mp_ReadFile( Path );

	assert( File.size() );

	PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) File.data();

	assert( DosHeader->e_magic == IMAGE_DOS_SIGNATURE );

	PIMAGE_NT_HEADERS FileHeader = ( PIMAGE_NT_HEADERS ) ( ( uint64_t ) DosHeader + DosHeader->e_lfanew );

	assert( FileHeader->Signature == IMAGE_NT_SIGNATURE );

	PIMAGE_OPTIONAL_HEADER OptionalHeader = &FileHeader->OptionalHeader;

	assert( OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC );
	assert( FileHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 );

	std::vector<BYTE> Prologue =
	{ 
		0x00, 0x00, // data
		0xF0, 0xFE, 0x05, 0xF8, 0xFF, 0xFF, 0xFF,                     // lock inc byte ptr [rip-n]
		                                                              // wait_lock:
		0x80, 0x3D, 0xF0, 0xFF, 0xFF, 0xFF, 0x00,                     // cmp byte ptr [rip-m], 0x0
		0xF3, 0x90,                                                   // pause
		0x74, 0xF5,                                                   // je wait_lock

		0x48, 0xB8, 0xAA, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00,   // mov rax, 0xAABBCCDDEEAA
		                                                              // data_sync_lock:
		0x0F, 0x0D, 0x08,                                             // prefetchw [rax]
		0x81, 0x38, 0xDD, 0xCC, 0xBB, 0xAA,                           // cmp dword ptr[rax], 0xAABBCCDD
		0xF3, 0x90,                                                   // pause
		0x75, 0xF3,                                                   // jne data_sync_lock

		0xF0, 0xFE, 0x0D, 0xCF, 0xFF, 0xFF, 0xFF,                     // lock dec byte ptr [rip-n]
		0x75, 0x41,                                                   // jnz continue_exec                         
		0x53,                                                         // push stuff
		0x51, 
		0x52, 
		0x56, 
		0x57, 
		0x55, 
		0x41, 0x50, 
		0x41, 0x51, 
		0x41, 0x52, 
		0x41, 0x53, 
		0x41, 0x54, 
		0x41, 0x55, 
		0x41, 0x56, 
		0x41, 0x57, 
		0x9C, 
		0x48, 0x89, 0xE5,                                             // mov rbp, rsp
		0x48, 0x83, 0xEC, 0x20,                                       // sub rsp, 0x20
		0x48, 0x83, 0xE4, 0xF0,                                       // and rsp, 0xFFFFFFFFFFFFFFF0
		0xE8, 0x26, 0x00, 0x00, 0x00,                                 // call stub
		0x48, 0x89, 0xEC,                                             // mov rsp, rbp
		0x9D,                                                         // pop stuff
		0x41, 0x5F, 
		0x41, 0x5E,
		0x41, 0x5D, 
		0x41, 0x5C, 
		0x41, 0x5B, 
		0x41, 0x5A, 
		0x41, 0x59, 
		0x41, 0x58, 
		0x5D, 
		0x5F, 
		0x5E, 
		0x5A, 
		0x59, 
		0x5B, 
		0x48, 0xB8, 0xAA, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00,  // mov rax, 0xAABBCCDDEEFFAA
		0xFF, 0xE0                                                   // jmp rax
		                                                             // stub:
	};

	*( PVOID* ) &Prologue[ 0x77 ] = HookOut;
	*( PVOID* ) &Prologue[ 0x16 ] = ValCheck;
	*( DWORD* ) &Prologue[ 0x23 ] = *( DWORD* ) ValCheck;

	std::vector<BYTE> JmpEntryPont =
	{ 
		0x48, 0xB8, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0x00, 0x00,   // mov rax, 0xAABBCCDD
		0x48, 0x89, 0xC1,                                             // mov rcx, rax
		0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                     // mov rdx, 1
		0x4D, 0x31, 0xC0,                                             // xor r8, r8
		0x48, 0x05, 0xCD, 0xBB, 0xAA, 0x00,                           // add rax, 0xAABBCD
		0xFF, 0xE0                                                    // jmp rax
	};

	printf( "[+] Creating import shellcode...\n" );
	uint32_t ShellSize = Mp_CreateImportShell( File.data(), nullptr, LoadLib ).size() + JmpEntryPont.size() + Prologue.size();

	BYTE* Memory = ( BYTE* ) MemoryAllocator( OptionalHeader->SizeOfImage + ShellSize + 0xFFF );

	uint64_t ImageMemory = ( ( uint64_t ) Memory + ShellSize + 0xFFF )&( ~0xFFF );

	*( uint64_t* ) ( &JmpEntryPont[ 0x02 ] ) = ImageMemory;
	*( uint32_t* ) ( &JmpEntryPont[ 0x19 ] ) = FileHeader->OptionalHeader.AddressOfEntryPoint;

	auto Shell = Mp_CreateImportShell( File.data(), PVOID( ImageMemory ), LoadLib );
	Mp_PushBytes( Shell, JmpEntryPont );
	Mp_PushBytes( Prologue, Shell );
	Shell = Prologue;

	printf( "[+] Relocating image...\n" );
	Mp_RelocateImage( File.data(), PBYTE( ImageMemory ) );
	memcpy( Memory, Shell.data(), Shell.size() );

	printf( "[+] Image mapping done!\n" );
	return ( TlsLockedHookController * ) Memory;
}
