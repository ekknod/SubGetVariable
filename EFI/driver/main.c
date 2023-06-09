#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/Cpu.h>
#include <IndustryStandard/PeImage.h>
#include <Guid/GlobalVariable.h>

#define CONTAINING_RECORD(address, type, field) ((type *)((UINT8 *)(address) - (UINTN)(&((type *)0)->field)))
#define RELATIVE_ADDR(addr, size) ((VOID *)((UINT8 *)(addr) + *(INT32 *)((UINT8 *)(addr) + ((size) - (INT32)sizeof(INT32))) + (size)))
#define Print(Text) gST->ConOut->OutputString(gST->ConOut, Text)

typedef UINTN QWORD;
typedef UINT32 DWORD;
typedef long NTSTATUS;

typedef struct _EFI_RUNTIME_ARCH_PROTOCOL EFI_RUNTIME_ARCH_PROTOCOL;

EFI_SYSTEM_TABLE *gST;
EFI_RUNTIME_SERVICES *gRT;
EFI_BOOT_SERVICES *gBS;
EFI_RUNTIME_ARCH_PROTOCOL *gRuntime;

typedef LIST_ENTRY EFI_LIST_ENTRY;

struct _EFI_RUNTIME_ARCH_PROTOCOL
{
	EFI_LIST_ENTRY ImageHead;		  ///< A list of type EFI_RUNTIME_IMAGE_ENTRY.
	EFI_LIST_ENTRY EventHead;		  ///< A list of type EFI_RUNTIME_EVENT_ENTRY.
	UINTN MemoryDescriptorSize;		  ///< Size of a memory descriptor that is returned by GetMemoryMap().
	UINT32 MemoryDesciptorVersion;		  ///< Version of a memory descriptor that is returned by GetMemoryMap().
	UINTN MemoryMapSize;			  ///< Size of the memory map in bytes contained in MemoryMapPhysical and MemoryMapVirtual.
	EFI_MEMORY_DESCRIPTOR *MemoryMapPhysical; ///< Pointer to a runtime buffer that contains a copy of
						  ///< the memory map returned via GetMemoryMap().
	EFI_MEMORY_DESCRIPTOR *MemoryMapVirtual;  ///< Pointer to MemoryMapPhysical that is updated to virtual mode after SetVirtualAddressMap().
	BOOLEAN VirtualMode;			  ///< Boolean that is TRUE if SetVirtualAddressMap() has been called.
	BOOLEAN AtRuntime;			  ///< Boolean that is TRUE if ExitBootServices () has been called.
};


struct _EFI_RUNTIME_IMAGE_ENTRY
{
	///
	/// Start of image that has been loaded in memory. It is a pointer
	/// to either the DOS header or PE header of the image.
	///
	VOID *ImageBase;
	///
	/// Size in bytes of the image represented by ImageBase.
	///
	UINT64 ImageSize;
	///
	/// Information about the fix-ups that were performed on ImageBase when it was
	/// loaded into memory.
	///
	VOID *RelocationData;
	///
	/// The ImageHandle passed into ImageBase when it was loaded.
	///
	EFI_HANDLE Handle;
	///
	/// Entry for this node in the EFI_RUNTIME_ARCHITECTURE_PROTOCOL.ImageHead list.
	///
	EFI_LIST_ENTRY Link;
};

typedef struct _EFI_RUNTIME_IMAGE_ENTRY EFI_RUNTIME_IMAGE_ENTRY;

EFI_RUNTIME_IMAGE_ENTRY *GetImageEntry(QWORD address)
{
	EFI_LIST_ENTRY *entry = &gRuntime->ImageHead;
	while ((entry = entry->ForwardLink) != &gRuntime->ImageHead) {

		EFI_RUNTIME_IMAGE_ENTRY *image = CONTAINING_RECORD( entry, EFI_RUNTIME_IMAGE_ENTRY, Link);
		if ( (QWORD)address > (QWORD)image->ImageBase && (QWORD)address < ((QWORD)image->ImageBase + image->ImageSize) ) {
			return image;
		}
	}
	return 0;
}

VOID *ResolveRelativeAddress(VOID * Instruction, DWORD OffsetOffset, DWORD InstructionSize)
{
	QWORD Instr = (QWORD)Instruction;
 
	DWORD RipOffset = *(DWORD*)(Instr + OffsetOffset);
	VOID * ResolvedAddr = (VOID *)(Instr + InstructionSize + RipOffset);
 
	return ResolvedAddr;
}

VOID MemCopy(VOID* dest, VOID* src, UINTN size)
{
	for (UINT8* d = dest, *s = src; size--; *d++ = *s++)
		;
}

BOOLEAN CheckMask(unsigned char* base, unsigned char* pattern, unsigned char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return FALSE;
	return TRUE;
}

QWORD strleni(const char *s)
{
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

VOID *FindPattern(unsigned char* base, UINTN size, unsigned char* pattern, unsigned char* mask)
{
	size -= strleni(mask);
	for (UINTN i = 0; i <= size; ++i) {
		VOID* addr = &base[i];
		if (CheckMask(addr, pattern, mask))
			return addr;
	}
	return NULL;
}

inline void PressAnyKey()
{
	EFI_STATUS         Status;
	EFI_EVENT          WaitList;
	EFI_INPUT_KEY      Key;
	UINTN              Index;
	Print(L"Press F11 key to continue . . .");
	do {
		WaitList = gST->ConIn->WaitForKey;
		Status = gBS->WaitForEvent(1, &WaitList, &Index);
		gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
		if (Key.ScanCode == SCAN_F11)
			break;
	} while ( 1 );
	gST->ConOut->ClearScreen(gST->ConOut);
	gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
}


EFI_STATUS EFIAPI EfiMain(IN EFI_LOADED_IMAGE *LoadedImage, IN EFI_SYSTEM_TABLE *SystemTable)
{
	gRT = SystemTable->RuntimeServices;
	gBS = SystemTable->BootServices;
	gST = SystemTable;


	EFI_GUID gEfiRuntimeArchProtocolGuid = {0xb7dfb4e1, 0x052f, 0x449f, {0x87, 0xbe, 0x98, 0x18, 0xfc, 0x91, 0xb7, 0x33}};
	if (EFI_ERROR(gBS->LocateProtocol(&gEfiRuntimeArchProtocolGuid, 0, &gRuntime))) {
		Print(L"Status: Motherboard is not compatible (0)\n");
		PressAnyKey();
		return 0;
	}

	unsigned char *bytes = (unsigned char *)gRT->GetVariable;

	while (1) {
		if (*bytes == 0xE8)
			break;
		bytes++;
	}

	unsigned char *SubGetVariable = RELATIVE_ADDR(bytes, 5);
	EFI_RUNTIME_IMAGE_ENTRY *runtime_driver = GetImageEntry((QWORD)SubGetVariable);

	if (runtime_driver == 0) {
		Print(L"[bootx64.efi] Motherboard is not compatible (1)\n");
		PressAnyKey();
		return 0;
	}

	char mask[] = { 'x','?','?','?','?','x','x','x','x',0 };

	QWORD address = (QWORD)FindPattern( ((unsigned char *)gBS->UnloadImage - 0x2000), 0x2000, "\xE8\x00\x00\x00\x00\x48\x8D\x77\x30", mask);

	if (address == 0) {
		Print(L"[bootx64.efi] Motherboard is not compatible (2)\n");
		PressAnyKey();
		return 0;
	}


	address = (QWORD)ResolveRelativeAddress(( void*)address, 1, 5);	

	VOID ( *SetUefiImageMemoryAttributes )(
	  IN UINT64   BaseAddress,
	  IN UINT64   Length,
	  IN UINT64   Attributes
	  );

	*(QWORD*)&SetUefiImageMemoryAttributes = address;

	SetUefiImageMemoryAttributes((QWORD)runtime_driver->ImageBase, runtime_driver->ImageSize, 0);

	unsigned char payload[] = { 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x51, 0x48,
		0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x80, 0x50, 0x05, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x3E, 0x48, 0x8B, 0x40, 0x18, 0x48,
		0x8B, 0x40, 0x20, 0x48, 0x8B, 0x48, 0x10, 0x48, 0x85, 0xC9, 0x74, 0x2D, 0x48, 0x8B, 0x51, 0x08, 0x4C, 0x8B, 0x41, 0x10, 0x4C, 0x8B, 0x49,
		0x18, 0x4C, 0x8B, 0x79, 0x20, 0x4C, 0x89, 0x7C, 0x24, 0x20, 0x48, 0x8B, 0x09, 0x48, 0x8B, 0x40, 0x18, 0xFF, 0xD0, 0x48, 0xB8, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x48, 0x31, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3 };

	/*
		0:  48 83 ec 28             sub    rsp,0x28
		4:  65 48 8b 04 25 88 01    mov    rax,QWORD PTR gs:0x188
		b:  00 00
		d:  48 85 c0                test   rax,rax
		10: 74 51                   je     0x63
		12: 48 8b 80 b8 00 00 00    mov    rax,QWORD PTR [rax+0xb8]
		19: 48 8b 80 50 05 00 00    mov    rax,QWORD PTR [rax+0x550]
		20: 48 85 c0                test   rax,rax
		23: 74 3e                   je     0x63
		25: 48 8b 40 18             mov    rax,QWORD PTR [rax+0x18]
		29: 48 8b 40 20             mov    rax,QWORD PTR [rax+0x20]
		2d: 48 8b 48 10             mov    rcx,QWORD PTR [rax+0x10]
		31: 48 85 c9                test   rcx,rcx
		34: 74 2d                   je     0x63
		36: 48 8b 51 08             mov    rdx,QWORD PTR [rcx+0x8]
		3a: 4c 8b 41 10             mov    r8,QWORD PTR [rcx+0x10]
		3e: 4c 8b 49 18             mov    r9,QWORD PTR [rcx+0x18]
		42: 4c 8b 79 20             mov    r15,QWORD PTR [rcx+0x20]
		46: 4c 89 7c 24 20          mov    QWORD PTR [rsp+0x20],r15
		4b: 48 8b 09                mov    rcx,QWORD PTR [rcx]
		4e: 48 8b 40 18             mov    rax,QWORD PTR [rax+0x18]
		52: ff d0                   call   rax
		54: 48 b8 0f 00 00 00 00    movabs rax,0x800000000000000f
		5b: 00 00 80
		5e: 48 83 c4 28             add    rsp,0x28
		62: c3                      ret
		63: 48 31 c0                xor    rax,rax
		66: 48 83 c4 28             add    rsp,0x28
		6a: c3                      ret
	*/

	MemCopy( SubGetVariable, payload, sizeof(payload) );

	Print(L"[bootx64.efi] SubGetVariable has been successfully patched\n");

	gST->ConOut->SetCursorPosition(gST->ConOut, 0, 1);

	PressAnyKey();

	return 0;
}

