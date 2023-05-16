#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

typedef ULONG_PTR QWORD;

#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege
 (
  ULONG    Privilege,
  BOOLEAN  Enable,
  BOOLEAN  CurrentThread,
  PBOOLEAN Enabled
 );

QWORD ntoskrnl_exe_base;
QWORD ntoskrnl_exe_size;


BOOL initialize_main(void);
QWORD GetKernelExport(PCSTR name);

QWORD MmCopyMemoryAddress;
void mm_copy_memory(QWORD buffer, QWORD address, QWORD length, ULONG memory_type, QWORD *res);

namespace km
{
	static BOOL  read(QWORD address, PVOID buffer, QWORD length);
	static DWORD read_i32(QWORD addr);
	static QWORD read_i64(QWORD addr);
}

namespace pm
{
	static BOOL  read(QWORD address, PVOID buffer, QWORD length);
	static BOOL  read(QWORD address, PVOID buffer, QWORD length, QWORD *res);
	static QWORD read_i64(QWORD addr);
	static QWORD translate(QWORD dir, QWORD va);
}

typedef void* vm_handle;
enum class VM_MODULE_TYPE {
	Full = 1,
	CodeSectionsOnly = 2,
	Raw = 3 // used for dump to file
};

typedef void *vm_handle;
namespace vm
{
	vm_handle get_process_by_name(PCSTR process_name);
	BOOL      running(vm_handle process);
	BOOL      read(vm_handle process, QWORD address, PVOID buffer, QWORD length);

	inline BYTE read_i8(vm_handle process, QWORD address)
	{
		BYTE result = 0;
		if (!read(process, address, &result, sizeof(result)))
		{
			return 0;
		}
		return result;
	}

	inline WORD read_i16(vm_handle process, QWORD address)
	{
		WORD result = 0;
		if (!read(process, address, &result, sizeof(result)))
		{
			return 0;
		}
		return result;
	}

	inline DWORD read_i32(vm_handle process, QWORD address)
	{
		DWORD result = 0;
		if (!read(process, address, &result, sizeof(result)))
		{
			return 0;
		}
		return result;
	}

	inline QWORD read_i64(vm_handle process, QWORD address)
	{
		QWORD result = 0;
		if (!read(process, address, &result, sizeof(result)))
		{
			return 0;
		}
		return result;
	}

	inline float read_float(vm_handle process, QWORD address)
	{
		float result = 0;
		if (!read(process, address, &result, sizeof(result)))
		{
			return 0;
		}
		return result;
	}

	inline QWORD get_relative_address(vm_handle process, QWORD instruction, DWORD offset, DWORD instruction_size)
	{
		INT32 rip_address = read_i32(process, instruction + offset);
		return (QWORD)(instruction + instruction_size + rip_address);
	}

	QWORD     get_peb(vm_handle process);
	QWORD     get_wow64_process(vm_handle process);
	QWORD     get_module(vm_handle process, PCSTR dll_name);
	QWORD     get_module_export(vm_handle process, QWORD base, PCSTR export_name);
	PVOID     dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type);
	void      free_module(PVOID dumped_module);
	QWORD     scan_pattern(PVOID dumped_module, PCSTR pattern, PCSTR mask, QWORD length);
}

QWORD PsInitialSystemProcess;
DWORD PsGetProcessId;
DWORD PsGetProcessExitProcessCalled;
DWORD PsGetProcessImageFileName;
DWORD PsGetProcessPeb;
DWORD PsGetProcessWow64Process ;

int main(void)
{
	if (!initialize_main())
	{
		printf("[-] run as admin\n");
		return getchar();
	}

	printf("[+] program is running\n");

	MmCopyMemoryAddress = GetKernelExport("MmCopyMemory");
	if (MmCopyMemoryAddress == 0)
	{
		return 0;
	}

	PsInitialSystemProcess = GetKernelExport("PsInitialSystemProcess");
	if (PsInitialSystemProcess == 0)
	{
		return 0;
	}

	PsGetProcessId = km::read_i32(GetKernelExport("PsGetProcessId") + 3);
	if (PsGetProcessId == 0)
	{
		return 0;
	}

	PsGetProcessExitProcessCalled = km::read_i32(GetKernelExport("PsGetProcessExitProcessCalled") + 2);
	if (PsGetProcessExitProcessCalled == 0)
	{
		return 0;
	}

	PsGetProcessImageFileName = km::read_i32(GetKernelExport("PsGetProcessImageFileName") + 3);
	if (PsGetProcessImageFileName == 0)
	{
		return 0;
	}

	PsGetProcessPeb = km::read_i32(GetKernelExport("PsGetProcessPeb") + 3);
	if (PsGetProcessPeb == 0)
	{
		return 0;
	}

	PsGetProcessWow64Process = km::read_i32(GetKernelExport("PsGetProcessWow64Process") + 3);
	if (PsGetProcessWow64Process == 0)
	{
		return 0;
	}

	//
	// demo
	//
	vm_handle process = vm::get_process_by_name("csgo.exe");
	if (process == 0)
	{
		return 0;
	}

	QWORD client_dll = vm::get_module(process, "client.dll");
	if (client_dll == 0)
	{
		return 0;
	}

	printf("[+] client.dll: 0x%llx\n", client_dll);

	QWORD create_interface = vm::get_module_export(process, client_dll, "CreateInterface");
	if (create_interface == 0)
	{
		return 0;
	}

	printf("[+] client.dll->CreateInterface: 0x%llx\n", create_interface);

	PVOID client_dump = vm::dump_module(process, client_dll , VM_MODULE_TYPE::CodeSectionsOnly);
	if (client_dump == 0)
	{
		return 0;
	}


	QWORD GetLocalTeam = vm::scan_pattern(client_dump, "\xE8\x00\x00\x00\x00\x85\xC0\x74\x11\x5F", "x????xxxxx", 10);

	vm::free_module(client_dump);

	if (GetLocalTeam == 0)
	{
		return 0;
	}

	GetLocalTeam = (DWORD)vm::get_relative_address(process, GetLocalTeam, 1, 5);

	printf("[+] client.dll->GetLocalTeam: 0x%llx\n", GetLocalTeam);

	// 
	// QWORD cr3=0;
	// mm_copy_memory((QWORD)&cr3, 0x10A0, 8, 0x1, 0);
	// printf("cr3: %llx\n", cr3);
	// printf("MmCopyMemoryAddress physical: %llx\n", pm::translate(cr3, MmCopyMemoryAddress));
	//

	return 0;
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
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
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

BOOL initialize_main(void)
{
	BOOLEAN privs=1;
	if (RtlAdjustPrivilege(22, 1, 0, &privs) != 0l)
	{
		return 0;
	}

	ULONG driver_length=0;
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, 0, 0, &driver_length);

	if (driver_length == 0)
	{
		return 0;
	}

	PRTL_PROCESS_MODULES ModuleInfo= (PRTL_PROCESS_MODULES)HeapAlloc(GetProcessHeap(), 0, driver_length);
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, driver_length, 0);

	if (status != 0) {
		HeapFree(GetProcessHeap(), 0, ModuleInfo);
		return 0;
	}

	ULONG_PTR kernel_base=(ULONG_PTR)ModuleInfo->Modules[0].ImageBase;
	ULONG_PTR kernel_size=(ULONG_PTR)ModuleInfo->Modules[0].ImageSize;

	ntoskrnl_exe_base = kernel_base;
	ntoskrnl_exe_size = kernel_size;

	HeapFree(GetProcessHeap(), 0, ModuleInfo);

	return 1;
}

QWORD GetKernelExport(PCSTR name)
{
	HMODULE ntos = LoadLibraryA("ntoskrnl.exe");

	if (ntos == 0)
	{
		return 0;
	}

	QWORD export_address = (QWORD)GetProcAddress(ntos, name);
	if (export_address == 0)
	{
		goto cleanup;
	}

	export_address = export_address - (QWORD)ntos;
	export_address = export_address + ntoskrnl_exe_base;

cleanup:
	FreeLibrary(ntos);


	return export_address;
}

extern "C" NTSTATUS NTAPI
NtQuerySystemEnvironmentValueEx(
    __in PUNICODE_STRING VariableName,
    __in LPGUID VendorGuid,
    __out_bcount_opt(*ValueLength) PVOID Value,
    __inout PULONG ValueLength,
    __out_opt PULONG Attributes
    );

NTSTATUS call_payload(QWORD target, PVOID parameters)
{
	QWORD peb;

	peb = __readgsqword(0x60);
	peb = *(QWORD*)(peb + 0x18);
	peb = *(QWORD*)(peb + 0x20);

	*(QWORD*)(peb + 0x18) = target;
	*(QWORD*)(peb + 0x10) = (QWORD)parameters;

	ULONG ids=0,count=0;


	UNICODE_STRING string;
	RtlInitUnicodeString(&string, L"SecureBoot");

	unsigned char ret = 0;
	ULONG ret_len = 1;
	ULONG attributes = 0;

	GUID gEfiGlobalVariableGuid         = { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }};
	NTSTATUS status = NtQuerySystemEnvironmentValueEx(&string,
						&gEfiGlobalVariableGuid,
						&ret,
						&ret_len,
						&attributes);

	*(QWORD*)(peb + 0x18) = 0;
	*(QWORD*)(peb + 0x10) = 0;

	return status;
}

void mm_copy_memory(QWORD buffer, QWORD address, QWORD length, ULONG memory_type, QWORD *res)
{
	#pragma pack(push,1)
	typedef struct {
		QWORD rcx;
		QWORD rdx;
		QWORD r8;
		QWORD r9;
		QWORD rsp_20;
	} PAYLOAD ;
	#pragma pack(pop)

	PAYLOAD parameters;
	parameters.rcx = (QWORD)buffer;
	parameters.rdx = address;
	parameters.r8  = length;
	parameters.r9 = memory_type;

	char rsp[120];
	memset(rsp, 0, 120);

	QWORD reserved=0;
	*(QWORD*)&rsp[0] = (QWORD)&reserved;
	parameters.rsp_20 = (QWORD)rsp;

	call_payload( MmCopyMemoryAddress, &parameters );

	if (res)
	{
		*res = *(QWORD*)&rsp[0];
	}
}

static BOOL km::read(QWORD address, PVOID buffer, QWORD length)
{
	QWORD res = 0;
	mm_copy_memory( (QWORD)buffer, address, length, 0x2, &res);

	if (res == length)
	{
		return 1;
	}

	return 0;
}

static DWORD km::read_i32(QWORD addr)
{
	DWORD buffer=0;
	QWORD res = 0;
	mm_copy_memory((QWORD)&buffer, addr, sizeof(buffer), 0x2, &res);

	if (res == sizeof(buffer))
	{
		return buffer;
	}

	return 0;
}

static QWORD km::read_i64(QWORD addr)
{
	QWORD buffer=0;
	QWORD res = 0;
	mm_copy_memory((QWORD)&buffer, addr, sizeof(buffer), 0x2, &res);

	if (res == sizeof(buffer))
	{
		return buffer;
	}

	return 0;
}

static BOOL pm::read(QWORD address, PVOID buffer, QWORD length)
{
	QWORD res = 0;
	mm_copy_memory( (QWORD)buffer, address, length, 0x1, &res);

	if (res == length)
	{
		return 1;
	}

	return 0;
}

static BOOL pm::read(QWORD address, PVOID buffer, QWORD length, QWORD *res)
{
	mm_copy_memory( (QWORD)buffer, address, length, 0x1, res);

	if (*res == length)
	{
		return 1;
	}

	return 0;
}

static QWORD pm::read_i64(QWORD addr)
{
	QWORD buffer=0;
	QWORD res = 0;
	mm_copy_memory((QWORD)&buffer, addr, sizeof(buffer), 0x1, &res);

	if (res == sizeof(buffer))
	{
		return buffer;
	}

	return 0;
}

static QWORD pm::translate(QWORD dir, QWORD va)
{
	__int64 v2; // rax
	__int64 v3; // rax
	__int64 v5; // rax
	__int64 v6; // rax

	v2 = pm::read_i64(8 * ((va >> 39) & 0x1FF) + dir);
	if ( !v2 )
		return 0i64;

	if ( (v2 & 1) == 0 )
		return 0i64;

	v3 = pm::read_i64((v2 & 0xFFFFFFFFF000i64) + 8 * ((va >> 30) & 0x1FF));
	if ( !v3 || (v3 & 1) == 0 )
		return 0i64;

	if ( (v3 & 0x80u) != 0i64 )
		return (va & 0x3FFFFFFF) + (v3 & 0xFFFFFFFFF000i64);

	v5 = pm::read_i64((v3 & 0xFFFFFFFFF000i64) + 8 * ((va >> 21) & 0x1FF));
	if ( !v5 || (v5 & 1) == 0 )
		return 0i64;

	if ( (v5 & 0x80u) != 0i64 )
		return (va & 0x1FFFFF) + (v5 & 0xFFFFFFFFF000i64);

	v6 = pm::read_i64((v5 & 0xFFFFFFFFF000i64) + 8 * ((va >> 12) & 0x1FF));
	if ( v6 && (v6 & 1) != 0 )
		return (va & 0xFFF) + (v6 & 0xFFFFFFFFF000i64);

	return 0i64;
}

vm_handle vm::get_process_by_name(PCSTR process_name)
{
	QWORD process;
	QWORD entry;

	DWORD gActiveProcessLink = PsGetProcessId + 8;
	process = km::read_i64(PsInitialSystemProcess);

	DWORD offset_exit = PsGetProcessExitProcessCalled;
	DWORD offset_name = PsGetProcessImageFileName;

	entry = process;
	do {
		char name[15]{};
		DWORD eax = km::read_i32(entry + offset_exit);
		if (eax == 0)
			goto E0;

		eax = eax >> 2;
		eax = eax & 1;
		if (eax)
		{
			goto E0;
		}

		if (!km::read(entry + offset_name, name, sizeof(name)))
		{
			goto E0;
		}

		if (!_strcmpi(name, process_name))
		{
			return (vm_handle)entry;
		}
	E0:
		entry = km::read_i64(entry + gActiveProcessLink) - gActiveProcessLink;
	} while (entry != process);

	return 0;
}

BOOL vm::running(vm_handle process)
{
	if (process == 0)
	{
		return 0;
	}

	DWORD offset_exit = PsGetProcessExitProcessCalled;

	DWORD eax = km::read_i32((QWORD)process + offset_exit);
	if (eax == 0)
		return 0;

	eax = eax >> 2;
	eax = eax & 1;

	return eax == 0;
}

BOOL vm::read(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	if (process == 0)
	{
		return 0;
	}

	QWORD cr3 = km::read_i64((QWORD)process + 0x28);
	if (cr3 == 0)
	{
		return 0;
	}

	QWORD total_size = length;
	QWORD offset = 0;
	QWORD bytes_read=0;
	QWORD physical_address;
	QWORD current_size;

	while (total_size)
	{
		physical_address = pm::translate(cr3, address + offset);
		if (!physical_address)
		{
			if (total_size >= 0x1000)
			{
				bytes_read = 0x1000;
			}
			else
			{
				bytes_read = total_size;
			}
			goto E0;
		}

		current_size = min(0x1000 - (physical_address & 0xFFF), total_size);
		if (!pm::read(physical_address, (PVOID)((QWORD)buffer + offset), current_size, &bytes_read))
		{
			break;
		}
	E0:
		total_size -= bytes_read;
		offset += bytes_read;
	}
	return 1;
}

QWORD vm::get_peb(vm_handle process)
{
	if (process == 0)
		return 0;

	return km::read_i64((QWORD)process + PsGetProcessPeb);
}

QWORD vm::get_wow64_process(vm_handle process)
{
	if (process == 0)
		return 0;

	QWORD rax = km::read_i64((QWORD)process + PsGetProcessWow64Process);

	if (rax == 0)
		return 0;
	
	return km::read_i64(rax);
}

QWORD vm::get_module(vm_handle process, PCSTR dll_name)
{
	#ifdef __linux__
	return (QWORD)0x140000000;
	#else

	QWORD peb = get_wow64_process(process);

	DWORD a0[6]{};
	QWORD a1, a2;
	unsigned short a3[120]{};

	QWORD(*read_ptr)(vm_handle process, QWORD address) = 0;
	if (peb)
	{
		*(QWORD*)&read_ptr = (QWORD)read_i32;
		a0[0] = 0x04, a0[1] = 0x0C, a0[2] = 0x14, a0[3] = 0x28, a0[4] = 0x10, a0[5] = 0x20;
	}
	else
	{
		*(QWORD*)&read_ptr = (QWORD)read_i64;
		peb = get_peb(process);
		a0[0] = 0x08, a0[1] = 0x18, a0[2] = 0x20, a0[3] = 0x50, a0[4] = 0x20, a0[5] = 0x40;
	}

	if (peb == 0)
	{
		return 0;
	}

	a1 = read_ptr(process, peb + a0[1]);
	if (a1 == 0)
	{
		return 0;
	}

	a1 = read_ptr(process, a1 + a0[2]);
	if (a1 == 0)
	{
		return 0;
	}

	a2 = read_ptr(process, a1 + a0[0]);

	while (a1 != a2) {
		QWORD a4 = read_ptr(process, a1 + a0[3]);
		if (a4 != 0)
		{
			read(process, a4, a3, sizeof(a3));
			if (dll_name == 0)
				return read_ptr(process, a1 + a0[4]);

			char final_name[120]{};
			for (int i = 0; i < 120; i++) {
				final_name[i] = (char)a3[i];
				if (a3[i] == 0)
					break;
			}

			if (_strcmpi((PCSTR)final_name, dll_name) == 0)
			{
				return read_ptr(process, a1 + a0[4]);
			}
		}
		a1 = read_ptr(process, a1);
		if (a1 == 0)
			break;
	}
	return 0;
	#endif
}

QWORD vm::get_module_export(vm_handle process, QWORD base, PCSTR export_name)
{
	QWORD a0;
	DWORD a1[4]{};
	char a2[260]{};

	a0 = base + read_i16(process, base + 0x3C);
	if (a0 == base)
	{
		return 0;
	}

	WORD  machine = read_i16(process, a0 + 0x4);
	DWORD wow64_offset = machine == 0x8664 ? 0x88 : 0x78;

	a0 = base + (QWORD)read_i32(process, a0 + wow64_offset);
	if (a0 == base)
	{
		return 0;
	}

	int name_length = (int)strlen(export_name);
	if (name_length > 259)
		name_length = 259;

	read(process, a0 + 0x18, &a1, sizeof(a1));
	while (a1[0]--)
	{
		a0 = (QWORD)read_i32(process, base + a1[2] + ((QWORD)a1[0] * 4));
		if (a0)
		{
			read(process, base + a0, &a2, name_length);
			a2[name_length] = 0;

			if (!_strcmpi(a2, export_name))
			{
				DWORD tmp = read_i16(process, base + a1[3] + ((QWORD)a1[0] * 2)) * 4;
				DWORD tmp2 = read_i32(process, base + a1[1] + tmp);
				return (base + tmp2);
			}
		}
	}
	return 0;
}

PVOID vm::dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type)
{
	QWORD nt_header;
	DWORD image_size;
	BYTE* ret;

	if (base == 0)
	{
		return 0;
	}

	nt_header = (QWORD)read_i32(process, base + 0x03C) + base;
	if (nt_header == base)
	{
		return 0;
	}

	image_size = read_i32(process, nt_header + 0x050);
	if (image_size == 0)
	{
		return 0;
	}

	ret = (BYTE*)malloc((QWORD)image_size + 16);
	if (ret == 0)
		return 0;

	*(QWORD*)(ret + 0) = base;
	*(QWORD*)(ret + 8) = image_size;
	ret += 16;

	DWORD headers_size = read_i32(process, nt_header + 0x54);
	read(process, base, ret, headers_size);

	WORD machine = read_i16(process, nt_header + 0x4);
	QWORD section_header = machine == 0x8664 ?
		nt_header + 0x0108 :
		nt_header + 0x00F8;


	for (WORD i = 0; i < read_i16(process, nt_header + 0x06); i++) {
		QWORD section = section_header + ((QWORD)i * 40);
		if (module_type == VM_MODULE_TYPE::CodeSectionsOnly)
		{
			DWORD section_characteristics = read_i32(process, section + 0x24);
			if (!(section_characteristics & 0x00000020))
				continue;
		}

		QWORD target_address = (QWORD)ret + (QWORD)read_i32(process, section + ((module_type == VM_MODULE_TYPE::Raw) ? 0x14 : 0x0C));
		QWORD virtual_address = base + (QWORD)read_i32(process, section + 0x0C);
		DWORD virtual_size = read_i32(process, section + 0x08);
		read(process, virtual_address, (PVOID)target_address, virtual_size);
	}

	return (PVOID)ret;
}

void vm::free_module(PVOID dumped_module)
{
	if (dumped_module)
	{
		QWORD a0 = (QWORD)dumped_module;
		a0 -= 16;
		free((void*)a0);
	}
}

static BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{

	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

static QWORD FindPatternEx(QWORD dwAddress, QWORD dwLen, BYTE* bMask, char* szMask)
{

	if (dwLen <= 0)
		return 0;
	for (QWORD i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (QWORD)(dwAddress + i);

	return 0;
}

QWORD vm::scan_pattern(PVOID dumped_module, PCSTR pattern, PCSTR mask, QWORD length)
{
	QWORD ret = 0;

	if (dumped_module == 0)
		return 0;

	QWORD dos_header = (QWORD)dumped_module;
	QWORD nt_header = (QWORD) * (DWORD*)(dos_header + 0x03C) + dos_header;
	WORD  machine = *(WORD*)(nt_header + 0x4);

	QWORD section_header = machine == 0x8664 ?
		nt_header + 0x0108 :
		nt_header + 0x00F8;

	for (WORD i = 0; i < *(WORD*)(nt_header + 0x06); i++) {

		QWORD section = section_header + ((QWORD)i * 40);
		DWORD section_characteristics = *(DWORD*)(section + 0x24);

		if (section_characteristics & 0x00000020)
		{
			QWORD section_address = dos_header + (QWORD) * (DWORD*)(section + 0x0C);
			DWORD section_size = *(DWORD*)(section + 0x08);
			QWORD address = FindPatternEx(section_address, section_size - length, (BYTE*)pattern, (char*)mask);
			if (address)
			{
				ret = (address - (QWORD)dumped_module) +
					*(QWORD*)((QWORD)dumped_module - 16);
				break;
			}
		}

	}
	return ret;
}

