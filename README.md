# SubGetVariable
Infects DXE bios image with backdoor before booting the system.  
this backdoor can execute kernel code directly from your C++ project.  

# System Requirement
**AMD** motherboard is most likely required. 

# Hello World
<pre>
#include "km.h"
std::vector<QWORD> km::global_export_list;
NTOSKRNL_EXPORT(PsGetCurrentProcess);
NTOSKRNL_EXPORT(PsGetCurrentProcessId);

int main(void)
{
	if (!km::initialize())
	{
		return 0;
	}

	LOG("current process: %llx\n", km::call(PsGetCurrentProcess));
	LOG("current process id: %lld\n", km::call(PsGetCurrentProcessId));
}
</pre>
