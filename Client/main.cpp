#include "km.h"

//
// hello world
//

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

