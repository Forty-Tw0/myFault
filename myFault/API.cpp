extern "C"{
#include "ntifs.h"
#include "Fltkernel.h"
	PVOID ADDRESSOF(UINT64 address);

	//intrinsics
	VOID _disable();
	VOID _enable();
	VOID __writecr0(UINT64 address);
	UINT64 __readcr4();
	VOID __writecr4(UINT64 val);
	UINT64 __readcr0();
	UINT64 __readcr2();
	UINT64 __readcr3();
	VOID __nop();
	VOID __invlpg(PVOID);

	//in the asm
	VOID ENDHOOK();
	VOID JUMP(UINT32 low, UINT32 high);
	UINT64 GIDT(UINT64 address);
	VOID reloadDTLB();
	VOID reloadcr3();
	UINT64 getPageAddress(UINT64 pte);
}

#define MiGetVirtualAddressMappedByPte(pte) ((PVOID)((INT64)(((INT64)(pte) - PTE_BASE) << (12L + 13)) >> 16))
#define MiGetPteAddress(va) ((PPTE)(((((UINT64)(va) & ((((ULONG_PTR)1) << 48) - 1)) >> 12) << 3) + PTE_BASE))
typedef struct _PTE {
	UINT64 Valid : 1;
	UINT64 Writable : 1;        // changed for MP version
	UINT64 Owner : 1;
	UINT64 WriteThrough : 1;
	UINT64 CacheDisable : 1;
	UINT64 Accessed : 1;
	UINT64 Dirty : 1;
	UINT64 LargePage : 1;
	UINT64 Global : 1;
	UINT64 CopyOnWrite : 1; // software field
	UINT64 Prototype : 1;   // software field
	UINT64 Write : 1;       // software field - MP change
	UINT64 PageFrameNumber : 28;
	UINT64 reserved1 : 12;
	UINT64 SoftwareWsIndex : 11;
	UINT64 NoExecute : 1;
} PTE, *PPTE; //dt _MMPTE_HARDWARE 0x0

struct _KPROCESS {
	CHAR _0x28[0x28];
	UINT64 DirectoryTableBase; //0x28
	CHAR _0x30[0x160 - 0x30];
	EX_PUSH_LOCK pushlock;
	CHAR _0x168[0x270 - 0x168];
	UINT64 SectionBaseAddress; //0x270
	CHAR _0x278[0x2d8 - 0x278];
	UCHAR imageName[16]; //0x2d8
	//Expect these EPROCESS offsets to change all the time...
	//how about some dynamic sig scanning for undocumented API like PsGetProcessSectionBaseAddress()
	//here is the sig for it: static CHAR sig[] = "\x8B\xFF\x55\x8B\xEC\x8B\x45\x08\x8B\x80";
};

PPEB getPEB(UINT64 pid){
	// Get the address of PsGetProcessPeb
	PPEB(*pPsGetProcessPeb)(PEPROCESS) = NULL;
	UNICODE_STRING usMethodName;
	RtlInitUnicodeString(&usMethodName, L"PsGetProcessPeb");
	pPsGetProcessPeb = (PPEB(*)(PEPROCESS))MmGetSystemRoutineAddress(&usMethodName);

	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)pid, &process);
	return pPsGetProcessPeb(process);
}

struct pageData{
	UINT64 cr3;
	UINT64 address;
	UINT64 readWritePFN;
	UINT64 executePFN;
	UINT64 voidCall;
};

UINT32 numPages = 1;
pageData hookedPages[1];

PVOID mapRAM(UINT64 address, SIZE_T size){
	PHYSICAL_ADDRESS addy;
	addy.QuadPart = address;
	PVOID vaddy = MmMapIoSpace(addy, size, MmCached); //This uses system API and could possibly be hooked!
	//DbgPrint("		RAM at physical address %llx mapped to virtual address %llx\n", address, vaddy);
	return vaddy;
}

VOID unmapRAM(PVOID address, SIZE_T size){
	MmUnmapIoSpace(address, size); //This uses system API and could possibly be hooked!
	//DbgPrint("		Virtual address %llx unmapped from RAM (not sure if PVOID conversion of address is right?)\n", &address);
}

PPTE getPTE(UINT64 cr3, UINT64 va){
	UINT8 HARDWARE_PTE_SIZE = 8; //bytes
	DbgPrint("	Getting PFN for cr3 = %llx and VA = %llx\n", cr3, va);

	UINT64 PML4 = (va & 0xFF8000000000) >> 39;
	UINT64 PDP = (va & 0x7FC0000000) >> 30;
	UINT64 PD = (va & 0x3FE00000) >> 21;
	UINT64 PT = (va & 0x1FF000) >> 12;
	//UINT16 offset = va & 0xFFF;

	PVOID PML4E = mapRAM(cr3 + PML4 * HARDWARE_PTE_SIZE, HARDWARE_PTE_SIZE);
	DbgPrint("		PML4E: %llx\n", cr3 + PML4 * HARDWARE_PTE_SIZE);

	PVOID PDPE = mapRAM((*(PUINT64)PML4E & 0x000FFFFFFFFFF000) + PDP * HARDWARE_PTE_SIZE, HARDWARE_PTE_SIZE);
	DbgPrint("		PDPE: %llx\n", (*(PUINT64)PML4E & 0x000FFFFFFFFFF000) + PDP * HARDWARE_PTE_SIZE);

	PVOID PDE = mapRAM((*(PUINT64)PDPE & 0x000FFFFFFFFFF000) + PD * HARDWARE_PTE_SIZE, HARDWARE_PTE_SIZE);
	DbgPrint("		PDE: %llx\n", (*(PUINT64)PDPE & 0x000FFFFFFFFFF000) + PD * HARDWARE_PTE_SIZE);

	PVOID PTE = mapRAM((*(PUINT64)PDE & 0x000FFFFFFFFFF000) + PT * HARDWARE_PTE_SIZE, HARDWARE_PTE_SIZE);
	DbgPrint("		PTE: %llx\n", (*(PUINT64)PDE & 0x000FFFFFFFFFF000) + PT * HARDWARE_PTE_SIZE);

	UINT64 PFN = ((PPTE)PTE)->PageFrameNumber;
	DbgPrint("		PFN: %llx\n", PFN);

	//cleanup
	unmapRAM(PML4E, 8);
	unmapRAM(PDPE, 8);
	unmapRAM(PDE, 8);
	//unmapRAM(PTE, 8);

	return (PPTE)PTE;
}

PCH debugInput(PCHAR prompt, int replyMaxLength){
	PCCH out = prompt;
	PCH in = NULL;
	DbgPrompt(out, in, replyMaxLength);
	return in;
}

INT64 isHooked(UINT64 cr3, UINT64 virt){
	for (INT64 page = 0; page < numPages; page++){
		if ((hookedPages[page].address <= virt) && (virt < hookedPages[page].address + PAGE_SIZE) && hookedPages[page].cr3 == cr3) return page;
	}
	return -1;
}

VOID hookers(UINT64 cr3, UINT64 address, PCHAR opcodes, SIZE_T size){
	PPTE vpte = getPTE(cr3, address);
	PVOID page = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'page');
	PVOID vpage = mapRAM(vpte->PageFrameNumber * PAGE_SIZE, PAGE_SIZE);
	memcpy(page, vpage, PAGE_SIZE);
	//size = (SIZE_T)opcodes;
	memcpy((PVOID)((UINT64)page + (address & 0xFFF)), opcodes, size);
	DbgPrint("	%llx copied to %llx with hook at offset %llx\n", vpage, page, address & 0xFFF);

	hookedPages[0].cr3 = cr3;
	hookedPages[0].address = address;
	hookedPages[0].readWritePFN = vpte->PageFrameNumber;
	hookedPages[0].executePFN = MiGetPteAddress(page)->PageFrameNumber;
	hookedPages[0].voidCall = address + 16;
	DbgPrint("		rw %llx e %llx\n", hookedPages[0].readWritePFN, hookedPages[0].executePFN);

	//clear the present flag
	vpte->Valid = 0;

	//reload everything...
	//reloadcr3();

	//page is now hidden?
}

VOID notify(HANDLE parentId, HANDLE pid, BOOLEAN Create){
	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	DbgPrint("	EPROCESS: %llx\n", &process);
	DbgPrint("	NAME: %s\n", process->imageName);
	UCHAR name[16] = "myFaultTest.exe";
	if (process->imageName == name){
		DbgPrint("	EPROCESS: %llx\n", &process);
		DbgPrint("	Pushlock: %llx\n", process->pushlock);
		DbgPrint("	CR3: %llx\n", process->DirectoryTableBase);
		DbgPrint("	Base: %llx\n", process->SectionBaseAddress);
		getPTE(process->DirectoryTableBase, process->SectionBaseAddress);

		DbgPrint("\n\nATTEMPTING TO STEALTH HOOK!\n");

		PRKAPC_STATE apc = (PRKAPC_STATE)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC_STATE), 'apc');
		KeStackAttachProcess(process, apc);

		DbgPrint("	Pushlock: %llx\n", &apc->Process->pushlock);
		//FltAcquirePushLockShared(&apc->Process->pushlock);

		//overwrite that last pause
		hookers(process->DirectoryTableBase, process->SectionBaseAddress + 0x12CB, "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", 11);
		__debugbreak();

		KeUnstackDetachProcess(apc);
		ExFreePool(apc);
	}
}

VOID test42(UINT64 pid){
	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	DbgPrint("	EPROCESS: %llx\n", &process);
	DbgPrint("	NAME: %s\n", process->imageName);
}