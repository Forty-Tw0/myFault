#include "ntddk.h"

VOID boringFunction(){
	DbgPrint("	This is a normal function.\n");
	DbgPrint("		I should probably make sure there are enough bytes in it to inject a hook...\n");
	DbgPrint("		I should be safe to overwrite anything on the page.\n");
	DbgPrint("		I should probably redirct read-writes from the hook function to the real page to prevent data corruption.\n");
	DbgPrint("		I wonder If I could write my own hooking API also?\n");
	DbgPrint("		This should be enough bytes.\n");
}