.data

EXTERN OrigKeBugCheckExRestorePointer:PROC
EXTERN OrigKiPageFaultRestorePointer:PROC
EXTERN KiPageFaultHook:PROC

.code

ADDRESSOF PROC
	mov rax, qword ptr [rcx]
	ret
ADDRESSOF ENDP

JUMP PROC
	push rcx
	mov dword ptr[rsp + 4], edx
	ret
JUMP ENDP

reloadDTLB proc
	push rax
	mov rax, cr2
	mov rax, qword ptr [rax]
	pop rax
	ret
reloadDTLB ENDP

reloadcr3 proc
	push rax
	mov rax, cr3
	mov cr3, rax
	pop rax
	ret
reloadcr3 ENDP

GIDT PROC address:QWORD 
	sidt address
	mov rax, address+2
	ret
GIDT ENDP

; Points the stack pointer at the supplied argument and returns to the caller.
public AdjustStackCallPointer
AdjustStackCallPointer PROC
    mov rsp, rcx
    xchg r8, rcx
    jmp rdx
AdjustStackCallPointer ENDP

; Wraps the overwritten preamble of KeBugCheckEx.
public OrigKeBugCheckEx
OrigKeBugCheckEx PROC
    mov [rsp+8h], rcx
    mov [rsp+10h], rdx
    mov [rsp+18h], r8
    jmp qword ptr [OrigKeBugCheckExRestorePointer]
OrigKeBugCheckEx ENDP

public OrigKiPageFault
OrigKiPageFault PROC
	;int 3					;@@@@@@@@@@@@@@@@@@ take a look at the stack here
	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	sub rsp, 6*16
	movups xmmword ptr [rsp+0*16], xmm0
	movups xmmword ptr [rsp+1*16], xmm1
	movups xmmword ptr [rsp+2*16], xmm2
	movups xmmword ptr [rsp+3*16], xmm3
	movups xmmword ptr [rsp+4*16], xmm4
	movups xmmword ptr [rsp+5*16], xmm5
	
	mov rcx, [rsp+216]
	mov rdx, [rsp+224]
	call KiPageFaultHook
	cmp al, 1
	jne resume

	movups xmm0, xmmword ptr [rsp+0*16]
	movups xmm1, xmmword ptr [rsp+1*16]
	movups xmm2, xmmword ptr [rsp+2*16]
	movups xmm3, xmmword ptr [rsp+3*16]
	movups xmm4, xmmword ptr [rsp+4*16]
	movups xmm5, xmmword ptr [rsp+5*16]
	add rsp, 6*16
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax

	add rsp, 8
	iretq

	resume:
	
	movups xmm0, xmmword ptr [rsp+0*16]
	movups xmm1, xmmword ptr [rsp+1*16]
	movups xmm2, xmmword ptr [rsp+2*16]
	movups xmm3, xmmword ptr [rsp+3*16]
	movups xmm4, xmmword ptr [rsp+4*16]
	movups xmm5, xmmword ptr [rsp+5*16]
	add rsp, 6*16
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax

    push rbp
    sub rsp, 158h
	lea rbp, [rsp+80h]
	jmp qword ptr [OrigKiPageFaultRestorePointer]
OrigKiPageFault ENDP

END