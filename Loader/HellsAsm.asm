.data
	wSystemCall		DWORD	0h	
	qSyscallInsAdress	QWORD	0h	


.code

	XmSetInvokeId proc	
		xor eax, eax				; eax = 0
		mov wSystemCall, eax			; wSystemCall = 0
		mov qSyscallInsAdress, rax		; qSyscallInsAdress = 0
		mov eax, ecx				; eax = ssn
		mov wSystemCall, eax			; wSystemCall = eax = ssn
		mov r8, rdx				; r8 = AddressOfASyscallInst
		mov qSyscallInsAdress, r8		; qSyscallInsAdress = r8 = AddressOfASyscallInst
		ret
	XmSetInvokeId endp


; XmSetInvokeId should look like this :
	;XmSetInvokeId PROC
	;	mov wSystemCall, 0h
	;	mov qSyscallInsAdress, 0h
	;	mov wSystemCall, ecx
	;	mov qSyscallInsAdress, rdx
	;	ret
	;XmSetInvokeId ENDP


	XmInvokeSystemCall proc
		xor r10, r10					; r10 = 0
		mov rax, rcx					; rax = rcx
		mov r10, rax					; r10 = rax = rcx
		mov eax, wSystemCall				; eax = ssn
		jmp Run						; execute 'Run'
		xor eax, eax					; wont run
		xor rcx, rcx					; wont run
		shl r10, 2					; wont run
	Run:
		jmp qword ptr [qSyscallInsAdress]
		xor r10, r10					; r10 = 0
		mov qSyscallInsAdress, r10			; qSyscallInsAdress = 0
		ret
	XmInvokeSystemCall endp


; XmInvokeSystemCall should look like this :
	;XmInvokeSystemCall PROC
	;	mov r10, rcx
	;	mov eax, wSystemCall
	;	jmp qword ptr [qSyscallInsAdress]
	;	ret
	;XmInvokeSystemCall ENDP


end
