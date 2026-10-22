; Runs a hooked pak-list reader between PakReaderEnter and PakReaderExit (pak_list_race.cpp).
;
; The readers have different signatures, so this passes every argument through as it is: rcx, rdx, r8, r9, xmm0-3
; and the caller's first 16 stack arguments (20 in all, well past what the engine's pak functions take; copying a
; fixed number avoids needing each reader's signature). rax holds the ReaderHook on entry; its first
; field is the original function's trampoline. Declared as a frame function so stack walks unwind through it.

EXTERN PakReaderEnter:PROC
EXTERN PakReaderExit:PROC

STACK_ARGS     EQU 16
ARGS_OUT       EQU 20h                      ; the original's stack arguments, after its shadow space
SAVED_GPR      EQU ARGS_OUT + STACK_ARGS * 8
SAVED_XMM      EQU SAVED_GPR + 20h
PREVIOUS_EPOCH EQU SAVED_XMM + 40h
RESULT_GPR     EQU PREVIOUS_EPOCH + 8
RESULT_XMM     EQU RESULT_GPR + 8
FRAME_SIZE     EQU RESULT_XMM + 20h         ; keeps rsp 16-byte aligned after the push
ARGS_IN        EQU FRAME_SIZE + 8 + 8 + 20h ; the caller's stack arguments: past the push, return address, shadow

.code

PakReaderThunk PROC FRAME
	push rbx
	.pushreg rbx
	sub rsp, FRAME_SIZE
	.allocstack FRAME_SIZE
	.endprolog

	mov rbx, rax
	mov [rsp + SAVED_GPR], rcx
	mov [rsp + SAVED_GPR + 8], rdx
	mov [rsp + SAVED_GPR + 10h], r8
	mov [rsp + SAVED_GPR + 18h], r9
	movaps [rsp + SAVED_XMM], xmm0
	movaps [rsp + SAVED_XMM + 10h], xmm1
	movaps [rsp + SAVED_XMM + 20h], xmm2
	movaps [rsp + SAVED_XMM + 30h], xmm3

	mov rcx, rbx
	call PakReaderEnter
	mov [rsp + PREVIOUS_EPOCH], rax

	; xmm4 is free to use: it isn't an argument register
	ARG_PAIR = 0
	REPEAT STACK_ARGS / 2
		movups xmm4, [rsp + ARGS_IN + ARG_PAIR * 10h]
		movups [rsp + ARGS_OUT + ARG_PAIR * 10h], xmm4
		ARG_PAIR = ARG_PAIR + 1
	ENDM

	mov rcx, [rsp + SAVED_GPR]
	mov rdx, [rsp + SAVED_GPR + 8]
	mov r8, [rsp + SAVED_GPR + 10h]
	mov r9, [rsp + SAVED_GPR + 18h]
	movaps xmm0, [rsp + SAVED_XMM]
	movaps xmm1, [rsp + SAVED_XMM + 10h]
	movaps xmm2, [rsp + SAVED_XMM + 20h]
	movaps xmm3, [rsp + SAVED_XMM + 30h]
	call qword ptr [rbx]

	mov [rsp + RESULT_GPR], rax
	movaps [rsp + RESULT_XMM], xmm0
	mov rcx, [rsp + PREVIOUS_EPOCH]
	call PakReaderExit
	mov rax, [rsp + RESULT_GPR]
	movaps xmm0, [rsp + RESULT_XMM]

	add rsp, FRAME_SIZE
	pop rbx
	ret
PakReaderThunk ENDP

END
