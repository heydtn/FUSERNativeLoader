; Called by a pak reader's return stub: ends the reader, keeping its return value

EXTERN pak_return_exit:PROC

RETURN_XMM   EQU 20h
RETURN_GPR   EQU 30h
RETURN_FRAME EQU 48h                        ; keeps rsp 16-byte aligned: the stub's call left it 8 off

.code

pak_return_thunk PROC FRAME
    sub rsp, RETURN_FRAME
    .allocstack RETURN_FRAME
    .endprolog

    mov [rsp + RETURN_GPR], rax
    movups [rsp + RETURN_XMM], xmm0
    lea rcx, [rsp + RETURN_FRAME + 8]       ; the stack at the stub: just above where the return address was
    call pak_return_exit
    mov rax, [rsp + RETURN_GPR]
    movups xmm0, [rsp + RETURN_XMM]

    add rsp, RETURN_FRAME
    ret
pak_return_thunk ENDP

END
