
.code16

main:
    mov ax, 0x0
    mov dx, 0x2
    in  ax, 0x218
    add ax, dx
    out 0x217, ax
    mov dx, word [0x8000]
    add dx, ax
    mov word [0x8004], dx
    mov ax, 0x1
    out 0x217, ax
    vmcall
    out 0x217, ax
    mov ax, 0x4
    vmcall
    out 0x217, ax
    hlt
