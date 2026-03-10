# elfmutator

> *"The moral is obvious. You can't trust code that you did not totally create yourself."*
> - Ken Thompson, *Reflections on Trusting Trust (1984)*

## Disclaimer

**This project is a security research and educational demonstration only.**

`elfmutator` and all payloads in this repository are published to illustrate binary level trust concepts described in Ken Thompson's 1984 Turing Award lecture. They are intended for use in controlled environments, on systems you own or have explicit written permission to test.

The author assumes no liability for any misuse of this code. Using these tools against systems without authorization is **illegal and is explicitly not condoned**. If you use this code for anything other than education and authorized research, that is your choice and your legal responsibility, not the author's.

The techniques demonstrated here are decades old, widely documented, and available in every shellcode reference in existence. Publishing them in a clear, understandable form for researchers and students does not make the world less safe. Hiding them does not make it more safe. Understanding them does.

## Abstract

`elfmutator` is a minimal ARM32 ELF binary injector. It takes a compiled binary, appends a shellcode payload as a new loadable segment, redirects the ELF entry point to the payload, and patches the payload's stub instruction with a branch back to the original program, so the host binary executes normally after the payload runs.

The result is a binary that does something it was never written to do, and shows no outward sign of it.

```
                  --------------------------------
                  |         out.elf              |
                  |                              |
  kernel          |  [entry] ------------------> |  payload runs
  execve -------->|                              |  (write syscall)
                  |  payload: b main ----------> |  main() runs
                  |                              |  (original code)
                  |  [exit]                      |
                  --------------------------------
```

The host binary never consented to this. Neither did you, necessarily, when you ran a binary someone else compiled.

## The Trusting Trust Problem

In 1984 Ken Thompson demonstrated that a C compiler could be trojaned to insert malicious code into programs it compiled, including a new copy of the trojan into any future compiler it compiled, with no trace of the attack in any source code anywhere. The attack lives in the compiler binary itself. You cannot find it by reading source. You cannot find it by recompiling, because the infected compiler reinfects its own output.

Thompson's conclusion was not that you should audit your compiler. It was that you cannot. Trust is transitive and the chain goes further back than anyone can follow.

`elfmutator` is a concrete, inspectable illustration of one tiny link in that chain, the binary level.

## How it works

### 1. ELF structure

An ELF executable contains program headers describing loadable segments. The kernel reads these at `execve` time and maps each `PT_LOAD` segment into the process's virtual address space. The entry point (`e_entry`) is a virtual address the kernel jumps to after mapping is done.

elfmutator adds one more `PT_LOAD` segment, page aligned, readable and executable, containing the payload, then sets `e_entry` to the start of that segment.

```
Original ELF:                    Mutated ELF:

  LOAD [0x10000 R E]               LOAD [0x10000 R E]    original code
  LOAD [0x7ed48 RW ]               LOAD [0x7ed48 RW ]    original data
  e_entry = 0x1029c                LOAD [0x85000 R E]    injected payload
                                   e_entry = 0x85000     redirected
```

### 2. The stub pattern

The payload assembly contains a deliberate infinite loop `b .` which assembles to the 4byte pattern `fe ff ff ea` in ARM little endian. `elfmutator` scans the payload binary for this pattern, then overwrites it with a computed `b <target>` instruction that branches to `main()` in the host binary.

```c
//find the stub
for (size_t i = 0; i + 4 <= payload_size; i++) {
    if (payload[i] == 0xfe && payload[i+1] == 0xff &&
        payload[i+2] == 0xff && payload[i+3] == 0xea) {
        stub_offset = i;
        break;
    }
}

//patch it with a real branch
int32_t offset_words = (target - (stub_vaddr + 8)) / 4;
uint32_t branch = 0xea000000 | (offset_words & 0x00ffffff);
memcpy(payload + stub_offset, &branch, 4);
```

The `+8` is the ARM pipeline prefetch offset, the PC is always 8 bytes ahead of the executing instruction.

### 3. Why `-nostdlib`

The host binary must be compiled without glibc (`-nostdlib -nostartfiles`). This is not a limitation of the injector, it is a consequence of how glibc initializes itself.

glibc's `_start` calls `__libc_start_main`, which sets up TLS, the stack canary, stdio vtables, `atexit` handlers, and other global state, then calls `main()`. This initialization happens exactly once and is not idempotent. If the payload returns to `_start`, all of it runs a second time over already initialized memory and corrupts it. If the payload jumps directly to `main()`, libc's internal state is incomplete and `printf` dereferences a null vtable pointer.

The clean solution for libc binaries is a separate unsolved problem. The clean solution for `-nostdlib` binaries is trivial: `main()` is just a function. Branch to it. It calls `sys_exit()` and never returns.

## Usage

```sh
#build the injector
make

#assemble the payload to a flat binary
make payload

#compile a target, inject, and run
make test

#debug: disassembly, segment inspection, strace
make debug
```

### Manual injection

```sh
./elfmutator <input.elf> <output.elf> <payload.bin>
```

The input must be an ARM32 ELF executable with at least one `PT_LOAD` segment and an accessible symbol table (not stripped). The payload must be a flat binary containing the `fe ff ff ea` stub somewhere in its code section.

## Payload format

The payload is a flat ARM32 binary (no ELF headers). It must contain exactly one `b .` stub `fe ff ff ea` which elfmutator will patch with a branch to the target. Data must come after all code so the stub offset scan finds the right bytes.

```asm
_start:
mov r7, #4
mov r0, #1
adr r1, msg
mov r2, #34
svc 0
b .
msg:
    .asciz "Malicious ARM32 payload executed!\n"
```

Assemble and strip to binary:

```sh
as -o payload_arm.o payload_arm.S
objcopy -O binary payload_arm.o payload.bin
```

## Limitations

- ARM32 only (`EM_ARM`, `ELFCLASS32`)
- Target binary must not be stripped (symbol table required to locate `main`)
- Branch range limited to ±32MB between payload and target
- Does not support PIE binaries (`-no-pie` required)
- Does not support Thumb entry points
- Requires a writable program header table slot (elfmutator appends one)

## Files

| File            | Purpose                                       |
|-----------------|-----------------------------------------------|
| `elfmutator.c`  | The injector                                  |
| `payload_arm.S` | Example ARM32 payload (write + branch stub)   |
| `test.c`        | Minimal target binary (raw syscalls, no libc) |
| `Makefile`      | Build, test, and debug rules                  |

## On trust

Thompson's attack required access to the compiler. `elfmutator` requires access to the binary before it reaches you, a supply chain position, a compromised build server, a tampered download.

The binary you ran to get here was compiled by a compiler you did not compile, on a machine you did not build, running an OS you did not write. Each of those is a point of insertion. `elfmutator` is just one such point, made visible and understood.

Understanding the mechanism is the only partial defense. You cannot eliminate the trust. You can only know where it lives.

## License

GPL-3.0-only
