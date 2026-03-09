CC=gcc
BIN=elfmutator

all: $(BIN)

$(BIN): elfmutator.c
	$(CC) -o $@ $<

payload:
	as -o payload_arm.o payload_arm.S
	objcopy -O binary payload_arm.o payload.bin
	ls -l payload.bin
	hexdump -C payload.bin | tail

test:
	$(CC) -no-pie -static -marm -nostdlib -nostartfiles -o test.o test.c
	./$(BIN) test.o out.elf payload.bin
	chmod +x out.elf
	readelf -h out.elf
	readelf -l out.elf
	echo
	echo "running injected binary..."
	./out.elf

debug: test.o out.elf payload.bin
	@printf "\nmain() disassembly\n"
	@MAIN=$$(readelf -s test.o | awk '/ main$$/{printf "%08x", strtonum("0x"$$2)}'); \
	 objdump -d test.o | awk "/^$$MAIN <main>:/{f=1} f{print; if(/^\s*$$/ && f>1) exit; f++}" | head -30
	@printf "\n_start/entry disassembly\n"
	@START=$$(readelf -s test.o | awk '/ _start$$/{printf "%08x", strtonum("0x"$$2)}'); \
	 if [ -z "$$START" ]; then \
	   START=$$(readelf -h test.o | awk '/Entry point/{printf "%08x", strtonum($$4)}'); \
	 fi; \
	 objdump -d test.o | awk "/^$$START </{f=1} f{print; if(/^\s*$$/ && f>1) exit; f++}" | head -40
	@printf "\npayload disassembly (raw binary)\n"
	@objdump -b binary -m arm -D payload.bin
	@printf "\ninjected segment in out.elf (with vaddr)\n"
	@VADDR=$$(readelf -l out.elf | awk '/LOAD/{off=$$2; va=$$3; fl=$$6} \
		fl ~ /E/ {last_va=va} END{printf "%d", strtonum(last_va)}'); \
	 objdump -b binary -m arm -D --adjust-vma=$$VADDR payload.bin
	@printf "\nstub patch location in out.elf\n"
	@PAYLOAD_FOFF=$$(readelf -l out.elf | awk '/LOAD/{off=$$2; fl=$$6} \
		fl ~ /E/ {last=off} END{printf "%d", strtonum(last)}'); \
	 STUB_DELTA=$$(objdump -b binary -m arm -D payload.bin \
	 | awk '/eafffffe/{printf "%d", strtonum("0x"$$1); exit}'); \
	 STUB_ABS=$$(($$PAYLOAD_FOFF + $$STUB_DELTA)); \
	 printf "stub at file offset 0x%x:\n" $$STUB_ABS; \
	 hexdump -C out.elf -s $$STUB_ABS -n 8
	@printf "\nnon zero symbols\n"
	@readelf -s test.o \
		| awk 'NR>3 && $$2!="00000000" && $$4!="FILE" {print}' \
		| sort -k2 | head -20
	@printf "\nstrace\n"
	@strace ./out.elf 2>&1 || true

clean:
	rm -f $(BIN) out.elf test.o payload_arm.o payload.bin	
