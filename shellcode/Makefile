CC      := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
OBJDUMP := arm-none-eabi-objdump

CFLAGS  := -march=armv5te -marm -Os -nostdlib -fPIC -fPIE -fno-tree-loop-distribute-patterns

.PHONY: all clean disasm

all: cave.bin

cave.o: cave.c
	$(CC) $(CFLAGS) -c -o $@ $<

cave.elf: cave.o
	$(CC) $(CFLAGS) -o $@ $< -Wl,-Ttext=0x0,-e,cave

cave.bin: cave.elf
	$(OBJCOPY) -O binary $< $@
	@echo "cave.bin: $$(wc -c < $@) bytes"

disasm: cave.elf
	$(OBJDUMP) -D $<

clean:
	rm -f cave.o cave.elf cave.bin
