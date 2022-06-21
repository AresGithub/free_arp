all: 
	aarch64-linux-gnu-gcc free_arp.c -o free_arp_arm64
	arm-none-linux-gnueabi-gcc free_arp.c -o free_arp_arm32

.PHONY: clean

clean:
	rm -fr free_arp_arm32 free_arp_arm64
