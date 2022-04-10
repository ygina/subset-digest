# CFLAGS += -lpcap -g -target arm-eabi -marm -mfpu=vfp -mcpu=arm1176jzf-s -mtune=arm1176jzf-s -mfloat-abi=softfp -I/usr/include
CFLAGS += -lpcap -g -target arm-eabi -marm -mfpu=vfp -mcpu=arm1176jzf-s -mtune=arm1176jzf-s -mfloat-abi=softfp -I/usr/include

CC = clang

all: just_dump

just_dump: just_dump.c
	$(CC) $^ $(CFLAGS) -o $@
