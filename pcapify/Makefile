CFLAGS += -lpcap -g

all: just_dump main compare

compare: compare.c
	$(CC) $^ $(CFLAGS) -o $@

just_dump: just_dump.c
	$(CC) $^ $(CFLAGS) -o $@

main: main.c
	$(CC) $^ $(CFLAGS) -o $@
