CFLAGS := -std=c99 -O2 -Wall -fPIC

all: call-fprintf

call-fprintf: call_fprintf.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f call-fprintf

.PHONY: all clean
