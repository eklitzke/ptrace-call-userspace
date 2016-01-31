CFLAGS := -std=c99 -O2 -Wall -fPIC

all: call_fprintf

call_fprintf: call_fprintf.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f call_fprintf

.PHONY: all clean
