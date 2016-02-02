CFLAGS := -std=gnu99 -O2 -Wall -fPIC -g

all: call-fprintf target

call-fprintf: call_fprintf.c
	$(CC) $(CFLAGS) $< -o $@

target: target.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f call-fprintf target

.PHONY: all clean
