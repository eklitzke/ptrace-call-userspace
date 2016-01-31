CFLAGS := -std=c99 -O2 -Wall -fPIC

all: show_ip

show_ip: show_ip.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f show_ip

.PHONY: all clean
