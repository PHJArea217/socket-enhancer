all: socket-enhancer

socket-enhancer: socket-enhancer.c
	$(CC) -shared -fstack-protector-strong -o socket-enhancer socket-enhancer.c -fPIC -ldl -Wall -Wextra -Wl,-z,relro,-z,now
clean:
	rm -f socket-enhancer

.PHONY: all clean
