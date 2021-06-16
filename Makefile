socket-enhancer: socket-enhancer.c
	gcc -shared -fstack-protector-strong -o socket-enhancer socket-enhancer.c -fPIC -ldl -Wall -Wextra
