proxy_cache: server.c

	gcc -o proxy_cache server.c -lcrypto -pthread
