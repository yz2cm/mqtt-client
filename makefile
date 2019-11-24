#gcc mqtt-client.c -L/usr/local/openssl-1.1.1/lib -lssl -lcrypto -I/usr/local/openssl-1.1.1/include -o mqtt-client

mqtt-client: mqtt-client.c
	gcc -Wall -Wextra -pedantic -L/usr/local/openssl-1.1.1/lib -lssl -lcrypto -I/usr/local/openssl-1.1.1/include -o mqtt-client mqtt-client.c

.PHONY: clean
clean:
	rm -f mqtt-client mqtt-client.o

