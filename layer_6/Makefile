CC     = gcc
CFLAGS = -Wall -Wextra -pthread

SRC    = main.c tls_inspector.c ../layer_7/dns/dns.c
TARGET = tls-inspector

all: $(TARGET)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: all
	./start_layer6.sh

.PHONY: all clean run
