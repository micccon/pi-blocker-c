CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpthread
SRC = main.c proxy.c ../dns/dns.c
TARGET = http-proxy

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: all
	./$(TARGET)

.PHONY: all clean run
