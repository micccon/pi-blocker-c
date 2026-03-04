CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpthread
TARGET = dns-filter

all: $(TARGET)

$(TARGET): main.c dns.c ../../common/blocklist.c
	$(CC) $(CFLAGS) main.c dns.c ../../common/blocklist.c -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
