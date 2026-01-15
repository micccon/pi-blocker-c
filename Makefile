CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpthread
TARGET = pi-blocker

all: $(TARGET)

$(TARGET): main.c dns.c
	$(CC) $(CFLAGS) main.c dns.c -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)