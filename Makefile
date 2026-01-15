CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = pi-blocker

all: $(TARGET)

$(TARGET): main.c dns.c
	$(CC) $(CFLAGS) main.c dns.c -o $(TARGET)

clean:
	rm -f $(TARGET)
