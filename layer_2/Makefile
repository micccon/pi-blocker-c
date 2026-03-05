CC     = gcc
CFLAGS = -Wall -Wextra -pthread

SRC    = main.c arp_monitor.c
TARGET = arp-monitor

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: all
	./start_layer2.sh

.PHONY: all clean run
