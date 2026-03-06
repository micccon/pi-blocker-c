CC     = gcc
CFLAGS = -Wall -Wextra -pthread

SRC    = main.c link_monitor.c
TARGET = link-monitor

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: all
	./start_layer1.sh

.PHONY: all clean run
