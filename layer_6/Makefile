CC     = gcc
CFLAGS = -Wall -Wextra -pthread

SRC    = main.c tls_inspector.c ../common/blocklist.c
TARGET = tls-inspector

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: all
	./start_layer6.sh

.PHONY: all clean run
