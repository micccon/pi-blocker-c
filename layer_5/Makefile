CC     = gcc
CFLAGS = -Wall -Wextra -pthread

SRC    = main.c session.c ../common/blocklist.c ../common/enforce.c
TARGET = session-inspector

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: all
	./start_layer_5.sh

.PHONY: all clean run
