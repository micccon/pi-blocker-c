CC     = gcc
CFLAGS = -Wall -Wextra -pthread

SRC    = main.c filter.c ../common/enforce.c
TARGET = port-filter

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: all
	./$(TARGET)

.PHONY: all clean run
