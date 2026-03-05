CC     = gcc
CFLAGS = -Wall -Wextra -pthread

SRC    = main.c ip_filter.c ../common/enforce.c ../common/reputation.c
TARGET = ip-filter

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: all
	./$(TARGET)

.PHONY: all clean run
