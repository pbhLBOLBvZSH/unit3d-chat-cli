CC = gcc
CFLAGS = -std=c99 -Wall -Wextra
LIBS = -lcurl -lpthread -lncurses
SRC = src/main.c src/jsmn.c
TARGET = chat

# Performance build flags
PERF_CFLAGS = -O3 -march=native -flto -DNDEBUG
PERF_LDFLAGS = -s
PERF_TARGET = chat-perf

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Build a stripped, optimized binary for performance/testing
perf: CFLAGS += $(PERF_CFLAGS)
perf: LDFLAGS += $(PERF_LDFLAGS)
perf: $(PERF_TARGET)

$(PERF_TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PERF_TARGET) $(SRC) $(LIBS)
	strip --strip-all $(PERF_TARGET) || true

clean:
	rm -f $(TARGET) $(PERF_TARGET)
