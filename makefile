CC=g++
TARGET=ipk-sniffer
LDFLAGS=-lpcap

all: $(TARGET)

$(TARGET): main.cpp
	$(CC) -std=c++20 $^ -o $@ $(LDFLAGS)

clean:
	$(RM) $(TARGET)
