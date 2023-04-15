LDFLAGS = -lpcap

all: out

out: main.cpp
	g++ -std=c++20 $^ -o $@ $(LDFLAGS)

clean:
	$(RM) out
