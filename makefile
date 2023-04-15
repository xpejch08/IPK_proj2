CC = g++
CFLAGS = -Wall -Werror
TARGET = main.cpp

all:
	g++ -std=c++20 main.cpp -o out
clean:
	$(RM) out