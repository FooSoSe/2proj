CC=g++
CPPFLAGS=-Wall -pedantic -std=c++11

.PHONY: all clean

all: main.cpp
	${CC} ${CPPFLAGS} main.cpp -o trace

clean:
	rm -vf *.o
