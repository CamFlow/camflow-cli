INCLUDES = -I../include
CCFLAGS = -g -O2 -fpic
CCC = gcc
LIB = -lprovenance -lpthread -lz

.SUFFIXES: .c

all:
	$(CCC) $(INCLUDES) camflow.c $(LIB) -o camflow.o $(CCFLAGS)

debug:
	$(CCC) $(INCLUDES) camflow.c $(LIB) -o camflow.o $(CCFLAGS) -g

clean:
	rm -f camflow.o

install:
	cp --force ./camflow.o /usr/bin/camflow
