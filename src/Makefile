INCLUDES = -I../include
CCFLAGS = -g -O2 -fpic
CCC = gcc
LIB = /usr/local/lib/provenancelib.a -lpthread -lz

.SUFFIXES: .c

all:
	$(CCC) $(INCLUDES) tool.c $(LIB) -o tool.o $(CCFLAGS)

debug:
	$(CCC) $(INCLUDES) tool.c $(LIB) -o tool.o $(CCFLAGS) -g

clean:
	rm -f tool.o

install:
	cp --force ./tool.o /usr/bin/camflow
