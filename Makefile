CFLAGS=`pkg-config --cflags gtk+3.0`

all: main

main: main.c
	gcc -o spyware-beware `pkg-config --cflags gtk+-3.0` main.c monitor.c helpers.c `pkg-config --libs gtk+-3.0` -lpcap

debug: main.c
	gcc -o spyware-beware-debug -g `pkg-config --cflags gtk+-3.0` main.c monitor.c helpers.c `pkg-config --libs gtk+-3.0` -lpcap

monitor.o: monitor.c
	gcc `pkg-config --cflags gtk+-3.0` monitor.c `pkg-config --libs gtk+-3.0`



clean:
	rm *.o spyware-beware
