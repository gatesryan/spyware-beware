CFLAGS=`pkg-config --cflags gtk+3.0`

all: main
	rm *.o

main: main.c monitor.o netstructs.o
	gcc -o spyware-beware `pkg-config --cflags gtk+-3.0` main.c monitor.o netstructs.o `pkg-config --libs gtk+-3.0` -lpcap

monitor.o: monitor.c
	gcc -c monitor.c

netstructs.o: netstructs.c
	gcc -c netstructs.c

clean:
	rm *.o spyware-beware
