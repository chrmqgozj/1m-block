LDLIBS += -lnetfilter_queue

all: 1m-block

netfilter-test: 1m-block.c

clean:
	rm -f main *.o
