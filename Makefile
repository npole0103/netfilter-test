netfilter-test : netfilter-test.o
	gcc -o netfilter-test netfilter-test.o -lnetfilter_queue

netfilter-test.o : netfilter-test.c

clean:
	rm *.o netfilter-test
