all: multi_block

multi_block: multi_block.c
	gcc -o multi_block multi_block.c -lnetfilter_queue

clean:
	rm multi_block

