
all:
	gcc -Wall -O3 -DKECCAKF_MACRO -o sha3sum sha3sum.c sha3.c
clean:
	rm -f sha3sum
