#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include "sha3.h"

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

static const char *hashname[] = {
	"SHA3-224",
	"SHA3-256",
	"SHA3-384",
	"SHA3-512"
};

static int hashlen[] = {
	SHA3_224_DIGEST_SIZE,
	SHA3_256_DIGEST_SIZE,
	SHA3_384_DIGEST_SIZE,
	SHA3_512_DIGEST_SIZE
};

static int sha3_stream(FILE * stream, void *out, size_t outlen)
{
	int ret = -1;
	size_t n;
	struct sha3_ctx ctx;
	const size_t buf_len = 65536;
	uint8_t *buf = (uint8_t *) malloc(buf_len);

	if (!stream || !out || !buf)
		return -1;

	sha3_init(&ctx, outlen);

	while (!feof(stream)) {
		n = fread(buf, 1, buf_len, stream);

		if (ferror(stream))
			goto end;

		if (n > 0)
			sha3_update(&ctx, buf, n);
	}

	sha3_final(&ctx, out, outlen);
	ret = 0;

 end:
	free(buf);
	return ret;
}

static int sha3_file(const char *fname, void *out, size_t outlen)
{
	FILE *f = NULL;
	int ret = -1;

	if (!fname || !out)
		return -1;

	if (fname[0] == '-' && fname[1] == '\0')
		f = stdin;
	else
		f = fopen(fname, "rb");

	if (!f) {
		fprintf(stderr, "Could not open `%s': %s\n", fname,
			strerror(errno));
		return ret;
	}

	if (sha3_stream(f, out, outlen) < 0)
		fprintf(stderr, "Failed to hash `%s'\n", fname);
	else
		ret = 0;

	if (f != stdin)
		fclose(f);

	return ret;
}

static int
print_out(int bsdstyle, FILE * fout, const char *alg,
	  const char *fname, unsigned char *hash, size_t len)
{
	size_t i = 0;

	if (!fout || !alg || !hash)
		return -1;

	if (bsdstyle)
		fprintf(fout, "%s (%s) = ", alg, fname);

	for (i = 0; i < len; i++)
		fprintf(fout, "%02x", hash[i]);

	if (bsdstyle)
		fprintf(fout, "\n");
	else
		fprintf(fout, "  %s\n", fname);

	return 0;
}

static int match_hash_len(int bsdstyle, const char *alg, const char *hash)
{
	int i = 0;
	int hlen = 0;
	int len = 0;

	if (bsdstyle && alg) {
		for (i = 0; i < ARRAY_SIZE(hashname); i++)
			if (strcmp(alg, hashname[i]) == 0)
				return hashlen[i];
		return -1;
	} else if (hash) {
		hlen = strlen(hash);
		if (hlen % 2 != 0)
			return -1;
		len = hlen / 2;
		for (i = 0; i < ARRAY_SIZE(hashlen); i++)
			if (hashlen[i] == len)
				return hashlen[i];
		return -1;
	}

	return -1;
}

static int check_sha3(const char *outname)
{
	FILE *f = NULL;

	if (outname[0] == '-' && outname[1] == '\0')
		f = stdin;
	else
		f = fopen(outname, "rb");

	if (!f) {
		fprintf(stderr, "Could not open `%s': %s\n", outname,
			strerror(errno));
		exit(-1);
	}

	while (!feof(f) && !ferror(f)) {
		char line[LINE_MAX] = { 0 };
		char fname[NAME_MAX] = { 0 };
		char hex_hash[SHA3_512_DIGEST_SIZE * 2 + 1] = { 0 };
		unsigned char old_hash[SHA3_512_DIGEST_SIZE] = { 0 };
		unsigned char new_hash[SHA3_512_DIGEST_SIZE] = { 0 };
		char alg[16] = { 0 };
		char *s = NULL;
		int hash_len = 0;
		int n, i;
		unsigned int c;
		int bsdstyle = 0;
		int len = 0;
		int ret = 0;

		s = fgets(line, sizeof(line), f);
		if (s == NULL)
			break;
		len = strlen(line);
		if (line[len-1] == '\n')
			line[len-1] = '\0';

		n = sscanf(line, "%s (%[^)] %*s%*s %s\n", alg, fname, hex_hash);
		if (n == 3) {
			bsdstyle = 1;
		} else {
			n = sscanf(line, "%s  %s\n", hex_hash, fname);
			if (n != 2) {
				fprintf(stderr, "%s format err!\n", outname);
				continue;
			}
		}

		hash_len = match_hash_len(bsdstyle, alg, hex_hash);
		if (hash_len < 0)
			continue;
		for (i = 0; i < hash_len; i++) {
			sscanf(&hex_hash[i * 2], "%02x", &c);
			old_hash[i] = (unsigned char)c;
		}

		ret = sha3_file(fname, new_hash, hash_len);
		if (ret < 0) {
			fprintf(stderr, "calculate sha3 err:%s\n", fname);
			continue;
		}
		if (memcmp(old_hash, new_hash, hash_len) == 0)
			fprintf(stdout, "%s OK\n", fname);
		else
			fprintf(stdout, "%s ERROR\n", fname);

	}

	if (f != stdout)
		fclose(f);
	return 0;
}

static void usage(char **argv, int outerr)
{
	FILE *out = outerr ? stderr : stdout;
	fprintf(out, "Usage: %s [OPTION]... [FILE]...\n", argv[0]);
	fprintf(out, "\n");
	fprintf(out, "With no FILE, or when FILE is -, read standard input.\n");
	fprintf(out, "\n");
	fprintf(out,
		"  -c | --check read SHA3 sums from the FILEs and check them\n");
	fprintf(out, "  -l <length>  digest length in bits, 224 256 384 512\n");
	fprintf(out, "  --tag        create a BSD-style checksum\n");
	fprintf(out, "  --help       display this help and exit\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	const char *alg = hashname[0];
	unsigned long outbits, outbytes = SHA3_224_DIGEST_SIZE;
	unsigned char hash[SHA3_512_DIGEST_SIZE] = { 0 };
	int bsdstyle = 0;
	int check = 0;
	int c, i;

	static struct option long_options[] = {
		{"check", no_argument, 0, 0},
		{"help", no_argument, 0, 0},
		{"tag", no_argument, 0, 0},
		{NULL, 0, NULL, 0}
	};

	opterr = 1;
	while (1) {
		int option_index = 0;
		char *end = NULL;

		c = getopt_long(argc, argv, "l:c", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'l':
			outbits = strtoul(optarg, &end, 10);
			if (!end || *end != '\0' || (outbits % 8 != 0)) {
				printf("Invalid length argument: `%s'\n",
				       optarg);
				usage(argv, 1);
			} else {
				outbytes = outbits / 8;
				if (outbytes == SHA3_224_DIGEST_SIZE)
					alg = hashname[0];
				else if (outbytes == SHA3_256_DIGEST_SIZE)
					alg = hashname[1];
				else if (outbytes == SHA3_384_DIGEST_SIZE)
					alg = hashname[2];
				else if (outbytes == SHA3_512_DIGEST_SIZE)
					alg = hashname[3];
				else {
					printf("Invalid length argument: `%s'\n",
					     optarg);
					usage(argv, 1);
				}
			}
			break;

		case 'c':
			check = 1;
			break;

		case 0:
			if (!strcmp("help", long_options[option_index].name))
				usage(argv, 0);
			else if (!strcmp("check", long_options[option_index].name))
				check = 1;
			else if (!strcmp("tag", long_options[option_index].name))
				bsdstyle = 1;
			break;

		case '?':
			usage(argv, 1);
			break;
		}
	}

	if (optind == argc)
		argv[argc++] = (char *)"-";

	if (!check) {
		for (i = optind; i < argc; ++i) {
			if (sha3_file(argv[i], hash, outbytes) < 0) {
				fprintf(stderr, "calculate sha3 err:%s\n",
					argv[i]);
				continue;
			}
			print_out(bsdstyle, stdout, alg, argv[i], hash,
				  outbytes);
		}
	} else {
		check_sha3(argv[optind]);
	}

	return 0;
}
