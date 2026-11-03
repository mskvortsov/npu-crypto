/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <kcapi.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

struct worker {
	struct kcapi_handle *handle;
	uint8_t *plain, *cipher, *output;
	uint8_t iv[12];
	size_t size, aad, encin, encout, decin, decout;
	uint64_t count;
	int error, decrypt;
	double end;
};

static pthread_barrier_t barrier;
static double deadline;

static double now(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static ssize_t crypt(struct worker *w)
{
	if (w->decrypt)
		return kcapi_aead_decrypt(w->handle, w->cipher, w->decin, w->iv,
					  w->output, w->decout,
					  KCAPI_ACCESS_SENDMSG);
	return kcapi_aead_encrypt(w->handle, w->plain, w->encin, w->iv,
				  w->cipher, w->encout, KCAPI_ACCESS_SENDMSG);
}

static void *run(void *arg)
{
	struct worker *w = arg;
	pthread_barrier_wait(&barrier);
	do {
		if (!w->decrypt) {
			/* A fresh nonce for every timed encryption under this
			 * key. */
			for (size_t i = 0; i < sizeof(w->iv); i++)
				if (++w->iv[i])
					break;
		}
		ssize_t ret = crypt(w);
		if (ret != (ssize_t)(w->decrypt ? w->aad + w->size
						: w->aad + w->size + 16)) {
			w->error = ret < 0 ? (int)-ret : EIO;
			break;
		}
		w->count++;
	} while (now() < deadline);
	w->end = now();
	return NULL;
}

static unsigned number(const char *s, unsigned max)
{
	char *end;
	errno = 0;
	unsigned long n = strtoul(s, &end, 10);
	if (errno || !*s || *end || n > max) {
		fprintf(stderr, "Invalid numeric argument: %s (maximum %u)\n",
			s, max);
		exit(EXIT_FAILURE);
	}
	return (unsigned)n;
}

static int prepare(struct worker *w, const char *algorithm)
{
	uint8_t key[32];
	int ret = kcapi_aead_init(&w->handle, algorithm, 0);
	if (ret)
		return -ret;
	if (kcapi_aead_ivsize(w->handle) != sizeof(w->iv))
		return EINVAL;
	if (getrandom(key, sizeof(key), 0) != sizeof(key))
		return EIO;
	ret = kcapi_aead_setkey(w->handle, key, sizeof(key));
	memset(key, 0, sizeof(key));
	if (ret)
		return -ret;
	ret = kcapi_aead_settaglen(w->handle, 16);
	if (ret)
		return -ret;
	kcapi_aead_setassoclen(w->handle, w->aad);
	w->encin = kcapi_aead_inbuflen_enc(w->handle, w->size, w->aad, 16);
	w->encout = kcapi_aead_outbuflen_enc(w->handle, w->size, w->aad, 16);
	w->decin = kcapi_aead_inbuflen_dec(w->handle, w->size, w->aad, 16);
	w->decout = kcapi_aead_outbuflen_dec(w->handle, w->size, w->aad, 16);
	w->plain = calloc(1, w->encin);
	w->cipher = calloc(1, w->encout > w->decin ? w->encout : w->decin);
	w->output = calloc(1, w->decout);
	if (!w->plain || !w->cipher || !w->output)
		return ENOMEM;
	for (size_t i = 0; i < w->aad + w->size; i++)
		w->plain[i] = (uint8_t)i;
	ssize_t n = crypt(w);
	if (n != (ssize_t)(w->aad + w->size + 16))
		return n < 0 ? (int)-n : EIO;
	w->decrypt = 1;
	n = crypt(w);
	if (n != (ssize_t)(w->aad + w->size) ||
	    memcmp(w->plain + w->aad, w->output + w->aad, w->size))
		return n < 0 ? (int)-n : EIO;
	/* Ensure authentication failures are actually reported. */
	w->cipher[w->aad + w->size] ^= 1;
	n = crypt(w);
	w->cipher[w->aad + w->size] ^= 1;
	if (n != -EBADMSG)
		return EIO;
	w->decrypt = 0;
	return 0;
}

int main(int argc, char **argv)
{
	const char *algorithm = "airoha-npu-chacha20poly1305";
	unsigned size = 1420, aad = 0, seconds = 3, jobs = 1;
	int opt, status = EXIT_FAILURE;
	while ((opt = getopt(argc, argv, "a:s:A:t:j:h")) != -1) {
		switch (opt) {
		case 'a':
			algorithm = optarg;
			break;
		case 's':
			size = number(optarg, 60000);
			break;
		case 'A':
			aad = number(optarg, 256);
			break;
		case 't':
			seconds = number(optarg, 3600);
			break;
		case 'j':
			jobs = number(optarg, 64);
			break;
		default:
			printf("Usage: %s [-a algorithm] [-s bytes] [-A "
			       "aad-bytes] "
			       "[-t seconds-per-direction] [-j workers]\n",
			       argv[0]);
			return opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}
	if (optind != argc || !size || !seconds || !jobs) {
		fprintf(stderr, "Size, duration and workers must be positive; "
				"use -h for help.\n");
		return EXIT_FAILURE;
	}
	struct worker *workers = calloc(jobs, sizeof(*workers));
	pthread_t *threads = calloc(jobs, sizeof(*threads));
	if (!workers || !threads) {
		fprintf(stderr, "Out of memory\n");
		free(workers);
		free(threads);
		return EXIT_FAILURE;
	}
	for (unsigned i = 0; i < jobs; i++) {
		workers[i].size = size;
		workers[i].aad = aad;
		int err = prepare(&workers[i], algorithm);
		if (err) {
			fprintf(stderr,
				"Setup/verification: %s. Check /proc/crypto "
				"and "
				"CONFIG_CRYPTO_USER_API_AEAD.\n",
				strerror(err));
			goto cleanup;
		}
	}
	printf("algorithm=%s payload=%u aad=%u workers=%u; round-trip and "
	       "bad-tag checks passed\n",
	       algorithm, size, aad, jobs);
	printf("direction operations seconds ops/s MiB/s Mbit/s mean-us/op\n");
	for (int decrypt = 0; decrypt <= 1; decrypt++) {
		int err = pthread_barrier_init(&barrier, NULL, jobs + 1);
		if (err) {
			fprintf(stderr, "barrier: %s\n", strerror(err));
			goto cleanup;
		}
		for (unsigned i = 0; i < jobs; i++) {
			workers[i].decrypt = decrypt;
			workers[i].count = 0;
			err = pthread_create(&threads[i], NULL, run,
					     &workers[i]);
			if (err) {
				/* Other threads are waiting at the barrier;
				 * exit releases them. */
				fprintf(stderr, "pthread_create: %s\n",
					strerror(err));
				exit(EXIT_FAILURE);
			}
		}
		double start = now(), end = start;
		deadline = start + seconds;
		pthread_barrier_wait(&barrier);
		uint64_t count = 0;
		for (unsigned i = 0; i < jobs; i++) {
			pthread_join(threads[i], NULL);
			count += workers[i].count;
			if (workers[i].end > end)
				end = workers[i].end;
			if (workers[i].error)
				fprintf(stderr, "worker %u: %s\n", i,
					strerror(workers[i].error));
		}
		pthread_barrier_destroy(&barrier);
		for (unsigned i = 0; i < jobs; i++)
			if (workers[i].error)
				goto cleanup;
		double elapsed = end - start, rate = (double)count / elapsed;
		printf("%s %" PRIu64 " %.3f %.0f %.3f %.3f %.3f\n",
		       decrypt ? "decrypt" : "encrypt", count, elapsed, rate,
		       rate * size / 1048576, rate * size * 8 / 1e6,
		       elapsed * jobs * 1e6 / (double)count);
	}
	status = EXIT_SUCCESS;
cleanup:
	for (unsigned i = 0; i < jobs; i++) {
		if (workers[i].handle)
			kcapi_aead_destroy(workers[i].handle);
		free(workers[i].plain);
		free(workers[i].cipher);
		free(workers[i].output);
	}
	free(workers);
	free(threads);
	return status;
}
