/* Setup and save random seed at boot/shutdown
 *
 * Copyright (c) 2012-2025  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>		/* gettimeofday() */
#include <sys/types.h>
#include <sys/resource.h>	/* getrusage() */
#ifdef _LIBITE_LITE
# include <libite/lite.h>
#else
# include <lite/lite.h>
#endif
#include <linux/random.h>

#include "config.h"
#include "finit.h"
#include "helpers.h"
#include "plugin.h"
#include "conf.h"
#include "log.h"

#ifndef RANDOM_BYTES
#define RANDOM_BYTES (32*1024)
#endif

#ifdef RANDOMSEED
/*
 * This is the fallback seed function, please make sure you have drivers
 * enabling /dev/hwrng instead.
 */
static void fallback(FILE *fp)
{
	unsigned long seed;
	struct timeval tv;
	struct rusage ru;
	int iter = 128;

	gettimeofday(&tv, NULL);
	getrusage(RUSAGE_SELF, &ru);

	/* Mix multiple sources of "randomness" */
	seed = tv.tv_sec ^ (tv.tv_usec << 16);
	seed ^= ru.ru_utime.tv_sec ^ (ru.ru_utime.tv_usec << 16);
	seed ^= ru.ru_stime.tv_sec ^ (ru.ru_stime.tv_usec << 16);
	seed ^= getpid() << 8;

	srandom(seed);
	while (iter--) {
		uint32_t i, prng = random();

		for (i = 0; i < sizeof(prng); i++)
			fputc((prng >> (i * CHAR_BIT)) & UCHAR_MAX, fp);
	}
}
#endif

static void setup(void *arg)
{
#ifdef RANDOMSEED
	struct rand_pool_info *rpi;
	unsigned char *rpi_buf;
	ssize_t len = 0;
	struct stat st;
	int rc = -1;
	int fd, err;

	if (rescue) {
		dbg("Skipping %s plugin in rescue mode.", "urandom");
		return;
	}

	if (stat(RANDOMSEED, &st) || st.st_size < 512) {
		int ret = 1;
		mode_t prev;
		FILE *fp;

		print_desc("Bootstrapping random seed", NULL);
		prev = umask(077);
		fp = fopen(RANDOMSEED, "w");
		if (fp) {
			const char *hwrng = "/dev/hwrng";
			FILE *hw;

			hw = fopen(hwrng, "r");
			if (hw) {
				char buf[512];
				size_t num;

				num = fread(buf, sizeof(buf[0]), sizeof(buf), hw);
				if (num == 0)
					fallback(fp);
				else
					fwrite(buf, sizeof(buf[0]), num, fp);

				fclose(hw);
			} else {
				fallback(fp);
			}
			ret = fclose(fp);
		}
		print_result(ret);
		umask(prev);
	}

	print_desc("Seeding random number generator", NULL);

	/*
	 * Simply copying our saved entropy to /dev/urandom doesn't
	 * increment the kernel "entropy count", instead we must use
	 * the ioctl below.
	 */
	fd = open(RANDOMSEED, O_RDONLY);
	if (fd < 0)
		goto fallback;

	rpi = malloc(sizeof(*rpi) + RANDOM_BYTES);
	if (!rpi) {
		close(fd);
		goto fallback;
	}

	rpi_buf = (unsigned char *)rpi->buf;
	do {
		ssize_t num;

		num = read(fd, &rpi_buf[len], RANDOM_BYTES - len);
		if (num <= 0) {
			if (num == -1 && errno == EINTR)
				continue;
			if (len > 0)
				break;

			close(fd);
			free(rpi);
			goto fallback;
		}

		len += num;
	} while (len < RANDOM_BYTES);
	close(fd);

	fd = open("/dev/urandom", O_WRONLY);
	if (fd < 0) {
		free(rpi);
		goto fallback;
	}

	rpi->buf_size = len;
	rpi->entropy_count = len * 8;
	rc = ioctl(fd, RNDADDENTROPY, rpi);
	err = errno;
	close(fd);
	free(rpi);
	if (rc < 0)
		logit(LOG_WARNING, "Failed adding entropy to kernel random pool: %s", strerror(err));
	print_result(rc < 0);
	return;
fallback:
	print_result(512 > copyfile(RANDOMSEED, "/dev/urandom", 0, 0));
#endif
}

static void save(void *arg)
{
#ifdef RANDOMSEED
	mode_t prev;

	if (rescue) {
		dbg("Skipping %s plugin in rescue mode.", "urandom");
		return;
	}

	prev = umask(077);

	print_desc("Saving random seed", NULL);
	print_result(RANDOM_BYTES != copyfile("/dev/urandom", RANDOMSEED, RANDOM_BYTES, 0));

	umask(prev);
#endif
}

static plugin_t plugin = {
	.name = "urandom",
	.hook[HOOK_BASEFS_UP] = { .cb  = setup },
	.hook[HOOK_SHUTDOWN]  = { .cb  = save  },
	.depends = { "bootmisc", }
};

PLUGIN_INIT(__init)
{
	plugin_register(&plugin);
}

PLUGIN_EXIT(__exit)
{
	plugin_unregister(&plugin);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
