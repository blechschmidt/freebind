#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#define LIB_NAME "freebind.so"

static int help(char *name)
{
	fprintf(stderr, "Usage: %s program [arguments]\n", name);
	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	char buf[8192];
	if(argc < 2)
	{
		return help(argv[0]);
	}
	putenv("LD_PRELOAD=/usr/local/lib/" LIB_NAME);
	execvp(argv[1], &argv[1]);
	snprintf(buf, sizeof(buf), "Failed to open program \"%s\"", argv[1]);
	perror(buf);
	return help(argv[0]);
}
