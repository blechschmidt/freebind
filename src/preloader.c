#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#define LIB_NAME "freebind.so"
#define LIB_PATH "/usr/local/lib"

static int help(char *name)
{
	fprintf(stderr, "Usage: %s program [arguments]\n", name);
	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	char buf[8192];
	int first_arg = 1;
	char *orig_env = getenv("LD_PRELOAD");

	if(argc < 2)
	{
		return help(argv[0]);
	}

	buf[0] = 0;
	for(int i = 1; i < argc; i++)
	{
		if(argv[i][0] != '-')
		{
			first_arg = i;
			break;
		}
		else if((strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--random") == 0) && argv[++i] != NULL)
		{
			size_t buflen = strlen(buf);
			snprintf(buf + buflen, sizeof(buf) - buflen, "%s ", argv[i]);
		}
	}
	setenv("FREEBIND_RANDOM", buf, 1);

	snprintf(buf, sizeof(buf), LIB_PATH "/" LIB_NAME "%s%s",
			orig_env ? " " : "",
			orig_env ? orig_env : "");
	setenv("LD_PRELOAD", buf, 1);

	execvp(argv[first_arg], &argv[first_arg]);
	snprintf(buf, sizeof(buf), "Failed to open program \"%s\"", argv[1]);
	perror(buf);
	return help(argv[0]);
}
