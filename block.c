#include <stdio.h> // printf()
#include <unistd.h> // fork()
#include <string.h> // strerror()
#include <strings.h> // strcasecmp()
#include <errno.h> // errno
#include <sys/inotify.h> // inotify_*()
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h> // waitpid()
#include <fcntl.h>
#include <stdlib.h> // exit()
#include <utmpx.h> // struct utmpx
#include <signal.h> // signal()
#include "ipv4_str.h"
void fperr(char*s)
{
	perror(s);
	exit(EXIT_FAILURE);
}
void add_to_blacklist(char *ip)
{
	pid_t pid = fork();
	if(pid == 0) /* Child process */
	{
		execl("/usr/sbin/ipset", "ipset", "add", "autoblacklist", ip, NULL);
		fperr("execl");
		exit(EXIT_FAILURE);
	}
	else if(pid == -1) /* Error */
	{
		fperr("fork");
	}
	else /* Parent, after child was successfully started */
	{
		waitpid((pid_t)-1, NULL, WNOHANG);
	}

}
uint8_t user_is_bad(FILE *fp, char *username)
{
	if(fp == NULL)
		return 0;
	fseek(fp, 0, SEEK_SET);
	char *line = NULL;
	size_t n = 0;
	ssize_t ret = 0;
	errno = 0;
	while((ret = getline(&line, &n, fp)) > 0)
	{
		size_t l = strlen(line) - 1;
		if(line[l] == '\n')
			line[l] = 0;
		if(!strcasecmp(username, line))
		{
			free(line);
			return 1;
		}
	}
	if(errno != 0)
		fperr("getline");
	free(line);
	return 0;
}
int main(int argc, char *argv[])
{
	int32_t badip = 0;
	int32_t lastblocked = 0;
	uint8_t count = 1;
	if(argc > 3 || argc < 1)
	{
		printf("Usage: %s [bad user file] [log file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	FILE *logfp;
	if(argv[2])
	{
		logfp = fopen(argv[2], "a+");
		if(logfp == NULL)
		{
			fprintf(stderr, "Error opening log file %s: ", argv[2]);
			fperr(NULL);
		}
	}
	else
	{
		logfp = stdout;
		printf("No log file specified, using stdout\n");
	}
	FILE *baduserfp = NULL;
	fprintf(logfp, "Starting up, using ");
	if(argv[1])
	{
		fprintf(logfp, "bad-user file %s\n", argv[1]);
		fflush(logfp);
		baduserfp = fopen(argv[1], "r");
		if(baduserfp == NULL)
		{
			fprintf(stderr, "Error opening bad-user file %s: ", argv[1]);
			fperr(NULL);
		}
	}
	else
	{
		fprintf(logfp, "no bad-user file.\n");
		fflush(logfp);
	}
	int infd = inotify_init1(IN_CLOEXEC);
	if(infd < 0)
		fperr("inotify_init1");
	if(inotify_add_watch(infd, "/var/log/btmp", IN_MODIFY) < 0)
		fperr("inotify_add_watch");
	int btmpfd = open("/var/log/btmp", O_RDONLY|IN_CLOEXEC);
	signal(SIGCHLD, SIG_IGN);
	while(1)
	{
		struct inotify_event i;
		if(read(infd, &i, sizeof i) < 0)
			fperr("read");
		struct utmpx ut;
		lseek(btmpfd, 0 - sizeof ut, SEEK_END);
		ssize_t r = read(btmpfd, &ut, sizeof ut);
		if(r < 0)
			fperr("read");
		if(r == 0)
			continue;
		if(ut.ut_addr_v6[1])
		{
			fprintf(logfp, "Login failed from an IPv6 address, skipping.\n");
			fflush(logfp);
			continue;
		}
		char buf[16];
		if(ut.ut_addr_v6[0] == lastblocked)
			continue;
		ipv4_str(buf, 16, ut.ut_addr_v6[0]);
		int do_block = 0;
		if(badip == ut.ut_addr_v6[0])
		{
			count++;
			if(count == 4)
				do_block = 1;
		}
		else
		{
			badip = ut.ut_addr_v6[0];
			count = 1;
		}
		fprintf(logfp, "Failed login: %s from %s", ut.ut_user, buf);
		if(ut.ut_addr_v6[0] == 0)
		{
			fprintf(logfp, " (unblockable)\n");
			do_block = 0;
			count = 0;
			continue;
		}
		if(user_is_bad(baduserfp, ut.ut_user))
		{
			do_block = 1;
			fprintf(logfp, " bad user!");
		}
		else if(count > 1)
		{
			fprintf(logfp, " (Attempts from IP: %d)", count);
		}
		if(do_block)
		{
			do_block = 0;
			count = 0;
			add_to_blacklist(buf);
			lastblocked = badip;
			badip = 0;
			fprintf(logfp, " -- BLOCKED");
		}
		fprintf(logfp, "\n");
		fflush(logfp);
	}
	close(infd);
	fclose(baduserfp);
	return 0;
}
