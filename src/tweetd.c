#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define TS_BUF_SIZE sizeof("YYYY-MM-DD HH:MM:SS")       /* Includes '\0' */
#define SBUF_SIZE 100

int tweetd_daemonize(void);

/*
 * FIXME: This should be customizable.
 */
static const char * LOG_FILE = "/var/log/tweetd.log";
static const char * CONFIG_FILE = "/tmp/tweetd.conf";

static FILE *logfp;

static volatile sig_atomic_t hupReceived = 0;

static void log_message(const char *format, ...)
{
	va_list argList;
	const char *TIMESTAMP_FMT = "%F %X";        /* = YYYY-MM-DD HH:MM:SS */
	char timestamp[TS_BUF_SIZE];
	time_t t;
	struct tm *loc;

	t = time(NULL);
	loc = localtime(&t);
	if (loc == NULL ||
			strftime(timestamp, TS_BUF_SIZE, TIMESTAMP_FMT, loc) == 0)
		fprintf(logfp, "???Unknown time????: ");
	else
		fprintf(logfp, "%s: ", timestamp);

	va_start(argList, format);
	vfprintf(logfp, format, argList);
	fprintf(logfp, "\n");
	va_end(argList);
}

/* Open the log file 'logFilename' */

static void tweetd_log_open(const char *logFilename)
{
	mode_t m;

	m = umask(077);
	logfp = fopen(logFilename, "a");
	umask(m);

	/* If opening the log fails we can't display a message... */

	if (logfp == NULL)
		exit(EXIT_FAILURE);

	setbuf(logfp, NULL);                    /* Disable stdio buffering */

	log_message("Opened log file");
}

/* Close the log file */

static void tweetd_log_close(void)
{
	log_message("Closing log file");
	fclose(logfp);
}

/* (Re)initialize from configuration file. In a real application
   we would of course have some daemon initialization parameters in
   this file. In this dummy version, we simply read a single line
   from the file and write it to the log. */

static void tweetd_read_config_file(const char *configFilename)
{
	FILE *configfp;
	char str[SBUF_SIZE];

	configfp = fopen(configFilename, "r");
	if (configfp != NULL) {                 /* Ignore nonexistent file */
		if (fgets(str, SBUF_SIZE, configfp) == NULL)
			str[0] = '\0';
		else
			str[strlen(str) - 1] = '\0';    /* Strip trailing '\n' */
		log_message("Read config file: %s", str);
		fclose(configfp);
	}
}

/* Set nonzero on receipt of SIGHUP */
static void tweetd_sigup_handler(int sig)
{
	hupReceived = 1;
}


int tweetd_daemonize()
{
	int maxfd, fd;
	uid_t uid, euid;

	uid = getuid();
	euid = geteuid();

	if (uid != euid || uid != 0) {
		printf("ERROR: You have to be logged in as root\n");
		exit(EXIT_SUCCESS);
	}

	switch (fork()) {                   /* Become background process */
		case -1: return -1;
		case 0:  break;                     /* Child falls through... */
		default: _exit(EXIT_SUCCESS);       /* while parent terminates */
	}

	if (setsid() == -1)                 /* Become leader of new session */
		return -1;

	switch (fork()) {                   /* Ensure we are not session leader */
		case -1: return -1;
		case 0:  break;
		default: _exit(EXIT_SUCCESS);
	}

	umask(0);                       /* Clear file mode creation mask */

	if (chdir("/") < 0)
		exit(EXIT_FAILURE);

	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd == -1)                /* Limit is indeterminate... */
		maxfd = 8192;       /* so take a guess */

	for (fd = 0; fd < maxfd; fd++)
		close(fd);

	close(STDIN_FILENO);            /* Reopen standard fd's to /dev/null */

	fd = open("/dev/null", O_RDWR);

	if (fd != STDIN_FILENO)         /* 'fd' should be 0 */
		return -1;
	if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
		return -1;
	if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	const int SLEEP_TIME = 15;      /* Time to sleep between messages */
	int count = 0;                  /* Number of completed SLEEP_TIME intervals */
	int unslept;                    /* Time remaining in sleep interval */
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = tweetd_sigup_handler;

	if (sigaction(SIGHUP, &sa, NULL) == -1)
		perror("sigaction");

	if (tweetd_daemonize() == -1)
		_exit(EXIT_FAILURE);

	tweetd_log_open(LOG_FILE);
	tweetd_read_config_file(CONFIG_FILE);

	unslept = SLEEP_TIME;

	/*
	 * Main Loop.
	 */
	while (1) {
		unslept = sleep(unslept);       /* Returns > 0 if interrupted */

		if (hupReceived) {              /* If we got SIGHUP... */
			hupReceived = 0;            /* Get ready for next SIGHUP */
			tweetd_log_close();
			tweetd_log_open(LOG_FILE);
			tweetd_read_config_file(CONFIG_FILE);
		}

		if (unslept == 0) {             /* On completed interval */
			count++;
			log_message("Main: %d", count);
			unslept = SLEEP_TIME;       /* Reset interval */
		}
	}
}
