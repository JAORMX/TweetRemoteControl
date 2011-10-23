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
#include <glib.h>
#include "libgsocial.h"

#define TS_BUF_SIZE sizeof("YYYY-MM-DD HH:MM:SS")       /* Includes '\0' */
#define SBUF_SIZE 100
#define zalloc(size) calloc(size, 1)

/*
 * The application keys, they are unique to this app that's why they are
 * hardcoded.
 */
char consu_key[] = "VdtED3ZdOjcBlPbc5OpGlw";
char consu_secret[] = "8PF3On5ATUlplxtJCC4xzFwVGjLkFTuQjQYSoNCUc";
char *key = NULL;
char *secret = NULL;
gchar *last_id = NULL;

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

static char *get_string_from_stdin(void)
{
    char *temp;
    char *string;

    string = zalloc(1000);
    if (!string)
        return NULL;

    if (!fgets(string, 999, stdin)) {
        free(string);
        return NULL;
    }

    temp = strchr(string, '\n');
    if (temp)
        *temp = '\0';

    return string;
}

static void read_keys(char **key, char **secret)
{
    gchar *filename, *content;
    gchar *path;
    gsize bytes;

    GError *error = NULL;

    filename = g_build_filename (g_get_current_dir(), "keys", NULL);

    content = NULL;

    if(!g_file_test (filename, G_FILE_TEST_EXISTS)) {
        fprintf(stdout,
                "Please open the following link in your browser, and "
                "allow 'tweetd' to access your account. Then paste "
                "back the provided PIN in here.\n");

        gchar *url = gsocial_get_twitter_authorize_url();
        printf ( "%s\n", url );
        fprintf(stdout, "PIN: ");
        char *pin= get_string_from_stdin();
        content = gsocial_get_access_key_full_reply(pin);
        if(content)
            g_file_set_contents(filename, content, strlen(content), &error);
        else {
            g_error("PIN not entered");
        }

    }

    g_file_get_contents(filename, &content, &bytes, &error);

    if(gsocial_parse_reply_access(content, key, secret))
        g_error("Error: Can't read file");

    g_free(content);
    g_free(filename);

}

gchar *get_last_message()
{
    gchar *last_msg = NULL;
    GList *messages = gsocial_get_direct_messages(last_id);
    GSLTweet *tweet;
    int i;
    for(i = 0; i<g_list_length(messages); i++){
        tweet = (GSLTweet *) g_list_nth_data(messages, i);
        if(i==0){
            last_id = tweet->id;
            last_msg = tweet->text;
        }
    }
    return last_msg;
}

int main(int argc, char *argv[])
{
    const int SLEEP_TIME = 60;      /* Time to sleep between messages */
    int count = 0;                  /* Number of completed SLEEP_TIME intervals */
    int unslept;                    /* Time remaining in sleep interval */
    struct sigaction sa;

    /* We begin using the libgsocial library */
    gsocial_init();
    gsocial_set_consumer_keys(consu_key, consu_secret);
    read_keys(&key, &secret);
    gsocial_set_access_keys(key, secret);
            
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
            char* last_msg = get_last_message();
            if(last_msg != NULL)
                log_message("Last message: %s\n", last_msg);
            unslept = SLEEP_TIME;       /* Reset interval */
        }
    }
}
