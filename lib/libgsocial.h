#ifndef LIBGSOCIAL_H_INCLUDED
#define LIBGSOCIAL_H_INCLUDED
#include <glib.h>
enum action {
    ACTION_HOME_TIMELINE,
    ACTION_UPDATE,
    ACTION_MESSAGES,
    ACTION_NEW_MESSAGE
};

typedef struct
{
    char *tweet;
    char *since_id;
    char *max_id;
    char *recp; 
    int exit_code;
    enum action action;
} Session;

typedef struct
{
    gchar *text;
    gchar *name;
    gchar *screen_name;
    gchar *created_at;
    gchar *id;

} GSLTweet;

void gsocial_init(void);

char *gsocial_get_twitter_authorize_url(void);

char *gsocial_get_access_key_full_reply(char *);

void gsocial_set_consumer_keys(char *, char *);

void gsocial_set_access_keys(char *, char *);

void gsocial_request_token(void);

int gsocial_parse_reply_access(char *, char **, char**);

int gsocial_send_tweet(char *);

GList *gsocial_get_home_timeline(char *since_id);

GList *gsocial_get_direct_messages(char *since_id);

gchar *gsocial_get_dm_last_id(void);

gchar *gsocial_get_tw_last_id(void);

int gsocial_send_message(gchar *, gchar *);

#endif /* LIBGSOCIAL_H_INCLUDED */
