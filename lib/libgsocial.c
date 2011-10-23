/*
 * =====================================================================================
 *
 *       Filename:  libgsocial.c
 *
 *    Description:  Library that connects that retrieves the information
 *                  from the social networks. 
 *
 *        Version:  1.0
 *        Created:  10/22/2011 06:31:24 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Gabriel Chavez (), gabrielchavez02@gmail.com
 *        Company:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <oauth.h>
#include <glib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libgsocial.h"

const char twitter_statuses[] = "http://api.twitter.com/1/statuses";
const char request_token_uri[] = "https://api.twitter.com/oauth/request_token";
const char access_token[] = "https://api.twitter.com/oauth/access_token";
const char twitter_authorize_uri[] = "http://api.twitter.com/oauth/authorize?oauth_token=";
const char twitter_dm_uri[] = "http://api.twitter.com/1/direct_messages.xml";
const char twitter_dm_new_uri[] = "http://api.twitter.com/1/direct_messages/new.xml";

static char *consumer_key = NULL;
static char *consumer_secret = NULL;
static char *access_key = NULL;
static char *access_secret = NULL;
// Temporal keys
char *req_key = NULL;
char *req_secret = NULL;
Session *request;
GList *tweet_list;

static gchar *last_tw_id = "0";
static gchar *last_dm_id = "0";

static void gsocial_request_free(Session *request)
{
    if(!request)
        return;
    free(request);
}

void gsocial_init()
{
    request = calloc(1, sizeof(Session));
}

void gsocial_set_consumer_keys(char *consumer, char *secret)
{
    consumer_key = consumer;
    consumer_secret = secret;
}

void gsocial_set_access_keys(char *key, char *secret)
{
    access_key = key;
    access_secret = secret;
}



int gsocial_parse_reply_access(char *reply, char **token, char **secret)
{
    int retval = 1;
    int rc;  /* Number of url parameters */
    char **rv = NULL; /* url parameters */
    rc = oauth_split_url_parameters(reply, &rv);
    qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
    if (rc == 2 || rc == 4) {
        if (!strncmp(rv[0], "oauth_token=", 11) &&
                !strncmp(rv[1], "oauth_token_secret=", 18)) {
            if (token)
                *token = strdup(&(rv[0][12]));
            if (secret)
                *secret = strdup(&(rv[1][19]));

            retval = 0;
        }
    } else if (rc == 3)
        if(!strncmp(rv[1], "oauth_token=", 11) &&
                !strncmp(rv[2], "oauth_token_secret=", 18)) {
            if(token)
                *token = strdup(&rv[1][12]);
            if(secret)
                *secret = strdup(&rv[2][19]);
            retval = 0;
        }
    if(rv)
        free(rv);

    return retval;
}

char *gsocial_get_twitter_authorize_url()
{
    char *req_url;
    char *reply;
    char *twitter_auth_url;

    req_url = oauth_sign_url2(request_token_uri, NULL, OA_HMAC, NULL,
            consumer_key, consumer_secret, NULL, NULL);
    //printf("%s\n", req_url);

    reply = oauth_http_get(req_url, NULL);
    //printf("%s\n", reply);
    if(gsocial_parse_reply_access(reply, &req_key, &req_secret))
        printf("Something is wrong!\n");

    free(reply);

    //fprintf(stdout, "%s%s\nPIN: ", twitter_authorize_uri, req_key);

    twitter_auth_url = g_strconcat(twitter_authorize_uri, req_key, NULL);
    //g_print(twitter_auth_url);

    return twitter_auth_url;
}


char *gsocial_get_access_key_full_reply(char *pin)
{
    char *req_url;
    char ath_uri[90];
    char *new_reply;


    sprintf(ath_uri, "%s?oauth_verifier=%s", access_token, pin);

    req_url = oauth_sign_url2(ath_uri, NULL, OA_HMAC, NULL, consumer_key,
            consumer_secret, req_key, req_secret);

    new_reply = oauth_http_get(req_url, NULL);

    free(req_key);
    free(req_secret);

    return new_reply;
}




static GSLTweet *gsocial_parse_statuses(Session *session,
        xmlDocPtr doc, xmlNodePtr current, enum action ACTION)
{
    xmlChar *text = NULL;
    xmlChar *screen_name = NULL;
    xmlChar *name = NULL;
    xmlChar *created_at = NULL;
    xmlChar *id = NULL;
    xmlNodePtr userinfo;
    GSLTweet *tweet = g_slice_new(GSLTweet);
    tweet->text = NULL;
    tweet->name = NULL;
    tweet->screen_name = NULL;
    tweet->id = NULL;
    tweet->created_at = NULL;
    const xmlChar *author = NULL;
    
    if(ACTION == ACTION_HOME_TIMELINE)
            author = (const xmlChar *) "user"; 
    else if (ACTION == ACTION_MESSAGES)
            author = (const xmlChar *)"sender";
    

    current = current->xmlChildrenNode;
    while (current != NULL) {
        if (current->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(current->name, (const xmlChar *)"created_at")) {
                created_at = xmlNodeListGetString(doc, current->xmlChildrenNode, 1);
            }
            if (!xmlStrcmp(current->name, (const xmlChar *)"text")) {
                text = xmlNodeListGetString(doc, current->xmlChildrenNode, 1);
            }
            if (!xmlStrcmp(current->name, (const xmlChar *)"id")) {
                id = xmlNodeListGetString(doc, current->xmlChildrenNode, 1);
               if(ACTION == ACTION_HOME_TIMELINE) {
                    if(atoi(last_tw_id) < atoi((gchar *) id))
                        last_tw_id = (gchar *) id;

                }
                else if(ACTION == ACTION_MESSAGES) {
                        if(atoi(last_dm_id) < atoi((gchar *) id))
                            last_dm_id = (gchar *) id;

                }

            }
            if (!xmlStrcmp(current->name, author)) {
                userinfo = current->xmlChildrenNode;
                while (userinfo != NULL) {
                    if ((!xmlStrcmp(userinfo->name, (const xmlChar *)"screen_name"))) {
                        if (screen_name)
                            xmlFree(screen_name);
                        screen_name = xmlNodeListGetString(doc, userinfo->xmlChildrenNode, 1);
                    }
                    if ((!xmlStrcmp(userinfo->name, (const xmlChar *)"name"))) {
                        if (name)
                            xmlFree(name);
                        name = xmlNodeListGetString(doc, userinfo->xmlChildrenNode, 1);
                    }
                    userinfo = userinfo->next;
                }
            }

            if (screen_name && text && created_at && id && name) {
                tweet->name = (gchar *)name;
                tweet->screen_name = (gchar *)screen_name;
                tweet->text = (gchar *)text;
                tweet->created_at = (gchar *)created_at;
                tweet->id = (gchar *)id;

            }
        }
        current = current->next;
    }

    return tweet;
}

static void gsocial_parse(char *document, Session *session, enum action ACTION)
{
    xmlDocPtr doc;
    xmlNodePtr current;
    tweet_list = NULL;
    GSLTweet *tweet = g_slice_new(GSLTweet);
    tweet->text = NULL;
    const xmlChar *doc_type = NULL;
    const xmlChar *text_type = NULL;


    doc = xmlReadMemory(document, strlen(document), "timeline.xml",
            NULL, XML_PARSE_NOERROR);
    if (doc == NULL)
        return;

    current = xmlDocGetRootElement(doc);
    if (current == NULL) {
        fprintf(stderr, "empty document\n");
        xmlFreeDoc(doc);
        return;
    }


    if(ACTION == ACTION_HOME_TIMELINE) {
        doc_type = (const xmlChar *)"statuses";
        text_type = (const xmlChar *)"status";

    }
    else if(ACTION == ACTION_MESSAGES) {
        doc_type = (const xmlChar *)"direct-messages";
        text_type = (const xmlChar *)"direct_message";

    }

    if (xmlStrcmp(current->name, doc_type)){
        fprintf(stdout, "%s\n", current->name);
        fprintf(stderr, "unexpected document type\n");
        xmlFreeDoc(doc);
        return;
    }


    current = current->xmlChildrenNode;
    while (current != NULL) {
        if (!xmlStrcmp(current->name, text_type)) {
            tweet_list = g_list_append(tweet_list, 
                    (gpointer*)gsocial_parse_statuses(session, doc, current, ACTION));
            tweet = (GSLTweet *)g_list_nth_data(tweet_list, 0); 
        }
        current = current->next;
    }



    xmlFreeDoc(doc);

    return;
}


static void gsocial_send_request(Session *request)
{
    request->exit_code = 0;
    char *escaped_tweet = NULL;
    int is_post = 0;
    char endpoint[500];
    char *req_url;
    char *reply;
    char *postarg = NULL;
    switch(request->action) {
        case ACTION_HOME_TIMELINE:
            if(request->since_id != NULL) {
                sprintf(endpoint, "%s%s?%s%s", twitter_statuses, "/home_timeline.xml", 
                        "since_id=", request->since_id);
            }
            else {
                sprintf(endpoint, "%s%s", twitter_statuses, "/home_timeline.xml");
            }
            break;
        case ACTION_UPDATE:
            escaped_tweet = oauth_url_escape(request->tweet);
            sprintf(endpoint, "%s%s?status=%s","http://api.twitter.com/1/statuses",
                    "/update.xml", escaped_tweet);
            is_post = 1;
            break;
        case ACTION_MESSAGES:
            if(request->since_id != NULL) {
                sprintf(endpoint, "%s?%s%s", twitter_dm_uri, "since_id=", request->since_id);
            }
            else {
                sprintf(endpoint, "%s", twitter_dm_uri);
            }
            break;
        case ACTION_NEW_MESSAGE:
            escaped_tweet = oauth_url_escape(request->tweet);
            sprintf(endpoint, "%s?screen_name=%s&text=%s", twitter_dm_new_uri,
                    request->recp, escaped_tweet);
            is_post = 1;
            break;

    }
    if(is_post){
        req_url = oauth_sign_url2(endpoint, &postarg, 
                OA_HMAC, NULL, consumer_key, consumer_secret, access_key, access_secret);

        reply = oauth_http_post(req_url, postarg);

    } else{
        req_url = oauth_sign_url2(endpoint, NULL, OA_HMAC, NULL,
                consumer_key, consumer_secret, access_key, access_secret);

        reply = oauth_http_get(req_url, postarg);
    }


    if (request->action != ACTION_UPDATE || request->action != ACTION_NEW_MESSAGE)
        gsocial_parse(reply, request, request->action);

    if(reply)
        request->exit_code = 1;

    free(postarg);
    free(req_url);
    free(reply);
}


GList *gsocial_get_home_timeline(char *since_id)
{
    request->action = ACTION_HOME_TIMELINE;
    request->since_id = since_id;
    gsocial_send_request(request);
    return tweet_list;

}

int gsocial_send_tweet(char *tweet)
{   
    request->tweet = tweet;
    request->action = ACTION_UPDATE;
    gsocial_send_request(request);
    return request->exit_code;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  gsocial_get_direct_messages
 *  Description:  This functions retrieves the direct messages from the user
 * =====================================================================================
 */
GList *gsocial_get_direct_messages(char *since_id)
{
    request->action = ACTION_MESSAGES;
    request->since_id = since_id;
    gsocial_send_request(request);
    return tweet_list;

}

int gsocial_send_message(gchar *user_name, gchar *message)
{
    request->action = ACTION_NEW_MESSAGE;
    request->tweet = message;
    request->recp = user_name;
    gsocial_send_request(request);
    return request->exit_code;

}

gchar *gsocial_get_tw_last_id()
{
    return last_tw_id;
}

gchar *gsocial_get_dm_last_id()
{
    return last_dm_id;
}

