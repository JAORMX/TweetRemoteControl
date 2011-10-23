LIBGSOCIAL = ../lib/libgsocial.o

CFLAGS = -I../lib/  `pkg-config --cflags glib-2.0`

LIBS=`xml2-config --libs` `pkg-config --libs glib-2.0` -loauth

all: tweetd
	gcc $(LIBGSOCIAL) tweetd.o -o tweetd $(LIBS)

tweetd: tweetd.c 
	gcc -c $<  $(CFLAGS) -o $@.o

.PHONY:
clean:
	-rm *.o tweetd




