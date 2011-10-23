LIBGSOCIAL = libgsocial.c

CFLAGS=`xml2-config --cflags`  `pkg-config --cflags glib-2.0`


all: libgsocial

libgsocial: $(LIBGSOCIAL)
	gcc -Wall -c $^ $(CFLAGS)  -o $@.o $(LIBS)

.PHONY:

clean: 
	-rm *.o
