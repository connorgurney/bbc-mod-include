#!/usr/bin/make

APXS=apxs


all: mod_ssi_setsplitvars.o

mod_ssi_setsplitvars.o: mod_ssi_setsplitvars.c
	$(APXS) -c mod_ssi_setsplitvars.c

install: all
	$(APXS) -c -i mod_ssi_setsplitvars.c

clean:
	-rm -rf *.o *.so *.la *.lo *.slo .libs
