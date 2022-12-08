#!/usr/bin/make

APXS=apxs


all: mod_ssi_func_rnd.o

mod_ssi_func_rnd.o: mod_ssi_func_rnd.c
	$(APXS) -c mod_ssi_func_rnd.c

install: all
	$(APXS) -c -i mod_ssi_func_rnd.c

clean:
	-rm -rf *.o *.so *.la *.lo *.slo .libs
