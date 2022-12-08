#!/usr/bin/make

APXS=apxs


all: mod_ssi_func_math.o

mod_ssi_func_math.o: mod_ssi_func_math.c
	$(APXS) -c mod_ssi_func_math.c

install: all
	$(APXS) -c -i mod_ssi_func_math.c

clean:
	-rm -rf *.o *.so *.la *.lo *.slo .libs
