#!/usr/bin/make

APXS=apxs


all: mod_ssi_func_flastmod.o

mod_ssi_func_flastmod.o: mod_ssi_func_flastmod.c
	$(APXS) -c mod_ssi_func_flastmod.c

install: all
	$(APXS) -c -i mod_ssi_func_flastmod.c

clean:
	-rm -rf *.o *.so *.la *.lo *.slo .libs
