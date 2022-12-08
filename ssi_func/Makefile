#!/usr/bin/make

APXS=apxs
INSTALL=install


all: mod_ssi_func.o

mod_ssi_func.o: mod_ssi_func.c
	$(APXS) -c mod_ssi_func.c

install: all
	$(APXS) -c -i mod_ssi_func.c
	$(INSTALL) mod_ssi_func.h `$(APXS) -q includedir`

clean:
	-rm -rf *.o *.so *.la *.lo *.slo .libs
