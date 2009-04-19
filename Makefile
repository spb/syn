PREFIX ?= /home/users/stephen/bins/atheme
ATHEME ?= ../atheme

ATHEME_CFLAGS = -I$(ATHEME)/include -I$(ATHEME)/libmowgli/src/libmowgli -DDATADIR=\"$(PREFIX)/etc\"

SOURCES = $(wildcard *.c)
MODULES = $(patsubst %.c,%.so,$(SOURCES))

default: $(MODULES)

clean:
	rm -f $(MODULES)

%.so: %.c
	gcc -O1 -ggdb3 -fPIC $(ATHEME_CFLAGS) -shared -o$@ $<

.PHONY: install

install: $(MODULES)
	install -d $(PREFIX)/modules/syn
	install -t $(PREFIX)/modules/syn $(MODULES)




