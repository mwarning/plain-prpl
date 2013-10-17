
SRCS = plainprpl.c scripts.c extra.c

plainprpl:
	gcc `pkg-config --cflags --libs glib-2.0 purple` -fPIC ${SRCS} -o libplainprpl.so -shared

install:
	cp libplainprpl.so /usr/lib/purple-2/
	cp -rf pixmaps/protocols/* /usr/share/pixmaps/pidgin/protocols/

clean:
	rm -f *.so
