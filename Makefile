# pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

CFLAGS		+= -fPIC -Wall
 
ifdef DEBUG
CFLAGS      += -O0 -ggdb -DDEBUG=1
else
CFLAGS      += -O2
endif

LDFLAGS		+= -shared -lpam -lcurl

arch		:= $(shell uname -m)

obj			:= pam_url.so
objc		:= ${shell ls pam_url*.c}
objo		:= ${objc:%.c=%.o}

ifeq (${arch},x86_64)
pamlib := lib64/security
CFLAGS += -m64
else
pamlib := lib/security
endif


all: ${obj}

debug:
	${MAKE} DEBUG=1 all

${obj}: ${objo}
	${CC} ${LDFLAGS} -o ${obj} ${objo}

clean:
	${MAKE} -C tests clean
	rm -f ${obj} ${objo}

install:
	install -D -m 755 ${obj} ${DESTDIR}/${pamlib}/${obj}

uninstall:
	rm -f ${DESTDIR}/${pamlib}/${obj}

test:
	${MAKE} -C tests all

