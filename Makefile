# pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

libs		+= libcurl libconfig

CFLAGS		+= -fPIC -pthread -D_GNU_SOURCE $(shell pkg-config --cflags ${libs})

LDFLAGS		+= -shared -lpam -pthread $(shell pkg-config --libs ${libs})

arch		:= $(shell uname -m)
pamlib		:= lib/security

obj			:= pam_url.so
objc		:= ${shell ls pam_url*.c}
objo		:= ${objc:%.c=%.o}

# If platform is AMD/Intel 64bit
ifeq (${arch},x86_64)
pamlib := lib64/security
endif
ifeq (${arch},ppc64)
pamlib := lib64/security
endif

all: ${obj}

debug:
	CFLAGS="-g3 -O0" ${MAKE} all

${obj}: ${objo}
	${CC} ${objo} ${LDFLAGS} -o ${obj}

clean:
	rm -f ${obj} ${objo}

install:
	install -D -m 755 ${obj} ${DESTDIR}/${pamlib}/${obj}
	install -D -m 644 examples/pam_url.conf ${DESTDIR}/etc/pam_url.conf

uninstall:
	rm -f ${DESTDIR}/${pamlib}/${obj}
