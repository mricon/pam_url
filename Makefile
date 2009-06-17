# pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

CFLAGS		+= -fPIC

LDFLAGS		:= -shared -lpam -lcurl

arch		:= $(shell uname -m)
pamlib		:= lib/security

obj			:= pam_url.so
objc		:= ${shell ls pam_url*.c}
objo		:= ${objc:%.c=%.o}

# If platform is AMD/Intel 64bit
ifeq (${arch},x86_64)
pamlib := lib64/security
endif

all: ${obj}

debug:
	CFLAGS="-g3 -O0 -DDEBUG=1" ${MAKE} all

${obj}: ${objo}
	${CC} ${LDFLAGS} -o ${obj} ${objo}

clean:
	rm -f ${obj} ${objo}

install:
	install -D -m 755 ${obj} ${DESTDIR}/${pamlib}/${obj}

uninstall:
	rm -f ${DESTDIR}/${pamlib}/${obj}
