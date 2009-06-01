CFLAGS		+= -fPIC -Wall
 
ifdef DEBUG
CFLAGS      += -O0 -ggdb -DDEBUG=1
else
CFLAGS      += -O2
endif

LDFLAGS		+= -shared -lpam -lcurl

arch		:= $(shell uname -m)

obj			:= pam_url.so
objc		:= ${obj:%.so=%.c}
objo		:= ${obj:%.so=%.o}

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
	rm -f ${obj} ${objo}

install:
	install -D -m 755 ${obj} ${DESTDIR}/${pamlib}/${obj}

uninstall:
	rm -f ${DESTDIR}/${pamlib}/${obj}

