
CFLAGS	+= -ggdb -O0 -DDEBUG=1
LDFLAGS	+= -lpam -lpam_misc

OBJS	:=	test_auth test_acct test_sess test_chauthtok

all: ${OBJS}

clean:
	rm -f ${OBJS} ${OBJS:%=%.o}
