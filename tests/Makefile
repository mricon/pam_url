
CFLAGS	+= -g3 -O0 -pthread
LDFLAGS	+= -lpam -lpam_misc -pthread

OBJS	:=	test_auth test_acct test_sess test_chauthtok

all: ${OBJS}

clean:
	rm -f ${OBJS} ${OBJS:%=%.o}
