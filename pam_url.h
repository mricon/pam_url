// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#ifndef PAM_URL_H_
#define PAM_URL_H_


#ifndef NAME
	#define NAME "pam_url"
#endif

#ifndef VERS
	#define VERS "0.3.3"
#endif

#ifndef USER_AGENT
	#define USER_AGENT NAME "/" VERS
#endif

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define PAM_SM_AUTH 1
#define PAM_SM_ACCOUNT 2
#define PAM_SM_SESSION 3
#define PAM_SM_PASSWORD 4

#ifndef _SECURITY_PAM_MODULES_H
	#error PAM headers not found on this system. Giving up.
#endif

#include <curl/curl.h>
#ifndef __CURL_CURL_H
	#error libcurl headers not found on this system. Giving up.
#endif

#include <libconfig.h>
#ifndef __libconfig_h
	#error libconfig headers not found on this system. Giving up.
#endif

#ifndef __USE_XOPEN_EXTENDED
# define __USE_XOPEN_EXTENDED
#endif
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>

#ifndef DEF_URL
	#define DEF_URL "https://www.example.org/"
#endif

#ifndef DEF_RETURNCODE
	#define DEF_RETURNCODE "OK"
#endif

#ifndef DEF_USER
	#define DEF_USER "user"
#endif

#ifndef DEF_PASSWD
	#define DEF_PASSWD "passwd"
#endif

#ifndef DEF_EXTRA
	#define DEF_EXTRA "&do=pam_url"
#endif

#ifndef DEF_CA_CERT
	#define DEF_CA_CERT "/etc/pki/tls/certs/ca-bundle.crt"
#endif

#ifndef DEF_SSLKEY
	#define DEF_SSLKEY "/etc/pki/pam_url_key.pem"
#endif

#ifndef DEF_SSLCERT
    #define DEF_SSLCERT "/etc/pki/pam_url_cert.pem"
#endif

#ifndef DEF_PROMPT
    #define DEF_PROMPT "Password: "
#endif

bool pam_url_debug;

typedef struct pam_url_opts_ {
	const char *url;
	const char *ret_code;
	const char *user_field;
	const char *passwd_field;
	char *extra_field;
	const char *mode;
	char *configfile;
	const char *ssl_cert;
	const char *ssl_key;
	const char *ca_cert;
	int use_first_pass;
	int prepend_first_pass;
	char *first_pass;

	int ssl_verify_peer;
	int ssl_verify_host;

	const void *user;
	const void *passwd;
} pam_url_opts;

void debug(pam_handle_t* pamh, const char *msg);
int get_password(pam_handle_t* pamh, pam_url_opts* opts);
int parse_opts(pam_url_opts* opts, int argc, const char** argv, int mode);
int fetch_url(pam_handle_t *pamh, pam_url_opts opts);
int check_rc(pam_url_opts opts);
void cleanup(pam_url_opts* opts);

#endif /* PAM_URL_H_ */
