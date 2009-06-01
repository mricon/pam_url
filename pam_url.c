/*
 * pam_url - authenticate against webservers
 *
 * This software is opensource software licensed under the GNU Public License version 2.
 * The author of this software is Sascha Thomas Spreitzer <sspreitzer (at) fedoraproject.org>.
 * Please take a look in the COPYING, INSTALL and README files.
 *
 * USE THIS SOFTWARE WITH ABSOLUTELY NO GUARANTEE AND WARRANTY
 *
 *
 * /etc/pam.d/sshd or /etc/pam.d/system-auth:
 *
 * [...]
 * auth sufficient pam_url.so https://www.example.org/ secret user passwd &do=login
 * auth sufficient pam_url.so URL                      PSK    USER PASSWD EXTRA
 * [...]
 * This module takes 4 arguments:
 * - URL = HTTPS URL
 * - PSK = Pre Shared Key
 * - USER = The name of the user variable
 * - PASSWD = The name of the password variable
 * - EXTRA = additional url encoded data
 *
 * auth sufficient pam_url.so https://www.example.org/ secret user passwd &do=auth
 * This line forms the following url encoded POST data:
 * user=<username>&passwd=<pass>&mode=<PAM_AUTH|PAM_ACCT|PAM_SESS|PAM_PASS>&PSK=secret&do=auth
 * It should return either 200 OK with PSK in the body or 403 Forbidden if unsuccessful.
 */

#ifndef NAME
	#define NAME "pam_url"
#endif

#ifndef VERS
	#define VERS "0.0"
#endif

#ifndef USER_AGENT
	#define USER_AGENT NAME "/" VERS
#endif

#define PAM_SM_AUTH 1
#define PAM_SM_ACCOUNT 2
#define PAM_SM_SESSION 3
#define PAM_SM_PASSWORD 4

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#ifndef _SECURITY_PAM_MODULES_H
	#error PAM headers not found on this system. Giving up.
#endif

#include <curl/curl.h>
#ifndef __CURL_CURL_H
	#error libcurl headers not found on this system. Giving up.
#endif

#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#ifndef DEF_URL
	#define DEF_URL "https://www.example.org/"
#endif

#ifndef DEF_PSK
	#define DEF_PSK "presharedsecret"
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

typedef struct pam_url_opts_ {
	char* url;
	char* PSK;
	char* userfield;
	char* passwdfield;
	char* extrafield;
	char* mode;

	const void* user;
	const void* passwd;
} pam_url_opts;

char* recvbuf = NULL;
size_t recvbuf_size = 0;

void notice(pam_handle_t* pamh, const char *msg)
{
	pam_syslog(pamh, LOG_NOTICE, "%s", msg);
}

void debug(pam_handle_t* pamh, const char *msg)
{
#ifdef DEBUG
	pam_syslog(pamh, LOG_ERR, "%s", msg);
#endif
}

int get_password(pam_handle_t* pamh, pam_url_opts* opts)
{
	char* p = NULL;
	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &p, "%s", "Password: ");

	if( NULL != p )
	{
		opts->passwd = p;
		return PAM_SUCCESS;
	}
	else
	{
		return PAM_AUTH_ERR;
	}
}

int parse_opts(pam_url_opts* opts, int argc, const char** argv, int mode)
{
	opts->url = calloc(1, strlen(DEF_URL) + 1);
	strcpy(opts->url, DEF_URL);

	opts->PSK = calloc(1, strlen(DEF_PSK) + 1);
	strcpy(opts->PSK, DEF_PSK);

	opts->userfield = calloc(1, strlen(DEF_USER) + 1);
	strcpy(opts->userfield, DEF_USER);

	opts->passwdfield = calloc(1, strlen(DEF_PASSWD) + 1);
	strcpy(opts->passwdfield, DEF_PASSWD);

	opts->extrafield = calloc(1, strlen(DEF_EXTRA) + 1);
	strcpy(opts->extrafield, DEF_EXTRA);

	if( 0 == argc )
	{
		return PAM_SUCCESS;
	}

	if( argc >= 1 )
	{
		opts->url = calloc(1, strlen(argv[0]) + 1);
		strcpy(opts->url, argv[0]);
	}

	if( argc >= 2 )
	{
		opts->PSK = calloc(1, strlen(argv[1]) +1);
		strcpy(opts->PSK, argv[1]);
	}

	if( argc >= 3 )
	{
		opts->userfield = calloc(1, strlen(argv[2]) + 1);
		strcpy(opts->userfield, argv[2]);
	}

	if( argc >= 4 )
	{
		opts->passwdfield = calloc(1, strlen(argv[3]) + 1);
		strcpy(opts->passwdfield, argv[3]);
	}

	if( argc >= 5 )
	{
		opts->extrafield = calloc(1, strlen(argv[4]) + 1);
		strcpy(opts->extrafield, argv[4]);
	}

	switch(mode)
	{
		case PAM_SM_ACCOUNT:
			opts->mode = calloc(1, strlen("PAM_SM_ACCOUNT") + 1);
			strcpy(opts->mode, "PAM_SM_ACCOUNT");
			break;

		case PAM_SM_SESSION:
			opts->mode = calloc(1, strlen("PAM_SM_SESSION") + 1);
			strcpy(opts->mode, "PAM_SM_SESSION");
			break;

		case PAM_SM_PASSWORD:
			opts->mode = calloc(1, strlen("PAM_SM_PASSWORD") + 1);
			strcpy(opts->mode, "PAM_SM_PASSWORD");
			break;

		default: // PAM_SM_AUTH
			opts->mode = calloc(1, strlen("PAM_SM_AUTH") + 1);
			strcpy(opts->mode,"PAM_SM_AUTH");
	}

	return PAM_SUCCESS;
}

size_t curl_wf(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t oldsize=0;

	if( 0 == size * nmemb )
		return 0;

	if( NULL == recvbuf )
	{
		if( NULL == ( recvbuf = calloc(nmemb, size) ) )
		{
			return 0;
		}
	}

	if( NULL == ( recvbuf = realloc(recvbuf, recvbuf_size + (nmemb * size)) ) )
	{
		return 0;
	}
	else
	{
		oldsize=recvbuf_size;
		recvbuf_size += nmemb * size;
		memcpy(recvbuf + oldsize, ptr, size * nmemb);
		return(size*nmemb);
	}
}

int fetch_url(pam_url_opts opts)
{
	CURL* eh = NULL;
	char* post = NULL;

	if( NULL == opts.user )
		opts.user = calloc(1,1);

	if( NULL == opts.passwd )
		opts.passwd = calloc(1,1);

	post = calloc(1,strlen(opts.userfield) +
					strlen("=") +
					strlen(opts.user) +
					strlen("&") +
					strlen(opts.passwdfield) +
					strlen("=") +
					strlen(opts.passwd) +
					strlen("&mode=") +
					strlen(opts.mode) +
					strlen(opts.extrafield) +
					strlen("\0") );

	sprintf(post, "%s=%s&%s=%s&mode=%s%s", opts.userfield,
													(char*)opts.user,
													opts.passwdfield,
													(char*)opts.passwd,
													opts.mode,
													opts.extrafield);

	if( 0 != curl_global_init(CURL_GLOBAL_ALL) )
		return PAM_AUTH_ERR;

	if( NULL == (eh = curl_easy_init() ) )
		return PAM_AUTH_ERR;

#ifdef DEBUG
	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_VERBOSE, 1) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}
#endif

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_POSTFIELDS, post) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_USERAGENT, USER_AGENT) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, curl_wf) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_URL, opts.url) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 2) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 1) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_FAILONERROR, 1) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}

	if( CURLE_OK != curl_easy_perform(eh) )
	{
		curl_easy_cleanup(eh);
		return PAM_AUTH_ERR;
	}
	else
	{
		curl_easy_cleanup(eh);
		return PAM_SUCCESS;
	}
}

int check_psk(pam_url_opts opts)
{
	int ret=0;

	if( NULL == recvbuf )
	{
		ret++;
		return PAM_AUTH_ERR;
	}

	if( 0 != memcmp(opts.PSK, recvbuf, strlen(opts.PSK)) )
		ret++;

	if( 0 != ret )
	{
		return PAM_AUTH_ERR;
	}
	else
	{
		return PAM_SUCCESS;
	}
}

void cleanup(pam_url_opts* opts)
{
	if( NULL != recvbuf )
		free(recvbuf);

	recvbuf_size=0;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ // by now, a dummy
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
	pam_url_opts opts;

	int ret = 0;

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		ret++;
		debug(pamh, "Could not get user item from pam.");
	}

	if( PAM_SUCCESS != pam_get_item(pamh, PAM_AUTHTOK, &opts.passwd) )
	{
		ret++;
		debug(pamh, "Could not get password item from pam.");
	}

	if( NULL == opts.passwd )
	{
		debug(pamh, "No password. Will ask user for it.");
		if( PAM_SUCCESS != get_password(pamh, &opts) )
		{
			debug(pamh, "Could not get password from user. No TTY?");
			return PAM_AUTH_ERR;
		}
		else
		{
			pam_set_item(pamh, PAM_AUTHTOK, opts.passwd);
		}
	}

	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_AUTH) )
	{
		ret++;
		debug(pamh, "Could not parse module options.");
	}

	if( PAM_SUCCESS != fetch_url(opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_psk(opts) )
	{
		ret++;
		debug(pamh, "Pre Shared Key differs from ours.");
	}

	if( 0 == ret )
		return PAM_SUCCESS;

	debug(pamh, "Authentication failed.");
	cleanup(&opts);

	return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_url_opts opts;
	int ret=0;

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		ret++;
		debug(pamh, "Could not get user item from pam.");
	}

	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_ACCOUNT) )
	{
		ret++;
		debug(pamh, "Could not parse module options.");
	}

	if( PAM_SUCCESS != fetch_url(opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_psk(opts) )
	{
		ret++;
		debug(pamh, "Pre Shared Key differs from ours.");
	}

	if( 0 == ret )
		return PAM_SUCCESS;

	debug(pamh, "Account aged out. Failing.");

	cleanup(&opts);

	return PAM_PERM_DENIED;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_url_opts opts;
	int ret=0;
	char* addextra = "&PAM_SM_SESSION=open";
	char* tmp = NULL;

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		ret++;
		debug(pamh, "Could not get user item from pam.");
	}

	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_SESSION) )
	{
		ret++;
		debug(pamh, "Could not parse module options.");
	}

	opts.extrafield = realloc(opts.extrafield, strlen(opts.extrafield) + strlen(addextra) + 1);
	tmp = calloc(1, strlen(opts.extrafield) );
	sprintf(tmp, "%s", opts.extrafield );
	sprintf(opts.extrafield, "%s%s", addextra, tmp);
	free(tmp);

	if( PAM_SUCCESS != fetch_url(opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_psk(opts) )
	{
		ret++;
		debug(pamh, "Pre Shared Key differs from ours.");
	}

	if( 0 == ret )
		return PAM_SUCCESS;

	debug(pamh, "Session not registering. Failing.");

	cleanup(&opts);

	return PAM_SESSION_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_url_opts opts;
	int ret=0;
	char* addextra = "&PAM_SM_SESSION=close";
	char* tmp = NULL;

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		ret++;
		debug(pamh, "Could not get user item from pam.");
	}

	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_SESSION) )
	{
		ret++;
		debug(pamh, "Could not parse module options.");
	}

	opts.extrafield = realloc(opts.extrafield, strlen(opts.extrafield) + strlen(addextra) + 1);
	tmp = calloc(1, strlen(opts.extrafield) );
	sprintf(tmp, "%s", opts.extrafield );
	sprintf(opts.extrafield, "%s%s", addextra, tmp);
	free(tmp);

	if( PAM_SUCCESS != fetch_url(opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_psk(opts) )
	{
		ret++;
		debug(pamh, "Pre Shared Key differs from ours.");
	}

	if( 0 == ret )
		return PAM_SUCCESS;

	debug(pamh, "Session not releasing. Failing.");

	cleanup(&opts);

	return PAM_SESSION_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_url_opts opts;
	int ret=0;
	char *newp1 = NULL, *newp2 = NULL;
	char *tmp = NULL;

	if( PAM_PRELIM_CHECK == flags )
	{ // TODO: Connection checks?
		return PAM_SUCCESS;
	}

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		ret++;
		debug(pamh, "Could not get user item from pam.");
	}

	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_PASSWORD) )
	{
		ret++;
		debug(pamh, "Could not parse module options.");
	}

	pam_get_item(pamh, PAM_OLDAUTHTOK, &opts.passwd);
	if( NULL == opts.passwd )
	{
		pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &opts.passwd, "%s", "   CURRENT password: ");
	}

	pam_get_item(pamh, PAM_AUTHTOK, &newp1);
	if( NULL == newp1 )
	{
		pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &newp1, "%s"," Enter NEW password: ");
		pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &newp2, "%s","Retype NEW password: ");
		if( 0 != strcmp(newp1,newp2) )
		{
			ret++;
			return PAM_AUTHTOK_ERR;
		}
	}

	opts.extrafield = realloc(opts.extrafield, strlen(opts.extrafield) +
												strlen("&newpass=") +
												strlen(newp1) + 1);
	tmp = calloc(1, strlen(opts.extrafield) );
	sprintf(tmp, "%s", opts.extrafield );
	sprintf(opts.extrafield, "&newpass=%s%s", newp1, tmp);
	free(tmp);

	if( PAM_SUCCESS != fetch_url(opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_psk(opts) )
	{
		ret++;
		debug(pamh, "Pre Shared Key differs from ours.");
	}

	cleanup(&opts);

	if( 0 == ret )
	{
		return PAM_SUCCESS;
	}
	else
	{
		debug(pamh, "Password change failed.");
		return PAM_AUTHTOK_ERR;
	}
}



/*
 * vim: nu paste
 */

