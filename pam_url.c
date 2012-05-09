// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#include "pam_url.h"

#include <stdio.h>
#include <stdint.h>

char* recvbuf = NULL;
size_t recvbuf_size = 0;
static config_t config;

void debug(pam_handle_t* pamh, const char *msg)
{
	pam_syslog(pamh, LOG_ERR, "%s", msg);
}

int get_password(pam_handle_t* pamh, pam_url_opts* opts)
{
	char* p = NULL;
	const char *prompt;
	int prompt_len = 0;

	if(config_lookup_string(&config, "pam_url.settings.prompt", &prompt) == CONFIG_FALSE)
		prompt = DEF_PROMPT;
	
	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &p, "%s", prompt);
	
	if( NULL != p && strlen(p) > 0)
	{
		opts->passwd = p;
		return PAM_SUCCESS;
	}
	else
	{
		return PAM_AUTH_ERR;
	}
}


int parse_opts(pam_url_opts *opts, int argc, const char *argv[], int mode)
{
#if defined(DEBUG)
	pam_url_debug = true;
#else
	pam_url_debug = false;
#endif
	opts->configfile = NULL;
	
	if(argc > 0 && argv != NULL)
	{	
		for(int next_arg = 0; next_arg < argc; next_arg++)
		{
			if(strcmp(argv[next_arg], "debug") == 0)
			{
				pam_url_debug = true;
				continue;
			}
			
			if(strncmp(argv[next_arg], "config=", 7) == 0)
			{
				// Skip the first 7 chars ('config=').
				opts->configfile = strdup(argv[next_arg] + 7);
				continue;
			}
		}
	}
	
	if(opts->configfile == NULL)
		opts->configfile = strdup("/etc/pam_url.conf");
	
	switch(mode)
	{
		case PAM_SM_ACCOUNT:
			opts->mode = "PAM_SM_ACCOUNT";
			break;
		case PAM_SM_SESSION:
			opts->mode = "PAM_SM_SESSION";
			break;
		case PAM_SM_PASSWORD:
			opts->mode = "PAM_SM_PASSWORD";
			break;
		case PAM_SM_AUTH:
		default:
			opts->mode = "PAM_SM_AUTH";
			break;
	}
	
	config_init(&config);
	config_read_file(&config, opts->configfile);
	
	// General Settings
	if(config_lookup_string(&config, "pam_url.settings.url", &opts->url) == CONFIG_FALSE)
		opts->url = DEF_URL;
	
	if(config_lookup_string(&config, "pam_url.settings.returncode", &opts->ret_code) == CONFIG_FALSE)
		opts->ret_code = DEF_RETURNCODE;
	
	if(config_lookup_string(&config, "pam_url.settings.userfield", &opts->user_field) == CONFIG_FALSE)
		opts->user_field = DEF_USER;
	
	if(config_lookup_string(&config, "pam_url.settings.passwdfield", &opts->passwd_field) == CONFIG_FALSE)
		opts->passwd_field = DEF_PASSWD;
	
	if(config_lookup_string(&config, "pam_url.settings.extradata", &opts->extra_field) == CONFIG_FALSE)
		opts->extra_field = DEF_EXTRA;
	
	
	// SSL Options
	if(config_lookup_string(&config, "pam_url.ssl.client_cert", &opts->ssl_cert) == CONFIG_FALSE)
		opts->ssl_cert = DEF_SSLCERT;
	
	if(config_lookup_string(&config, "pam_url.ssl.client_key", &opts->ssl_key) == CONFIG_FALSE)
		opts->ssl_key = DEF_SSLKEY;
	
	if(config_lookup_bool(&config, "pam_url.ssl.verify_host", (int *)&opts->ssl_verify_host) == CONFIG_FALSE)
		opts->ssl_verify_host = true;
	
	if(config_lookup_bool(&config, "pam_url.ssl.verify_peer", (int *)&opts->ssl_verify_peer) == CONFIG_FALSE)
		opts->ssl_verify_peer = true;
	
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

	// Check the multiplication for an overflow
	if (((nmemb * size) > (SIZE_MAX / nmemb)) ||
			// Check the addition for an overflow
			((SIZE_MAX - recvbuf_size) < (nmemb * size))) {
		// The arithmetic will cause an integer overflow
		return 0;
	}
	if( NULL == ( recvbuf = realloc(recvbuf, recvbuf_size + (nmemb * size)) ) )
	{
		return 0;
	}
	else
	{
		oldsize = recvbuf_size;
		recvbuf_size += nmemb * size;
		memcpy(recvbuf + oldsize, ptr, size * nmemb);
		return(size*nmemb);
	}
}

int curl_debug(CURL *C, curl_infotype info, char * text, size_t textsize, void* pamh)
{
	debug((pam_handle_t*)pamh, text);
	return 0;
}

int fetch_url(pam_handle_t *pamh, pam_url_opts opts)
{
	CURL* eh = NULL;
	char* post = NULL;
	int ret = 0;

	if( NULL == opts.user )
		opts.user = "";

	if( NULL == opts.passwd )
		opts.passwd = "";
	
	if( 0 != curl_global_init(CURL_GLOBAL_ALL) )
		goto curl_error;

	if( NULL == (eh = curl_easy_init() ) )
		goto curl_error;

	char *safe_user = curl_easy_escape(eh, opts.user, 0);
	if( safe_user == NULL )
		goto curl_error;
	
	char *safe_passwd = curl_easy_escape(eh, opts.passwd, 0);
	if( safe_passwd == NULL )
		goto curl_error;

	ret = asprintf(&post, "%s=%s&%s=%s&mode=%s%s", opts.user_field,
							safe_user,
							opts.passwd_field,
							safe_passwd,
							opts.mode,
							opts.extra_field);
	
	curl_free(safe_passwd);
	curl_free(safe_user);

	if (ret == -1)
		// If this happens, the contents of post are undefined, we could
		// end up freeing an uninitialized pointer, which could crash (but
		// should not have security implications in this context).
		goto curl_error;

	if( 1 == pam_url_debug)
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_VERBOSE, 1) )
			goto curl_error;

		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGDATA, pamh) )
			goto curl_error;

		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGFUNCTION, curl_debug) )
			goto curl_error;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_POSTFIELDS, post) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_USERAGENT, USER_AGENT) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, curl_wf) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_URL, opts.url) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLCERT, opts.ssl_cert) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLCERTTYPE, "PEM") )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLKEY, opts.ssl_key) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLKEYTYPE, "PEM") )
		goto curl_error;

	if( opts.ssl_verify_host == true )
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 2) )
			goto curl_error;
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 0) )
			goto curl_error;
	}

	if( opts.ssl_verify_peer == true )
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 1) )
			goto curl_error;
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 0) )
			goto curl_error;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_FAILONERROR, 1) )
		goto curl_error;

	if( CURLE_OK != curl_easy_perform(eh) )
		goto curl_error;

	// No errors
	curl_easy_cleanup(eh);
	free(post);
	return PAM_SUCCESS;

curl_error:
	if (eh != NULL)
		curl_easy_cleanup(eh);
	if (post != NULL)
		free(post);
	return PAM_AUTH_ERR;
}

int check_rc(pam_url_opts opts)
{
	int ret=0;

	if( NULL == recvbuf )
	{
		ret++;
		return PAM_AUTH_ERR;
	}

	if( 0 != memcmp(opts.ret_code, recvbuf, strlen(opts.ret_code)) )
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
	{
		free(recvbuf);
		recvbuf = NULL;
	}

	recvbuf_size=0;
	free(opts->configfile);
	config_destroy(&config);
}
