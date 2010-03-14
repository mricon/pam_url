// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#include "pam_url.h"

char* recvbuf = NULL;
size_t recvbuf_size = 0;

void debug(pam_handle_t* pamh, const char *msg)
{
	pam_syslog(pamh, LOG_ERR, "%s", msg);
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
	int i = 0;

#ifdef DEBUG
	pam_url_debug = 1;
#else
	pam_url_debug = 0;
#endif

	if( 0 != argc && NULL != argv)
	{
		for( i = 0; i <= argc; i++)
		{
			if( 0 == strcmp(argv[i], "debug") )
			{
				pam_url_debug = 1;
			}

			if( 0 == strncmp(argv[i], "config=", strlen("config=")) )
			{
				opts->configfile = calloc(1, strlen(argv[i]) - strlen("config=") + 1 );
				strcpy(opts->configfile, argv[i] + strlen("config=") );
			}
		}
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

	config_t config;
	config_init(&config);
	config_read_file(&config,"/etc/pam_url.conf");

	if( CONFIG_FALSE == config_lookup_string(&config, "pam_url.settings.uri", &opts->url) )
	{
		opts->url = calloc(1, strlen(DEF_URL) + 1);
		strcpy(opts->url, DEF_URL);
	}

	if( CONFIG_FALSE == config_lookup_string(&config, "pam_url.settings.presharedkey", &opts->PSK) )
	{
		opts->PSK = calloc(1, strlen(DEF_PSK) + 1);
		strcpy(opts->PSK, DEF_PSK);
	}

	if( CONFIG_FALSE == config_lookup_string(&config, "pam_url.settings.userfield", &opts->userfield) )
	{
		opts->userfield = calloc(1, strlen(DEF_USER) + 1);
		strcpy(opts->userfield, DEF_USER);
	}

	if( CONFIG_FALSE == config_lookup_string(&config, "pam_url.settings.passwdfield", &opts->passwdfield) )
	{
		opts->passwdfield = calloc(1, strlen(DEF_PASSWD) + 1);
		strcpy(opts->passwdfield, DEF_PASSWD);
	}

	if( CONFIG_FALSE == config_lookup_string(&config, "pam_url.settings.extradata", &opts->extrafield) )
	{
		opts->extrafield = calloc(1, strlen(DEF_EXTRA) + 1);
		strcpy(opts->extrafield, DEF_EXTRA);
	}

	if( CONFIG_FALSE == config_lookup_bool(&config, "pam_url.ssl.verify_peer", &opts->ssl_verify_peer) )
	{
		opts->ssl_verify_peer = 1;
	}

	if( CONFIG_FALSE == config_lookup_bool(&config, "pam_url.ssl.verify_host", &opts->ssl_verify_host) )
	{
		opts->ssl_verify_host = 1;
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

	if( 1 == pam_url_debug)
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_VERBOSE, 1) )
		{
			curl_easy_cleanup(eh);
			return PAM_AUTH_ERR;
		}

		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGDATA, pamh) )
		{
			curl_easy_cleanup(eh);
			return PAM_AUTH_ERR;
		}

		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGFUNCTION, curl_debug) )
		{
			curl_easy_cleanup(eh);
			return PAM_AUTH_ERR;
		}
	}

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

	if( opts.ssl_verify_host == 1 )
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 2) )
		{
			curl_easy_cleanup(eh);
			return PAM_AUTH_ERR;
		}
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 0) )
		{
			curl_easy_cleanup(eh);
			return PAM_AUTH_ERR;
		}
	}

	if( opts.ssl_verify_peer == 1 )
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 1) )
		{
			curl_easy_cleanup(eh);
			return PAM_AUTH_ERR;
		}
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 0) )
		{
			curl_easy_cleanup(eh);
			return PAM_AUTH_ERR;
		}
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
