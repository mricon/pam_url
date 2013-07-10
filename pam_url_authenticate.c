// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#include "pam_url.h"

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ // by now, a dummy
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
	pam_url_opts opts;
	int ret = 0;
	int len = 0;
	char* prev_passwd = NULL;
	char* new_passwd = NULL;

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

	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_AUTH) )
	{
		ret++;
		debug(pamh, "Could not parse module options.");
	}

	if( !opts.use_first_pass || NULL == opts.passwd )
	{
		if( NULL != opts.passwd ) {
			prev_passwd = calloc(1, strlen(opts.passwd) + 1);
			snprintf(prev_passwd, strlen(opts.passwd) + 1, "%s", opts.passwd);
		}

		debug(pamh, "No password or use_first_pass is not set. Prompting user.");
		if( PAM_SUCCESS != get_password(pamh, &opts) )
		{
			debug(pamh, "Could not get password from user. No TTY?");
			return PAM_AUTH_ERR;
		}
		else
		{
			if( opts.prepend_first_pass && NULL != prev_passwd ) {
				new_passwd = calloc(1, strlen(opts.passwd) + 1);
				snprintf(new_passwd, strlen(opts.passwd) + 1, "%s", opts.passwd);
				len = strlen(opts.passwd) + strlen(prev_passwd) + 1;
				opts.passwd = realloc(opts.passwd, len);
				snprintf(opts.passwd, len, "%s%s", prev_passwd, new_passwd);
				free(prev_passwd);
				free(new_passwd);
			}
			debug(pamh, "No password or use_first_pass is not set. Prompting user.");
			pam_set_item(pamh, PAM_AUTHTOK, opts.passwd);
		}
	}

	if( PAM_SUCCESS != fetch_url(pamh, opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_rc(opts) )
	{
		ret++;
		debug(pamh, "Wrong Return Code.");
	}

	cleanup(&opts);

	if( 0 == ret )
	{
		return PAM_SUCCESS;
	}
	else
	{
		debug(pamh, "Authentication failed.");
		return PAM_AUTH_ERR;
	}
}
