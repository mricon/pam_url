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
