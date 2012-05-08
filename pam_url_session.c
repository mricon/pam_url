// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#include "pam_url.h"

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_url_opts opts;
	int ret=0;
	int len = 0;
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

	len = strlen(opts.extra_field) + strlen(addextra) + 1;
	opts.extra_field = realloc(opts.extra_field, len);
	if (opts.extra_field == NULL)
		goto done;

	tmp = calloc(1, strlen(opts.extra_field) + 1);
	if (tmp == NULL)
		goto done;
	snprintf(tmp, strlen(opts.extra_field) + 1, "%s", opts.extra_field);
	snprintf(opts.extra_field, len, "%s%s", addextra, tmp);
	free(tmp);

	if( PAM_SUCCESS != fetch_url(pamh, opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_rc(opts) )
	{
		ret++;
		debug(pamh, "Wrong Return Code");
	}

done:

	cleanup(&opts);

	if( 0 == ret )
	{
		return PAM_SUCCESS;
	}
	else
	{
		debug(pamh, "Session not registering. Failing.");
		return PAM_SESSION_ERR;
	}
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_url_opts opts;
	int ret=0;
	int len = 0;
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

	len = strlen(opts.extra_field) + strlen(addextra) + 1;
	opts.extra_field = realloc(opts.extra_field, len);
	if (opts.extra_field == NULL)
		goto done;

	tmp = calloc(1, strlen(opts.extra_field) + 1);
	if (tmp == NULL)
		goto done;

	snprintf(tmp, strlen(opts.extra_field) + 1, "%s", opts.extra_field );
	snprintf(opts.extra_field, len, "%s%s", addextra, tmp);
	free(tmp);

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

done:
	cleanup(&opts);

	if( 0 == ret )
	{
		return PAM_SUCCESS;
	}
	else
	{
		debug(pamh, "Session not releasing. Failing.");
		return PAM_SESSION_ERR;
	}
}
