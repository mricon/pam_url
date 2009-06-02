
#include "pam_url.h"

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
