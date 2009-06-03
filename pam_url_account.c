// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#include "pam_url.h"

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
