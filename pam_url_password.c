// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url

#include "pam_url.h"

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_url_opts opts;
	int ret=0;
    int len = 0;
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
		pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, (char**)&opts.passwd, "%s", "   CURRENT password: ");
	}

	pam_get_item(pamh, PAM_AUTHTOK, (const void**)&newp1);
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

	len = strlen(opts.extra_field) + strlen("&newpass=") + strlen(newp1) + 1;
	opts.extra_field = realloc(opts.extra_field, len);
	if (opts.extra_field == NULL)
		goto done;

	tmp = calloc(1, strlen(opts.extra_field) + 1);
	if (tmp == NULL)
		goto done;

	snprintf(tmp, strlen(opts.extra_field) + 1, "%s", opts.extra_field);
	snprintf(opts.extra_field, len, "&newpass=%s%s", newp1, tmp);
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
	free(opts.extra_field);

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
