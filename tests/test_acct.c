#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>

int main(int argc, char **argv) {
	pam_handle_t *pamh=NULL;
	static struct pam_conv pamc = {
			misc_conv,
			NULL
	};

	if( PAM_SUCCESS != pam_start("test", "testa", &pamc, &pamh) )
	{
		fprintf(stderr, "ERR: pam_start failed!\n");
		return 1;
	}

	/*
	if( PAM_SUCCESS != pam_set_item(pamh, PAM_USER, "tester") )
	{
		fprintf(stderr, "ERR: pam_set_item user failed!\n");
		return 1;
	}

	if( PAM_SUCCESS != pam_chauthtok(pamh, 0) )
	{
		fprintf(stderr, "ERR: pam_chauthtok failed!\n");
		return 1;
	}

	if( PAM_SUCCESS != pam_set_item(pamh, PAM_AUTHTOK, "mypassword") )
	{
		fprintf(stderr, "ERR: pam_set_item password failed!\n");
		return 1;
	}
	*/

	if( PAM_SUCCESS != pam_acct_mgmt(pamh, 0) )
	{
		fprintf(stderr, "ERR: pam_acct_mgmt failed!\n");
		return 1;
	}

	if( PAM_SUCCESS != pam_end(pamh, PAM_SUCCESS) )
	{
		fprintf(stderr, "ERR: pam_end failed!\n");
		return 1;
	}

	return 0;

}
