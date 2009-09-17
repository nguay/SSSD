/*
    SSSD

    Kerberos 5 Backend Module -- Utilities tests 

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <check.h>

#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_auth.h"

#define BASE "/abc/def"

#define USERNAME "testuser"
#define UID "12345"
#define PRINCIPLE_NAME "testuser@EXAMPLE.COM"
#define REALM "REALM.ORG"
#define HOME_DIRECTORY "/home/testuser"
#define CCACHE_DIR "/var/tmp"
#define PID "4321"

TALLOC_CTX *tmp_ctx = NULL;
struct krb5child_req *kr;

void setup_talloc_context(void)
{
    int ret;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    fail_unless(tmp_ctx == NULL, "Talloc context already initialized.");
    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "Cannot create talloc context.");

    kr = talloc_zero(tmp_ctx, struct krb5child_req);
    fail_unless(kr != NULL, "Cannot create krb5child_req structure.");

    pd = talloc_zero(tmp_ctx, struct pam_data);
    fail_unless(pd != NULL, "Cannot create pam_data structure.");

    krb5_ctx = talloc_zero(tmp_ctx, struct krb5_ctx);
    fail_unless(pd != NULL, "Cannot create krb5_ctx structure.");

    pd->user = USERNAME;
    pd->pw_uid = atoi(UID);
    pd->upn = PRINCIPLE_NAME;
    pd->cli_pid = atoi(PID);

    krb5_ctx->realm = REALM;
    krb5_ctx->ccache_dir = CCACHE_DIR;

    kr->homedir = HOME_DIRECTORY;

    kr->pd = pd;
    kr->krb5_ctx = krb5_ctx;

}

void free_talloc_context(void)
{
    int ret;
    fail_unless(tmp_ctx != NULL, "Talloc context already freed.");
    ret = talloc_free(tmp_ctx);
    fail_unless(ret == 0, "Connot free talloc context.");
}

START_TEST(test_multiple_substitutions)
{
    char *test_template = BASE"_%u_%U_%u";
    char *expected = BASE"_"USERNAME"_"UID"_"USERNAME;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_username)
{
    char *test_template = BASE"_%u";
    char *expected = BASE"_"USERNAME;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_uid)
{
    char *test_template = BASE"_%U";
    char *expected = BASE"_"UID;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_upn)
{
    char *test_template = BASE"_%p";
    char *expected = BASE"_"PRINCIPLE_NAME;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_realm)
{
    char *test_template = BASE"_%r";
    char *expected = BASE"_"REALM;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_home)
{
    char *test_template = BASE"_%h";
    char *expected = BASE"_"HOME_DIRECTORY;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_ccache_dir)
{
    char *test_template = BASE"_%d";
    char *expected = BASE"_"CCACHE_DIR;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_pid)
{
    char *test_template = BASE"_%P";
    char *expected = BASE"_"PID;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_percent)
{
    char *test_template = BASE"_%%";
    char *expected = BASE"_%";
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_unknow_template)
{
    char *test_template = BASE"_%X";
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result == NULL, "Unknown template [%s] should fail.",
                test_template);
}
END_TEST

START_TEST(test_NULL)
{
    char *test_template = NULL;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result == NULL, "Expected NULL as a result for an empty input.",
                test_template);
}
END_TEST

START_TEST(test_no_substitution)
{
    char *test_template = BASE;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, test_template) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, test_template);
}
END_TEST

Suite *krb5_utils_suite (void)
{
    Suite *s = suite_create ("krb5_utils");

    TCase *tc_ccname_template = tcase_create ("ccname_template");
    tcase_add_checked_fixture (tc_ccname_template, setup_talloc_context,
                               free_talloc_context);
    tcase_add_test (tc_ccname_template, test_no_substitution);
    tcase_add_test (tc_ccname_template, test_NULL);
    tcase_add_test (tc_ccname_template, test_unknow_template);
    tcase_add_test (tc_ccname_template, test_username);
    tcase_add_test (tc_ccname_template, test_uid);
    tcase_add_test (tc_ccname_template, test_upn);
    tcase_add_test (tc_ccname_template, test_realm);
    tcase_add_test (tc_ccname_template, test_home);
    tcase_add_test (tc_ccname_template, test_ccache_dir);
    tcase_add_test (tc_ccname_template, test_pid);
    tcase_add_test (tc_ccname_template, test_percent);
    tcase_add_test (tc_ccname_template, test_multiple_substitutions);
    suite_add_tcase (s, tc_ccname_template);

    return s;
}

int main(void)
{
  int number_failed;
  Suite *s = krb5_utils_suite ();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_NORMAL);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
