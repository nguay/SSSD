#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <pcre.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"
#include "confdb/confdb.h"

#ifdef HAVE_LIBPCRE_LESSER_THAN_7
#define NAME_DOMAIN_PATTERN_OPTIONS (PCRE_EXTENDED)
#else
#define NAME_DOMAIN_PATTERN_OPTIONS (PCRE_DUPNAMES | PCRE_EXTENDED)
#endif

#define SEED_SOURCE_LOCAL    1
#define SEED_SOURCE_DP      2

#define PASS_PROMPT 0
#define PASS_FILE 1

#ifndef TEMP_LEN
#define TEMP_LEN 10

int getstr_input(struct tools_ctx *mem_ctx, const char* request, char **_input)
{
    int ret = EOK;
    TALLOC_CTX *temp_ctx = NULL;
    char *temp = NULL;
    int bytes_read = 0;

    temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
 
    temp = talloc_array(temp_ctx, char, TEMP_LEN);
    if (temp == NULL) {
        ret = ENOMEM;
        goto done;
    }
    temp[0] = '\0';

    talloc_set_destructor((TALLOC_CTX *)temp, password_destructor);

    printf(_("Enter %1$s (%2$s):"), request,
            (*_input != NULL) ? *_input : request );
 
    while (fgets(temp, TEMP_LEN, stdin) != NULL){
        *_input = talloc_asprintf_append(*_input, "%s", temp);
        if (*_input == NULL) {
            ret = ENOMEM;
            goto done;
        }
        ret = EOK;

        //while (*_input[bytes_read] != '\0') bytes_read++;

        bytes_read = strlen(*_input);
        //DEBUG(SSSDBG_TRACE_FUNC, ("input so far [%s] [%d]\n",*_input,bytes_read));

        if ((char *)_input[0][bytes_read-1] == '\n') {
            _input[0][bytes_read-1] = '\0';
            break;
        }
        //DEBUG(SSSDBG_TRACE_FUNC, ("input [%s]\n",*_input));
    }

    ret = EOK;

done:
    talloc_free(temp_ctx);
    return ret;
}

int getid_input(TALLOC_CTX *mem_ctx, const char* request, uid_t *_input)
{
    int ret = EOK;
    TALLOC_CTX *temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    printf(_("Enter %1$s (%2$d):"), request, *_input);

    scanf("%d", _input);

    char c = getchar();
    if (c != '\n') {
        ret = EXIT_FAILURE;
    }

done:
    talloc_free(temp_ctx);
    return ret;
}

/*
 * get password from:
 *     file, or prompt for it
 */
int password_input(int method, char *file, char ** password)
{
    char* temp = NULL;
    int ret = EOK;
    FILE *finput = NULL;
    TALLOC_CTX *temp_ctx = NULL;

    temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate temp password context\n"));
        ret = ENOMEM;
        goto done;
    }

    temp = talloc_zero_array(temp_ctx, char, TEMP_LEN);
    if (temp == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate temp string\n"));
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor((TALLOC_CTX *)temp, password_destructor);

    if (method == PASS_FILE) {
        finput = fopen(file, "r");
        if (finput == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to open file for password\n"));
            ret = EINVAL;
            goto done;
        }
        //while(getline( &temp, TEMP_LEN, finput) != -1) {
        while (fgets(temp, TEMP_LEN, finput) != NULL) {
            *password = talloc_asprintf_append(*password, "%s", temp);
        }
    }

    *password = getpass("Password: ");
    if (*password == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get password from prompt\n"));
        ret = EINVAL;
        goto done;
    }

done:
    talloc_free(temp_ctx);
    if (finput) fclose(finput);
    return ret;
}
#endif /* TEMP_LEN */

int get_seed_input(struct tools_ctx *tctx, char **groups)
{
    int ret = EOK;

    ret = getstr_input(tctx, "username", &tctx->octx->name);
    if (ret != EOK) {
        goto done;
    }

    ret = getid_input(tctx, "UID for user", &tctx->octx->uid);
    if (ret != EOK) {
        goto done;
    }

    ret = getstr_input(tctx, "user comment (gecos)", &tctx->octx->gecos);
    if (ret != EOK) {
        goto done;
    }

    ret = getstr_input(tctx, "home directory", &tctx->octx->home);
    if (ret != EOK) {
        goto done;
    }

    ret = getstr_input(tctx, "user login shell", &tctx->octx->shell);
    if (ret != EOK) {
        goto done;
    }

    ret = getstr_input(tctx, "user groups", groups);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("username input: %s\n", tctx->octx->name));
    DEBUG(SSSDBG_TRACE_FUNC, ("uid input: %d\n", tctx->octx->uid));
    DEBUG(SSSDBG_TRACE_FUNC, ("gecos input: %s\n", tctx->octx->gecos));
    DEBUG(SSSDBG_TRACE_FUNC, ("home input: %s\n", tctx->octx->home));
    DEBUG(SSSDBG_TRACE_FUNC, ("shell input: %s\n", tctx->octx->shell));
    DEBUG(SSSDBG_TRACE_FUNC, ("groups input: %s\n", groups));
 
done:
    return ret;
}

int main(int argc, const char **argv)
{
    int seed_debug = 0xFFF0;
    int seed_source = SEED_SOURCE_DP;
    int interact = 0;

    char *uname = NULL;
    char *selinux_user = NULL;
    char *groups = NULL;
    char *badgroup = NULL;
    char *domain = NULL;
    char *password = NULL;
    int password_method = PASS_PROMPT;
    char *password_file;

    struct passwd *pc_passwd = NULL;

    struct ldb_result *res = NULL;

    const char *errstr = NULL;
    int errval;
    int errpos;
    int ret;

    struct tools_ctx *tctx = NULL;
    tctx = talloc_zero(NULL, struct tools_ctx);
    if (tctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate tools context\n"));
        ret = ENOMEM;
        goto end;
    }

    tctx->octx = talloc_zero(tctx, struct ops_ctx);
    if (tctx->octx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate data context\n"));
        ret = ENOMEM;
        goto end;
    }

    struct poptOption options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &seed_debug, 0,
         _("The debug level to run with"), NULL },
        { "uid",   'u', POPT_ARG_INT, &tctx->octx->uid, 0,
         _("User UID"), NULL },
        { "gid",   'g', POPT_ARG_INT, &tctx->octx->gid, 0,
         _("User GID"), NULL },
        { "username", 'n', POPT_ARG_STRING, &uname, 0,
         _("Username"), NULL},
        { "gecos", 'c', POPT_ARG_STRING, &tctx->octx->gecos, 0,
         _("Comment string"), NULL},
        { "home",  'h', POPT_ARG_STRING, &tctx->octx->home, 0,
         _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &tctx->octx->shell, 0,
         _("Login Shell"), NULL },
        { "groups", 'G', POPT_ARG_STRING, NULL, 'G', _("Groups"), NULL },
        { "force", 'f', POPT_ARG_NONE, NULL, 'f',
         _("force override of domain user info"), NULL },
        { "interactive", 'i', POPT_ARG_NONE, NULL, 'i',
         _("use interactive mode to enter user data"), NULL },
        { "skel", 'k', POPT_ARG_STRING, &tctx->octx->skeldir, 0,
         _("Specify an alternative skeleton directory"), NULL },
        { "selinux-user", 'Z', POPT_ARG_STRING, &selinux_user, 0,
         _("The SELinux user for user's login"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;

    debug_prg_name = argv[0];
    debug_level = debug_convert_old_level(seed_debug);

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("set_locale failed (%d): %s\n",
                                    ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto end;
    }

    /* parse arguments */
    pc = poptGetContext(NULL, argc, argv, options, 0);
    if (argc < 2) {
        poptPrintUsage(pc,stderr,0);
        ret = EXIT_FAILURE;
        goto end;
    }

    poptSetOtherOptionHelp(pc, "[OPTIONS] usernmae@DOMAIN");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'G':
                groups = poptGetOptArg(pc);
                if (!groups) {
                    BAD_POPT_PARAMS(pc, _("Specify group to add user to\n"),
                                          ret, end);
                }
                break;

            case 'f':
                DEBUG(SSSDBG_TRACE_INTERNAL, ("local seed info forced\n"));
                seed_source = SEED_SOURCE_LOCAL;
                break;

            case 'i':
                DEBUG(SSSDBG_TRACE_INTERNAL, ("Interactive mode slected\n"));
                interact = 1;
                break;
        }
    }

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, end);
    } else {
        ret = EOK;
    }

    /* interactive mode to fill in user seed info */
    if (interact) {
        ret = get_seed_input(tctx, &groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get seed input.\n"));
            ret = EXIT_FAILURE;
            goto end;
        }
    }

    uname = tctx->octx->name;

    /* check if root */
    ret = getuid();
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Running under uid %d, must be root\n", ret));
        ret = EXIT_FAILURE;
        goto end;
    }

    /* setup names context for domain parsing */
    tctx->snctx = talloc_zero(tctx, struct sss_names_ctx);
    if (tctx->snctx == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE,("Failed to allocate names context\n"));
        goto end;
    }

    char *confdb_path = talloc_asprintf(tctx, "%s/%s", "/var/lib/sss/db",
                                        CONFDB_FILE);
    if (confdb_path == NULL) {
        ret = ENOMEM;
        goto end;
    }

    ret = confdb_init(tctx, &tctx->confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not inittialize connection to the confdb\n"));
        goto end;
    }

    if (seed_source != SEED_SOURCE_LOCAL) {
        ret = confdb_get_domain(tctx->confdb, "local", &tctx->local);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to get local domain info from confdb\n"));
        }
    } else {
        tctx->local = tctx->octx->domain;
    }

    ret = confdb_get_string(tctx->confdb, tctx->snctx, confdb_path,
                            CONFDB_NAME_REGEX, NULL, &tctx->snctx->re_pattern);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get domain regex pattern\n"));
    }

    if (tctx->snctx->re_pattern == NULL) {
        ret = confdb_get_string(tctx->confdb, tctx->snctx,
                                CONFDB_MONITOR_CONF_ENTRY, CONFDB_NAME_REGEX,
                                NULL, &tctx->snctx->re_pattern);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to get domain regex from globals\n"));
        }
    }

    if (tctx->snctx->re_pattern == NULL) {
        tctx->snctx->re_pattern = talloc_strdup(tctx,
                                        "(?P<name>[^@]+)@?(?P<domain>[^@]*$)");
        if (tctx->snctx->re_pattern == NULL) {
            ret = ENOMEM;
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate regex string\n"));
            goto end;
        }
#ifdef HAVE_LIBPCRE_LESSER_THAN_7
    } else {
        DEBUG(SSSDBG_OP_FAILURE, ("This binary was build with a version of "
                                  "libpcre that does not support non-unique "
                                  "named subpatterns.\n"));
        DEBUG(SSSDBG_OP_FAILURE, ("Please make sure that your pattern [%s] "
                                  "only contains subpatterns with a unique name"
                                  " and uses the Python syntax (?P<name>).\n",
                                  ctx->re_pattern));
#endif
    }

    ret = confdb_get_string(tctx->confdb, tctx->snctx, confdb_path,
                            CONFDB_FULL_NAME_FORMAT,NULL, &tctx->snctx->fq_fmt);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get fq regex\n"));
    }

    if (tctx->snctx->fq_fmt == NULL) {
        ret = confdb_get_string(tctx->confdb, tctx->snctx,
                                CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_FULL_NAME_FORMAT,
                                NULL, &tctx->snctx->fq_fmt);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Failed to get fq name format from globals\n"));
        }
    }

    if (tctx->snctx->fq_fmt == NULL) {
        tctx->snctx->fq_fmt = talloc_strdup(tctx, "%1$s@%2$s");
        if (tctx->snctx->fq_fmt == NULL) {
            ret = ENOMEM;
            DEBUG(SSSDBG_CRIT_FAILURE,("Failed to allocate fq domain regex\n"));
            goto done;
        }
    }

    tctx->snctx->re = pcre_compile2(tctx->snctx->re_pattern,
                                    NAME_DOMAIN_PATTERN_OPTIONS, &errval,
                                    &errstr, &errpos, NULL);
    if (tctx->snctx->re == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid Regular Expression pattern at "
                                    "position %d. (ERROR: %d [%s])\n",
                                    errpos, errval, errstr));
        ret = EFAULT;
        goto done;
    }
/*
    ret = sss_names_init(tctx, tctx->confdb, tctx->octx->domain->name,
                         &tctx->snctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not set up parsing\n"));
        goto end;
    }
*/
    ret = sss_parse_name(tctx, tctx->snctx, uname, &domain, &tctx->octx->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to parse domain from username\n"));
        ret = EXIT_FAILURE;
        goto end;
    }
    DEBUG(SSSDBG_FUNC_DATA, ("Username parsed: %s\n", tctx->octx->name));

    if (domain) {
        DEBUG(SSSDBG_FUNC_DATA, ("Domain parsed: %s\n", domain));
    } else {
        /* no domain specified; default to local domain */
        domain = talloc_strdup(tctx, tctx->local->name);
    }

    ret = sysdb_init_domain_and_sysdb(tctx, tctx->confdb, domain,
                                      "/var/lib/sss/db", &tctx->octx->domain,
                                      &tctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the sysdb\n"));
        goto end;
    }

    /* get seed info from domain */
/*    if (seed_source == SEED_SOURCE_DP) {

        struct sss_domain_info **doms = NULL;
        struct sss_domain_info *dom = NULL;
        struct sysdb_ctx *sysdb = NULL;
        size_t num_domains = 0;

        for (dom = tctx->octx->domain; dom; dom = dom->next) num_domains++;

        doms = talloc_zero_array(state, struct sss_domain_info *, num_domains);

        ret = confdb_get_domains(tctx->confdb, doms);
        if (ret != EOK || doms == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to get domains from confdb\n"));
        }

        dom = doms[0];
        while(dom) {
           sysdb = dom->sysdb;

        }

    }
*/


    /* Check domains/groups exist for user to be created */
/*    if (groups) {
        ret = parse_groups(tctx, groups, &tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Cannot parse groups to add the user to\n"));
            ERROR("Internal error while parsing parameters\n");
            ret = EXIT_FAILURE;
            goto end;
        }

        ret = parse_group_name_domain(tctx, tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Cannot parse FQDN groups to add user to"));
            ERROR("Groups must be in the same domain as user\n");
            ret = EXIT_FAILURE;
            goto end;
        }
*/
        /* if local source check LOCAL domain for group names */
/*        if (seed_source == SEED_SOURCE_LOCAL) {
            ret = check_group_names(tctx, tctx->octx->addgroups, &badgroup);
            if (ret != EOK) {
                ERROR("Cannot find group %1$s in local domain\n", badgroup);
                ret = EXIT_FAILURE;
                goto end;
            }
        }
    }
*/
    /* password input */
    ret = password_input(password_method, password_file, &password);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Password input failure\n"));
        goto end;
    }

    /* Add user to sysdb and check user was added to cache */
    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        goto done;
    }

    pc_passwd = getpwnam(tctx->octx->name);
    if (pc_passwd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getpwnam failed; user entry not found or allocation error\n"));
    }

    tctx->octx->name = pc_passwd->pw_name;
    tctx->octx->gid = pc_passwd->pw_gid;

    ret = initgroups(tctx->octx->name, tctx->octx->gid);
    if (ret == -1) {
        DEBUG(SSSDBG_OP_FAILURE, ("initgroups failure\n"));
    }

    tctx->error = sysdb_add_user(tctx->sysdb, tctx->octx->name, tctx->octx->uid,
                                 tctx->octx->gid, tctx->octx->gecos,
                                 tctx->octx->home, tctx->octx->shell,
                                 NULL, 0, 0);
    if (tctx->error) {
        sysdb_transaction_cancel(tctx->sysdb);
        goto done;
    }

    ret = sysdb_cache_password(tctx->sysdb, tctx->octx->name, password);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to cache password. (%d)[%s]\n",
                                  ret, strerror(ret)));
    }

    tctx->error = sysdb_transaction_commit(tctx->sysdb);
    if (tctx->error) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb transaction failure\n"));
        goto done;
    }

    ret = sysdb_getpwnam(tctx, tctx->sysdb, tctx->octx->name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Couldn't lookup user (%s) in the cache", tctx->octx->name));
        ret = EXIT_FAILURE;
        goto end;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
                 ("User (%1$s) wasn't found in the cache", tctx->octx->name));
        ret = EXIT_FAILURE;
        goto end;
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("User found in cache\n"));
    }

/* initgroups

    ret = sysdb_initgroups(tctx, tctx->sysdb, pc_username, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb_initgroups failed\n"));
        ERROR("User couldn't be added to cache\n");
        ret = EXIT_FAILURE;
        goto end;
    } else {
       ret = sysdb_transaction_commit(tctx->sysdb);
       if (ret != EOK) {
       }

       ret = sysdb_getpwnam(tctx, tctx->sysdb, pc_username, &res);
       if (ret != EOK) {
           DEBUG(SSSDBG_CRIT_FAILURE,
                 ("Couldn't lookup user (%1$s) in the cache\n", pc_username));
           ret = EXIT_FAILURE;
           goto end;
       }

       if (res->count == 0) {
           DEBUG(SSSDBG_TRACE_INTERNAL,
                 ("User (%1$s) wasn't found in the cache", pc_username));
           ret = EXIT_FAILURE;
           goto end;
       } else {
          DEBUG(SSSDBG_TRACE_INTERNAL, ("User verified in cache\n"));
       }
    }

*/
    /* clean up */
done:
    ret = EXIT_SUCCESS;

end:
    poptFreeContext(pc);
    talloc_free(tctx);
    exit(ret);
}
