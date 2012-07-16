#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"
#include "confdb/confdb.h"

#define PASS_PROMPT 0
#define PASS_FILE 1

#ifndef TEMP_LEN
#define TEMP_LEN 10

int seed_str_input(struct tools_ctx *mem_ctx, const char* req, char **_input)
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
 
    temp = talloc_zero_array(temp_ctx, char, TEMP_LEN);
    if (temp == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor((TALLOC_CTX *)temp, password_destructor);

    printf(_("Enter %1$s:"), req);
 
    while (fgets(temp, TEMP_LEN, stdin) != NULL){
        *_input = talloc_asprintf_append(*_input, "%s", temp);
        if (*_input == NULL) {
            ret = ENOMEM;
            goto done;
        }

        bytes_read = strlen(*_input);

        if ((*_input)[bytes_read-1] == '\n') {
            (*_input)[bytes_read-1] = '\0';
            break;
        }
    }

    ret = EOK;

done:
    talloc_free(temp_ctx);
    return ret;
}

int seed_id_input(TALLOC_CTX *mem_ctx, const char* req, uid_t *_input)
{
    int ret = EOK;
    TALLOC_CTX *temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    printf(_("Enter %1$s:"), req);

    scanf("%d", _input);

    char c = getchar();
    if (c != '\n') {
        ret = EXIT_FAILURE;
    }

done:
    talloc_free(temp_ctx);
    return ret;
}

/* read password from file, or prompt for it */
int password_input(int method, char *filename, char ** password)
{
    char* temp = NULL;
    int ret = EOK;
    FILE *finput = NULL;
    TALLOC_CTX *temp_ctx = NULL;

    temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate temp context\n"));
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
        finput = fopen(filename, "r");
        if (finput == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to open file [%s] for "
                                        "password\n", filename));
            ret = EINVAL;
            goto done;
        }

        while (fgets(temp, TEMP_LEN, finput) != NULL) {
            *password = talloc_asprintf_append(*password, "%s", temp);
            if (*password == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate password\n"));
                ret = ENOMEM;
                goto done;
            }
        }
    } else {
        *password = getpass("Enter password: ");
        if (*password == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get prompted password\n"));
            ret = EINVAL;
            goto done;
        }
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

    if (tctx->octx->name == NULL) {
        ret = seed_str_input(tctx, "username", &tctx->octx->name);
        if (ret != EOK) {
            goto done;
        }
    }

    if (tctx->octx->uid == 0) {
        ret = seed_id_input(tctx, "UID", &tctx->octx->uid);
        if (ret != EOK) {
            goto done;
        }
    }

    if (tctx->octx->gid == 0) {
        ret = seed_id_input(tctx, "GID", &tctx->octx->gid);
        if (ret != EOK) {
            goto done;
        }
    }

    if (tctx->octx->gecos == NULL) {
        ret = seed_str_input(tctx, "user comment (gecos)", &tctx->octx->gecos);
        if (ret != EOK) {
            goto done;
        }
    }

    if (tctx->octx->home == NULL) {
        ret = seed_str_input(tctx, "home directory", &tctx->octx->home);
        if (ret != EOK) {
            goto done;
        }
    }

    if (tctx->octx->shell == NULL) {
        ret = seed_str_input(tctx, "user login shell", &tctx->octx->shell);
        if (ret != EOK) {
            goto done;
        }
    }

    if (*groups == NULL) {
        ret = seed_str_input(tctx, "user groups", groups);
        if (ret != EOK) {
            goto done;
        }
    }

done:
    return ret;
}

int main(int argc, const char **argv)
{
    int seed_debug = SSSDBG_DEFAULT;
    int interact = 0;
    bool in_transaction = false;
    const char* uname = NULL;
    char *groups = NULL;
    char *badgroup = NULL;
    char *domain = NULL;
    char *password = NULL;
    int password_method = PASS_PROMPT;
    char *password_file = NULL;
    struct passwd *pc_passwd = NULL;
    struct ldb_result *res = NULL;

    int ret;

    struct tools_ctx *tctx = NULL;
    tctx = talloc_zero(NULL, struct tools_ctx);
    if (tctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate tools context\n"));
        ret = ENOMEM;
        goto done;
    }

    tctx->octx = talloc_zero(tctx, struct ops_ctx);
    if (tctx->octx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate data context\n"));
        ret = ENOMEM;
        goto done;
    }

    struct poptOption options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &seed_debug, 0,
         _("The debug level to run with"), NULL },
        { "domain", 'D', POPT_ARG_STRING, &domain, 0, _("Domain"), NULL },
        { "username", 'n', POPT_ARG_STRING, &tctx->octx->name, 0,
         _("Username"), NULL},
        { "uid",   'u', POPT_ARG_INT, &tctx->octx->uid, 0,
         _("User UID"), NULL },
        { "gid",   'g', POPT_ARG_INT, &tctx->octx->gid, 0,
         _("User GID"), NULL },
        { "gecos", 'c', POPT_ARG_STRING, &tctx->octx->gecos, 0,
         _("Comment string"), NULL},
        { "home",  'h', POPT_ARG_STRING, &tctx->octx->home, 0,
         _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &tctx->octx->shell, 0,
         _("Login Shell"), NULL },
        { "groups", 'G', POPT_ARG_STRING, NULL, 'G', _("Groups"), NULL },
        { "interactive", 'i', POPT_ARG_NONE, NULL, 'i',
         _("Use interactive mode to enter user data"), NULL },
        { "password-file", 'p', POPT_ARG_STRING, &password_file, 0,
         _("File from which user's password is read "
           "(default is to prompt for password)"),NULL },
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
        goto done;
    }

    /* parse arguments */
    pc = poptGetContext(NULL, argc, argv, options, 0);
    if (argc < 2) {
        poptPrintUsage(pc,stderr,0);
        ret = EXIT_FAILURE;
        goto done;
    }

    poptSetOtherOptionHelp(pc, "[OPTIONS] -D <domain> <username>");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'G':
                groups = poptGetOptArg(pc);
                if (!groups) {
                    BAD_POPT_PARAMS(pc, _("Specify group to add user to\n"),
                                          ret, done);
                }
                break;
            case 'i':
                DEBUG(SSSDBG_TRACE_INTERNAL, ("Interactive mode slected\n"));
                interact = 1;
                break;
        }
    }

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, done);
    }

    /* username is standalone argument */
    uname = poptGetArg(pc);
    if (uname == NULL && tctx->octx->name == NULL) {
        BAD_POPT_PARAMS(pc, _("Username must be specified\n"), ret, done);
    } else if (uname != NULL) {
        tctx->octx->name = talloc_strdup(tctx,uname);
        if (tctx->octx->name == NULL) {
            ret = ENOMEM;
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate username\n"));
            goto done;
        }
    }

    /* check if passwordfile was provided */
    if (password_file != NULL) {
        password_method = PASS_FILE;
    }

    /* check if root */
    ret = getuid();
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Running under uid %d, must be root\n", ret));
        ret = EXIT_FAILURE;
        goto done;
    }

    /* getpwnam and initgroups */
    pc_passwd = getpwnam(tctx->octx->name);
    if (pc_passwd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getpwnam failed; user entry not found or allocation error\n"));
    } else {
        tctx->octx->name = pc_passwd->pw_name;
        tctx->octx->gid = pc_passwd->pw_gid;
        tctx->octx->uid = pc_passwd->pw_uid;
        tctx->octx->gecos = pc_passwd->pw_gecos;
        tctx->octx->home = pc_passwd->pw_dir;
        tctx->octx->shell = pc_passwd->pw_shell;

        ret = initgroups(tctx->octx->name, tctx->octx->gid);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, ("initgroups failure\n"));
        }
    }


    /* setup confdb */
    char *confdb_path = talloc_asprintf(tctx, "%s/%s", DB_PATH,
                                        CONFDB_FILE);
    if (confdb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_init(tctx, &tctx->confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not inittialize connection to the confdb\n"));
        goto done;
    }

    /* set up domain and sysdb */
    if (domain) {
        DEBUG(SSSDBG_FUNC_DATA, ("Domain provided: [%s]\n", domain));
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Domain must be specified.\n"));
        ret = EINVAL;
        goto done;
    }

    ret = confdb_get_domain(tctx->confdb, domain, &tctx->octx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Error retrieving domain [%s] from confdb\n",
                                  domain));
        goto done;
    }

    ret = sysdb_init_domain_and_sysdb(tctx, tctx->confdb, domain,
                                      DB_PATH, &tctx->octx->domain,
                                      &tctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the sysdb\n"));
        goto done;
    }

    /* look for user in cache */
    ret = sysdb_getpwnam(tctx, tctx->sysdb, tctx->octx->name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Couldn't lookup user (%s) in the cache", tctx->octx->name));
        ret = EXIT_FAILURE;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
                 ("User (%s) wasn't found in the cache\n", tctx->octx->name));
        interact = 1;
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("User found in cache\n"));
        /* get temporary password and cache the password if user is cached*/
        ret = password_input(password_method, password_file, &password);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Password input failure\n"));
            goto done;
        }

        ret = sysdb_cache_password(tctx->sysdb, tctx->octx->name, password);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to cache password. (%d)[%s]\n",
                                  ret, strerror(ret)));
        } else {
            goto done;
        }
    }

    /* interactive mode to fill in user seed info */
    if (interact) {
        ret = get_seed_input(tctx, &groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get seed input.\n"));
            ret = EXIT_FAILURE;
            goto done;
        }
    }

    /* Check domains/groups exist for user to be created */
    if (groups) {
        ret = sss_names_init(tctx, tctx->confdb, domain, &tctx->snctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to init names context\n"));
            goto done;
        }

        ret = parse_groups(tctx, groups, &tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Cannot parse groups to add the user to\n"));
            ERROR("Internal error while parsing parameters\n");
            ret = EXIT_FAILURE;
            goto done;
        }

        ret = parse_group_name_domain(tctx, tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Cannot parse FQDN groups to add user to"));
            ERROR("Groups must be in the same domain as user\n");
            ret = EXIT_FAILURE;
            goto done;
        }

        ret = check_group_names(tctx, tctx->octx->addgroups, &badgroup);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Cannot find group %s in domain\n",
                                      badgroup));
            ret = EXIT_FAILURE;
            goto done;
        }
    }

    /* password input */
    ret = password_input(password_method, password_file, &password);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Password input failure\n"));
        goto done;
    }

    /* Add user info and password to sysdb cache */
    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        goto done;
    }

    in_transaction = true;

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

    in_transaction = false;

    /* check user was added to the cache */
    ret = sysdb_getpwnam(tctx, tctx->sysdb, tctx->octx->name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Couldn't lookup user (%s) in the cache\n", tctx->octx->name));
        ret = EXIT_FAILURE;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
                 ("User (%1$s) wasn't found in the cache\n", tctx->octx->name));
        ret = EXIT_FAILURE;
        goto done;
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("User found in cache\n"));
    }

    ret = EXIT_SUCCESS;

done:
    if (in_transaction) {
        ret = sysdb_transaction_cancel(tctx->sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to cancel transaction\n"));
        }
    }

    poptFreeContext(pc);
    talloc_free(tctx);
    exit(ret);
}
