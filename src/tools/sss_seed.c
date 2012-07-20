#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <popt.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"
#include "confdb/confdb.h"

enum seed_pass_method {
    PASS_PROMPT,
    PASS_FILE
};

enum seed_input_type {
    STR_INPUT,
    ID_INPUT
};

#ifndef BUFSIZE
#define BUFSIZE 1024

int seed_str_input(TALLOC_CTX *mem_ctx,
               const char *req,
               char **_input)
{
    TALLOC_CTX *temp_ctx = NULL;
    char buf[BUFSIZE+1];
    size_t len = 0;
    int ret = EOK;

    temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, BUFSIZE);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("read failed [%d][%s].\n",
                                    ret, strerror(ret)));
        goto done;
    }

    if (len == BUFSIZE) {
        DEBUG(SSSDBG_TRACE_FUNC, ("input may exceed allowed buffer size\n"));
    }

    buf[len] = '\0';

    *_input = talloc_strdup(temp_ctx, buf);
    if (*_input == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate input\n"));
        goto done;
    }

    *_input = talloc_steal(mem_ctx, *_input);

done:
    talloc_free(temp_ctx);
    return ret;
}

int seed_id_input(TALLOC_CTX *mem_ctx,
                  const char *req,
                  uid_t *_id_input)
{
    TALLOC_CTX *temp_ctx = NULL;
    char buf[BUFSIZE+1];
    size_t len = 0;
    char *endptr = NULL;
    int ret = EOK;

    temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, BUFSIZE);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("read failed [%d][%s].\n",
                                    ret, strerror(ret)));
        goto done;
    }

    if (isdigit(*buf)) {
        errno = 0;
        *_id_input = (uid_t)strtoll((char *)buf, &endptr, 10);
        if (errno != 0) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE, ("strtoll failed on [%s]: [%d][%s].\n",
                                      (char *)buf, ret, strerror(ret)));
            goto done;
        }
        if (*endptr != '\0') {
            DEBUG(SSSDBG_MINOR_FAILURE, ("extra characters [%s] after "
                                         "UID [%d]\n", endptr, *_id_input));
        }
    } else {
        ret = EINVAL;
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get %s input.\n", req));
        goto done;
    }

done:
    talloc_free(temp_ctx);
    return ret;
}
#ifndef PASS_MAX
#define PASS_MAX 64

int seed_password_input(TALLOC_CTX *mem_ctx,
                   enum seed_pass_method method,
                   char *filename,
                   char **password)
{
    TALLOC_CTX *temp_ctx = NULL;
    char *temp = NULL;
    int len = 0;
    uint8_t buf[PASS_MAX+1];
    int fd = -1;
    int ret = EOK;

    temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate temp context\n"));
        ret = ENOMEM;
        goto done;
    }


    if (method == PASS_FILE) {
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to open password file "
                                        "[%s][%d][%s]\n",
                                        filename, errno, strerror(errno)));
            ret = EINVAL;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL,("pass_max = PASS_MAX"));

        errno = 0;
        len = sss_atomic_read_s(fd, buf, PASS_MAX);
        if (len == -1) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to read password from file "
                                         "[%s][%d][%s]\n",
                                         filename, ret, strerror(ret)));
            close(fd);
            goto done;
        }
        close(fd);

   } else {
        temp = getpass("Enter temporary password:");
        if (temp == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get prompted password\n"));
            ret = EINVAL;
            goto done;
        }
        *password = talloc_strdup(temp_ctx, temp);
        talloc_set_destructor((TALLOC_CTX *)*password, password_destructor);

        temp = getpass("Enter temporary password again:");
        if (temp == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get prompted password\n"));
            ret = EINVAL;
            goto done;
        }

        if (strncmp(temp,*password,strlen(*password)) != 0) {
            fprintf(stderr, _("Passowrds do not match\n"));
            DEBUG(SSSDBG_MINOR_FAILURE, ("Provided passwords do not match\n"));
            goto done;
        }
    }

    *password = talloc_steal(mem_ctx, *password);

done:
    talloc_free(temp_ctx);
    return ret;
}
#endif /* PASS_MAX */
#endif /* BUFSIZE */

int seed_interactive_input(struct tools_ctx *tctx, char **groups)
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

int seed_init_db(TALLOC_CTX *mem_ctx,
                 char* domain_name,
                 struct confdb_ctx **confdb,
                 struct sysdb_ctx **sysdb,
                 struct sss_domain_info **domain)
{
    TALLOC_CTX *temp_ctx = NULL;
    char *confdb_path = NULL;
    int ret = EOK;

    temp_ctx = talloc_new(NULL);
    if (temp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate seed init context\n"));
        ret = ENOMEM;
        goto done;
    }

    /* setup confdb */
    confdb_path = talloc_asprintf(temp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_init(temp_ctx, confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the confdb\n"));
        goto done;
    }
    *confdb = talloc_steal(mem_ctx, *confdb);

    /* set up domain and sysdb */
    if (domain_name) {
        DEBUG(SSSDBG_FUNC_DATA, ("Domain provided: [%s]\n", domain_name));
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Domain must be specified.\n"));
        fprintf(stderr, "No Domain provided.\n");
        ret = EINVAL;
        goto done;
    }

    ret = confdb_get_domain(*confdb, domain_name, domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Error retrieving domain [%s] from confdb\n",
                                  domain_name));
        goto done;
    }

    ret = sysdb_init_domain_and_sysdb(temp_ctx, *confdb, domain_name,
                                      DB_PATH, domain, sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the sysdb\n"));
        goto done;
    }
    *domain = talloc_steal(mem_ctx, *domain);
    *sysdb = talloc_steal(mem_ctx, *sysdb);

done:
    talloc_free(temp_ctx);
    return ret;
}

int seed_check_groups(struct tools_ctx *tctx,
                      char *groups,
                      char **badgroup)
{
    int ret = EOK;

    ret = sss_names_init(tctx, tctx->confdb, tctx->octx->domain->name,
                         &tctx->snctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to init names context\n"));
        goto done;
    }

    ret = parse_groups(tctx, groups, &tctx->octx->addgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot parse groups to add the user to\n"));
        ret = EXIT_FAILURE;
        goto done;
    }

    ret = parse_group_name_domain(tctx, tctx->octx->addgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot parse FQDN groups to add user to"));
        ret = EXIT_FAILURE;
        goto done;
    }

    ret = check_group_names(tctx, tctx->octx->addgroups, badgroup);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot find group [%s] in domain [%s]\n",
                                  badgroup, tctx->octx->domain->name));
        ret = EXIT_FAILURE;
        goto done;
    }

done:
    return ret;
}

int main(int argc, const char **argv)
{
    int seed_debug = SSSDBG_DEFAULT;
    bool interact = false;
    bool in_transaction = false;
    bool user_cached = false;
    const char* uname = NULL;
    char *groups = NULL;
    char *badgroup = NULL;
    char *domain = NULL;
    char *password = NULL;
    enum seed_pass_method password_method = PASS_PROMPT;
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

    poptContext pc = NULL;
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
                DEBUG(SSSDBG_TRACE_INTERNAL, ("Interactive mode selected\n"));
                interact = true;
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

    poptFreeContext(pc);

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

    /* get user info from domain */
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

    /* set up confdb,sysdb and domain */
    ret = seed_init_db(tctx, domain,  &tctx->confdb, &tctx->sysdb,
                       &tctx->octx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to initialize db and domain\n"));
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
    } else if (res->count == 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("User found in cache\n"));
        user_cached = true;
    } else {
        /* multiple user entries in cache */
        ret = EXIT_FAILURE;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Multiple user (%s) entries were "
                                    "found in the cache\n", tctx->octx->name));
        goto done;
    }

    /* interactive mode to fill in user information */
    if (interact == true && user_cached == false) {
        ret = seed_interactive_input(tctx, &groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get seed input.\n"));
            ret = EXIT_FAILURE;
            goto done;
        }
    } else if (tctx->octx->uid == 0 || tctx->octx->gid == 0) {
            /* require username, UID, and GID to continue */
            DEBUG(SSSDBG_MINOR_FAILURE, ("Not enough information provided\n"));
            ret = EXIT_FAILURE;
            goto done;
    }

    /* Check domains/groups exist for user to be created */
    if (groups != NULL) {
        ret = seed_check_groups(tctx, groups, &badgroup);
        if (ret != EOK) {
            goto done;
        }
    }

    /* password input */
    ret = seed_password_input(tctx, password_method, password_file, &password);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Password input failure\n"));
        goto done;
    }

    /* Add user info and password to sysdb cache */
    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb transaction start failure\n"));
        goto done;
    }

    in_transaction = true;

    if (user_cached == false) {
        tctx->error = sysdb_add_user(tctx->sysdb, tctx->octx->name,
                                     tctx->octx->uid, tctx->octx->gid,
                                     tctx->octx->gecos, tctx->octx->home,
                                     tctx->octx->shell, NULL, 0, 0);
        if (tctx->error) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to add user to the cache\n"));
            goto done;
        }
    }

    ret = sysdb_cache_password(tctx->sysdb, tctx->octx->name, password);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to cache password. (%d)[%s]\n",
                                  ret, strerror(ret)));
        fprintf(stderr, _("Failed to cache password\n"));
        goto done;
    }

    tctx->error = sysdb_transaction_commit(tctx->sysdb);
    if (tctx->error) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb transaction commit failure\n"));
        goto done;
    }

    in_transaction = false;

    ret = EXIT_SUCCESS;

done:
    if (in_transaction) {
        ret = sysdb_transaction_cancel(tctx->sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to cancel transaction\n"));
        }
    }

    talloc_free(tctx);
    exit(ret);
}
