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

struct user_ctx {
    char *domain_name;

    char *name;
    uid_t uid;
    gid_t gid;
    char *gecos;
    char *home;
    char *shell;
    char *groups;

    char *password;

    char **addgroups;
};

struct seed_ctx {
    struct confdb_ctx *confdb;
    struct sysdb_ctx *sysdb;

    struct sss_names_ctx *snctx;
    struct sss_domain_info *domain;

    struct user_ctx *uctx;

    char *password_file;
    enum seed_pass_method password_method;

    bool interact;
    bool transaction_done;
    bool user_cached;
    int error;
};


static int seed_prompt(const char *req)
{
    TALLOC_CTX *tmp_ctx = NULL;
    size_t len = 0;
    size_t index = 0;
    char *prompt = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    prompt = talloc_asprintf(tmp_ctx, _("Enter %s:"), req);
    if (prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    while (prompt[index] != '\0') {
       errno = 0;
       len = sss_atomic_write_s(STDOUT_FILENO, &prompt[index++], 1);
       if (len == -1) {
           ret = errno;
           DEBUG(SSSDBG_CRIT_FAILURE, ("write failed [%d][%s].\n",
                                       ret, strerror(ret)));
           goto done;
       }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

#ifndef BUFSIZE
#define BUFSIZE 1024

static int seed_str_input(TALLOC_CTX *mem_ctx,
                          const char *req,
                          char **_input)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char buf[BUFSIZE+1];
    size_t len = 0;
    size_t bytes_read = 0;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = seed_prompt(req);
    if (ret != EOK) {
        goto done;
    }

    errno = 0;
    while ((bytes_read = sss_atomic_read_s(STDIN_FILENO, buf+len, 1)) != 0) {
        if (bytes_read == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, ("read failed [%d][%s].\n",
                                        ret, strerror(ret)));
            goto done;
        }
        if (buf[len] == '\n' || len == BUFSIZE) {
            buf[len] = '\0';
            break;
        }
        len += bytes_read;
    }

    *_input = talloc_strdup(tmp_ctx, buf);
    if (*_input == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate input\n"));
        goto done;
    }

    *_input = talloc_steal(mem_ctx, *_input);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int seed_id_input(const char *req,
                         uid_t *_id_input)
{
    char buf[BUFSIZE+1];
    size_t len = 0;
    size_t bytes_read = 0;
    char *endptr = NULL;
    int ret = EOK;

    ret = seed_prompt(req);
    if (ret != EOK) {
        goto done;
    }

    errno = 0;
    while ((bytes_read = sss_atomic_read_s(STDIN_FILENO, buf+len, 1)) != 0) {
        if (bytes_read == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, ("read failed [%d][%s].\n",
                                        ret, strerror(ret)));
            goto done;
        }
        if (buf[len] == '\n' || len == BUFSIZE) {
            buf[len] = '\0';
            break;
        }
        len += bytes_read;
    }

    if (isdigit(*buf)) {
        errno = 0;
        *_id_input = (uid_t)strtoll(buf, &endptr, 10);
        if (errno != 0) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE, ("strtoll failed on [%s]: [%d][%s].\n",
                                      (char *)buf, ret, strerror(ret)));
            goto done;
        }
        if (*endptr != '\0') {
            DEBUG(SSSDBG_MINOR_FAILURE, ("extra characters [%s] after "
                                         "ID [%d]\n", endptr, *_id_input));
        }
    } else {
        ret = EINVAL;
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get %s input.\n", req));
        goto done;
    }

done:
    return ret;
}
#ifndef PASS_MAX
#define PASS_MAX 64

static int seed_password_input(TALLOC_CTX *mem_ctx,
                               enum seed_pass_method method,
                               char *filename,
                               char **_password)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *password = NULL;
    char *temp = NULL;
    int len = 0;
    uint8_t buf[PASS_MAX+1];
    int fd = -1;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
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
        buf[len] = '\0';

        password = talloc_strdup(tmp_ctx, (char *)buf);
        if (password == NULL) {
            ret = ENOMEM;
            goto done;
        }

   } else {
        temp = getpass("Enter temporary password:");
        if (temp == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to get prompted password\n"));
            ret = EINVAL;
            goto done;
        }
        password = talloc_strdup(tmp_ctx, temp);
        if (password == NULL) {
            ret = ENOMEM;
            goto done;
        }

        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        temp = getpass("Enter temporary password again:");
        if (temp == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to get prompted password\n"));
            ret = EINVAL;
            goto done;
        }

        if (strncmp(temp,password,strlen(password)) != 0) {
            fprintf(stderr, _("Passwords do not match\n"));
            DEBUG(SSSDBG_MINOR_FAILURE, ("Provided passwords do not match\n"));
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_ALL, ("Password: [%s]\n", password));

    *_password = talloc_steal(mem_ctx, password);

done:
    talloc_free(tmp_ctx);
    return ret;
}
#endif /* PASS_MAX */
#endif /* BUFSIZE */

static int seed_interactive_input(struct seed_ctx *sctx)
{
    int ret = EOK;

    if (sctx->uctx->name == NULL) {
        ret = seed_str_input(sctx, _("username"), &sctx->uctx->name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Username interactive input failed.\n"));        
            goto done;
        }
    }

    if (sctx->uctx->uid == 0) {
        ret = seed_id_input(_("UID"), &sctx->uctx->uid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("UID interactive input failed.\n"));
            goto done;
        }
    }

    if (sctx->uctx->gid == 0) {
        ret = seed_id_input(_("GID"), &sctx->uctx->gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("GID interactive input failed.\n"));
            goto done;
        }
    }

    if (sctx->uctx->gecos == NULL) {
        ret = seed_str_input(sctx, _("user comment (gecos)"),
                             &sctx->uctx->gecos);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Gecos interactive input failed.\n"));
            goto done;
        }
    }

    if (sctx->uctx->home == NULL) {
        ret = seed_str_input(sctx, _("home directory"), &sctx->uctx->home);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Home directory interactive input fialed.\n"));
            goto done;
        }
    }

    if (sctx->uctx->shell == NULL) {
        ret = seed_str_input(sctx, _("user login shell"), &sctx->uctx->shell);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Shell interactive input failed\n"));
            goto done;
        }
    }

    if (sctx->uctx->groups == NULL) {
        ret = seed_str_input(sctx, _("user groups"), &sctx->uctx->groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("User groups interactive input failed.\n"));
            goto done;
        }
    }

done:
    return ret;
}

static int seed_init(const int argc,
                     const char **argv,
                     struct seed_ctx **_sctx)
{
    TALLOC_CTX *tmp_ctx = NULL;

    int pc_debug = 0xfff0;
    const char *pc_domain = NULL;
    const char *pc_name = NULL;
    const char *temp_name = NULL;
    uid_t pc_uid = 0;
    gid_t pc_gid = 0;
    const char *pc_gecos = NULL;
    const char *pc_home = NULL;
    const char *pc_shell = NULL;
    const char *pc_groups = NULL;
    const char *pc_password_file = NULL;

    struct seed_ctx *sctx = NULL;

    int ret = EOK;

    poptContext pc = NULL;
    struct poptOption options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
         _("The debug level to run with"), NULL },
        { "domain", 'D', POPT_ARG_STRING, &pc_domain, 0, _("Domain"), NULL },
        { "username", 'n', POPT_ARG_STRING, &pc_name, 0,
         _("Username"), NULL},
        { "uid",   'u', POPT_ARG_INT, &pc_uid, 0,
         _("User UID"), NULL },
        { "gid",   'g', POPT_ARG_INT, &pc_gid, 0,
         _("User GID"), NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0,
         _("Comment string"), NULL},
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0,
         _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0,
         _("Login Shell"), NULL },
        { "groups", 'G', POPT_ARG_STRING, NULL, 'G', _("Groups"), NULL },
        { "interactive", 'i', POPT_ARG_NONE, NULL, 'i',
         _("Use interactive mode to enter user data"), NULL },
        { "password-file", 'p', POPT_ARG_STRING, &pc_password_file, 0,
         _("File from which user's password is read "
           "(default is to prompt for password)"),NULL },
        POPT_TABLEEND
    };

    /* init contexts */
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto fini;
    }

    sctx = talloc_zero(tmp_ctx, struct seed_ctx);
    if (sctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate tools context\n"));
        ret = ENOMEM;
        goto fini;
    }

    sctx->uctx = talloc_zero(sctx, struct user_ctx);
    if (sctx->uctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate user data context\n"));
        ret = ENOMEM;
        goto fini;
    }

    debug_prg_name = argv[0];
    debug_level = debug_convert_old_level(pc_debug);

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("set_locale failed (%d): %s\n",
                                    ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    CHECK_ROOT(ret, argv[0]);

    /* parse arguments */
    pc = poptGetContext(NULL, argc, argv, options, 0);
    if (argc < 2) {
        poptPrintUsage(pc,stderr,0);
        ret = EXIT_FAILURE;
        goto fini;
    }

    poptSetOtherOptionHelp(pc, "[OPTIONS] -D <domain> <username>");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'G':
                pc_groups = poptGetOptArg(pc);
                if (pc_groups == NULL) {
                    BAD_POPT_PARAMS(pc, _("Specify group to add user to\n"),
                                    ret, fini);
                }
                break;
            case 'i':
                DEBUG(SSSDBG_TRACE_INTERNAL, ("Interactive mode selected\n"));
                sctx->interact = true;
                break;
        }
    }

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    /* username is standalone argument */
    temp_name = poptGetArg(pc);
    if (pc_name == NULL && temp_name == NULL) {
        BAD_POPT_PARAMS(pc, _("Username must be specified\n"), ret, fini);
    } else if (pc_name != NULL) {
        sctx->uctx->name = talloc_strdup(sctx, pc_name);
    } else {
        sctx->uctx->name = talloc_strdup(sctx, temp_name);
    }

    if (sctx->uctx->name == NULL) {
        ret = ENOMEM;
        goto fini;
    }

    /* check domain is provided */
    if (pc_domain == NULL) {
        BAD_POPT_PARAMS(pc, _("Domain must be specified.\n"), ret, fini);
    } else {
        DEBUG(SSSDBG_FUNC_DATA,
              ("Domain provided: [%s]\n", pc_domain));
    }

    sctx->uctx->domain_name = talloc_strdup(sctx, pc_domain);
    if (sctx->uctx->domain_name == NULL) {
        ret = ENOMEM;
        goto fini;
    }

    poptFreeContext(pc);

    ret = EOK;

    /* copy all information provided from popt */
    sctx->uctx->uid = pc_uid;
    sctx->uctx->gid = pc_gid;
    if (pc_gecos != NULL) {
        sctx->uctx->gecos = talloc_strdup(sctx, pc_gecos);
        if (sctx->uctx->gecos == NULL) {
            ret = ENOMEM;
            goto fini;
        }
    }
    if (pc_home != NULL) {
        sctx->uctx->home = talloc_strdup(sctx, pc_home);
        if (sctx->uctx->home == NULL) {
            ret = ENOMEM;
            goto fini;
        }
    }
    if (pc_shell != NULL) {
        sctx->uctx->shell = talloc_strdup(sctx, pc_shell);
        if (sctx->uctx->shell == NULL) {
            ret = ENOMEM;
            goto fini;
        }
    }
    if (pc_groups != NULL) {
        sctx->uctx->groups = talloc_strdup(sctx, pc_groups);
        if (sctx->uctx->groups == NULL) {
            ret = ENOMEM;
            goto fini;
        }
    }

    /* check if password file provided */
    if (pc_password_file != NULL) {
        sctx->password_file = talloc_strdup(sctx, pc_password_file);
        if (sctx->password_file == NULL) {
            ret = ENOMEM;
            goto fini;
        }
        sctx->password_method = PASS_FILE;
    }

    *_sctx = talloc_steal(NULL, sctx);

fini:
    talloc_free(tmp_ctx);
    return ret;
}

static int seed_init_db(TALLOC_CTX *mem_ctx,
                        char* domain_name,
                        struct confdb_ctx **confdb,
                        struct sysdb_ctx **sysdb,
                        struct sss_domain_info **domain)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *confdb_path = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* setup confdb */
    confdb_path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_init(tmp_ctx, confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the confdb\n"));
        goto done;
    }
    *confdb = talloc_steal(mem_ctx, *confdb);

    ret = confdb_get_domain(*confdb, domain_name, domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Error retrieving domain [%s] from confdb\n",
                                  domain_name));
        goto done;
    }

    ret = sysdb_init_domain_and_sysdb(tmp_ctx, *confdb, domain_name,
                                      DB_PATH, domain, sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the sysdb\n"));
        goto done;
    }
    *domain = talloc_steal(mem_ctx, *domain);
    *sysdb = talloc_steal(mem_ctx, *sysdb);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int seed_dom_user_info(TALLOC_CTX *mem_ctx,
                              char *name,
                              struct user_ctx *uctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct passwd *passwd = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    passwd = getpwnam(name);
    if (passwd == NULL) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, ("getpwnam failed [%d] [%s]\n",
                                     ret, strerror(ret)));
        goto done;
    }

    uctx->gid = passwd->pw_gid;
    uctx->uid = passwd->pw_uid;
    uctx->name = talloc_strdup(tmp_ctx, passwd->pw_name);
    if (uctx->name == NULL) {
        ret = ENOMEM;
        goto done;
    }
    uctx->gecos = talloc_strdup(tmp_ctx, passwd->pw_gecos);
    if (uctx->gecos == NULL) {
        ret = ENOMEM;
        goto done;
    }
    uctx->home = talloc_strdup(tmp_ctx, passwd->pw_dir);
    if (uctx->home == NULL) {
        ret = ENOMEM;
        goto done;
    }
    uctx->shell = talloc_strdup(tmp_ctx, passwd->pw_shell);
    if (uctx->shell == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = initgroups(name, uctx->gid);
    if (ret == -1) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("initgroups failure\n"));
        goto done;
    }

    uctx->name = talloc_steal(mem_ctx, uctx->name);
    uctx->gecos = talloc_steal(mem_ctx, uctx->gecos);
    uctx->home = talloc_steal(mem_ctx, uctx->home);
    uctx->shell = talloc_steal(mem_ctx, uctx->shell);

done:
    if (ret == ENOMEM) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate user information\n"));
    }
    talloc_free(tmp_ctx);
    return ret;
}

static int seed_check_groups(struct seed_ctx *sctx, char *groups)
{
    int i = 0;
    char *name = NULL;
    char *domain = NULL;
    struct ops_ctx *groupinfo = NULL;
    int ret = EOK;

    ret = sss_names_init(sctx, sctx->confdb, sctx->uctx->domain_name,
                         &sctx->snctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to init names context\n"));
        return ret;
    }

    ret = parse_groups(sctx, groups, &sctx->uctx->addgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot parse groups to add the user to\n"));
        return ret;
    }

    if (sctx->uctx->addgroups != NULL) {
        for (i = 0; sctx->uctx->addgroups[i]; ++i) {
             ret = sss_parse_name(sctx, sctx->snctx, sctx->uctx->addgroups[i],
                                  &domain, &name);
             if (ret != EOK) {
                 DEBUG(SSSDBG_CRIT_FAILURE,
                       ("Invalid name in group list, skipping: [%s] (%d)\n",
                        sctx->uctx->addgroups[i], ret));
                 continue;
             }

             /* If FQDN specified, it must be within the same domain as user */
             if (domain != NULL) {
                 if (strcmp(domain,sctx->uctx->domain_name) != 0) {
                     return EINVAL;
                 }
                 
                 /* only use groupname */
                 talloc_zfree(sctx->uctx->addgroups[i]);
                 sctx->uctx->addgroups[i] = talloc_strdup(sctx, name);
                 if (sctx->uctx->addgroups[i] == NULL) {
                     return ENOMEM;
                 }
             }

             talloc_zfree(name);
             talloc_zfree(domain);
         }

         talloc_zfree(name);
         talloc_zfree(domain);
    }

    groupinfo = talloc_zero(sctx, struct ops_ctx);
    if (groupinfo == NULL) {
        return ENOMEM;
    }

    for (i = 0; sctx->uctx->addgroups[i]; ++i) {
        ret = sysdb_getgrnam_sync(sctx,
                                  sctx->sysdb,
                                  sctx->uctx->addgroups[i],
                                  groupinfo);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("Cannot find group [%s] in domain [%s].\n",
                   sctx->uctx->addgroups[i], sctx->uctx->domain_name));
            break;
        }
    }

    talloc_zfree(groupinfo);
    return ret;
}

static int seed_cache_user(struct seed_ctx *sctx)
{
    int ret = EOK;

    ret = sysdb_transaction_start(sctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb transaction start failure\n"));
        goto done;
    }

    sctx->transaction_done = false;

    if (sctx->user_cached == false) {
        ret = sysdb_add_user(sctx->sysdb, sctx->uctx->name,
                             sctx->uctx->uid, sctx->uctx->gid,
                             sctx->uctx->gecos, sctx->uctx->home,
                             sctx->uctx->shell, NULL, 0, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to add user to the cache. (%d)[%s]\n",
                   ret, strerror(ret)));
            ERROR("Failed to create user cache entry\n");
            goto done;
        }
    }

    ret = sysdb_cache_password(sctx->sysdb, sctx->uctx->name,
                               sctx->uctx->password);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to cache password. (%d)[%s]\n",
                                  ret, strerror(ret)));
        fprintf(stderr, _("Failed to cache password\n"));
        goto done;
    }

    ret = sysdb_transaction_commit(sctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb transaction commit failure\n"));
        goto done;
    }

    sctx->transaction_done = true;

done:
    if (sctx->transaction_done == false) {
        ret = sysdb_transaction_cancel(sctx->sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to cancel transaction\n"));
        }
    }

    return ret;
}

int main(int argc, const char **argv)
{
    struct seed_ctx *sctx = NULL;
    struct ldb_result *res = NULL;
    int ret = EOK;

    /* initialize seed context and parse options */
    ret = seed_init(argc, argv, &sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,("Seed init failed [%d][%d]\n",
                                 ret, strerror(ret)));
        goto done;
    }


    /* get user info from domain */
    ret = seed_dom_user_info(sctx, sctx->uctx->name, sctx->uctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed lookup of user [%s] in domain [%s]",
                                  sctx->uctx->name, sctx->uctx->domain_name));
    }

    /* set up confdb,sysdb and domain */
    ret = seed_init_db(sctx, sctx->uctx->domain_name, &sctx->confdb,
                       &sctx->sysdb, &sctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to initialize db and domain\n"));
        goto done;
    }

    /* look for user in cache */
    ret = sysdb_getpwnam(sctx, sctx->sysdb, sctx->uctx->name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Couldn't lookup user (%s) in the cache", sctx->uctx->name));
        ret = EXIT_FAILURE;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
                 ("User (%s) wasn't found in the cache\n", sctx->uctx->name));
        sctx->user_cached = false;
    } else if (res->count == 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("User found in cache\n"));
        sctx->user_cached = true;
    } else {
        /* multiple user entries in cache */
        ret = EXIT_FAILURE;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Multiple user (%s) entries were found in the cache\n",
               sctx->uctx->name));
        goto done;
    }

    /* interactive mode to fill in user information */
    if (sctx->user_cached == false) {
        if (sctx->interact == true) {
            ret = seed_interactive_input(sctx);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get seed input.\n"));
                ret = EXIT_FAILURE;
                goto done;
            }
        } else if (sctx->uctx->uid == 0 || sctx->uctx->gid == 0) {
            /* require username, UID, and GID to continue */
            DEBUG(SSSDBG_MINOR_FAILURE, ("Not enough information provided\n"));
            ret = EXIT_FAILURE;
            goto done;
        }
    }

    /* Check domains/groups exist for user to be created */
    if (sctx->uctx->groups != NULL) {
        ret = seed_check_groups(sctx, sctx->uctx->groups);
        if (ret != EOK) {
            goto done;
        }
    }

    /* password input */
    ret = seed_password_input(sctx, sctx->password_method,
                              sctx->password_file, &sctx->uctx->password);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Password input failure\n"));
        goto done;
    }

    /* Add user info and password to sysdb cache */
    ret = seed_cache_user(sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to modify cache.\n"));
        goto done;
    }

    ret = EXIT_SUCCESS;

done:
    if (sctx != NULL) {
        talloc_zfree(sctx->uctx);
    }
    talloc_free(sctx);
    exit(ret);
}
