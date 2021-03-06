/*
    SSSD

    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2008-2011 Simo Sorce <ssorce@redhat.com>
    Copyright (C) 2008-2011 Stephen Gallagher

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

#include "util/util.h"
#include "db/sysdb_private.h"

static int finish_upgrade(int result, struct ldb_context *ldb,
                          const char *next_ver, const char **ver)
{
    int ret = result;
    int lret;

    if (ret == EOK) {
        lret = ldb_transaction_commit(ldb);
        ret = sysdb_error_to_errno(lret);
        if (ret == EOK) {
            *ver = next_ver;
        }
    }

    if (ret != EOK) {
        lret = ldb_transaction_cancel(ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not cancel transaction! [%s]\n",
                   ldb_strerror(lret)));
            /* Do not overwrite ret here, we want to return
             * the original failure, not the failure of the
             * transaction cancellation.
             */
        }
    }

    return ret;
}

/* serach all groups that have a memberUid attribute.
 * change it into a member attribute for a user of same domain.
 * remove the memberUid attribute
 * add the new member attribute
 * finally stop indexing memberUid
 * upgrade version to 0.2
 */
int sysdb_upgrade_01(struct ldb_context *ldb, const char **ver)
{
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *basedn;
    struct ldb_dn *mem_dn;
    struct ldb_message *msg;
    const struct ldb_val *val;
    const char *filter = "(&(memberUid=*)(objectclass=group))";
    const char *attrs[] = { "memberUid", NULL };
    const char *mdn;
    char *domain;
    int ret, i, j;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!basedn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_SUBTREE,
                     attrs, "%s", filter);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        el = ldb_msg_find_element(res->msgs[i], "memberUid");
        if (!el) {
            DEBUG(1, ("memberUid is missing from message [%s], skipping\n",
                      ldb_dn_get_linearized(res->msgs[i]->dn)));
            continue;
        }

        /* create modification message */
        msg = ldb_msg_new(tmp_ctx);
        if (!msg) {
            ret = ENOMEM;
            goto done;
        }
        msg->dn = res->msgs[i]->dn;

        ret = ldb_msg_add_empty(msg, "memberUid", LDB_FLAG_MOD_DELETE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_msg_add_empty(msg, SYSDB_MEMBER, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        /* get domain name component value */
        val = ldb_dn_get_component_val(res->msgs[i]->dn, 2);
        domain = talloc_strndup(tmp_ctx, (const char *)val->data, val->length);
        if (!domain) {
            ret = ENOMEM;
            goto done;
        }

        for (j = 0; j < el->num_values; j++) {
            mem_dn = ldb_dn_new_fmt(tmp_ctx, ldb, SYSDB_TMPL_USER,
                                    (const char *)el->values[j].data, domain);
            if (!mem_dn) {
                ret = ENOMEM;
                goto done;
            }

            mdn = talloc_strdup(msg, ldb_dn_get_linearized(mem_dn));
            if (!mdn) {
                ret = ENOMEM;
                goto done;
            }
            ret = ldb_msg_add_string(msg, SYSDB_MEMBER, mdn);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }

            talloc_zfree(mem_dn);
        }

        /* ok now we are ready to modify the entry */
        ret = ldb_modify(ldb, msg);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        talloc_zfree(msg);
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_2);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, ldb, SYSDB_VERSION_0_2, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_check_upgrade_02(struct sss_domain_info *domains,
                           const char *db_path)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_context *ldb;
    char *ldb_file;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    struct ldb_message_element *el;
    struct ldb_message *msg;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    const char *version = NULL;
    bool do_02_upgrade = false;
    bool ctx_trans = false;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_get_db_file(tmp_ctx,
                            "local", "UPGRADE",
                            db_path, &ldb_file);
    if (ret != EOK) {
        goto exit;
    }

    ret = sysdb_ldb_connect(tmp_ctx, ldb_file, &ldb);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_ldb_connect failed.\n"));
        return ret;
    }

    verdn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!verdn) {
        ret = EIO;
        goto exit;
    }

    ret = ldb_search(ldb, tmp_ctx, &res,
                     verdn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto exit;
    }
    if (res->count > 1) {
        ret = EIO;
        goto exit;
    }

    if (res->count == 1) {
        el = ldb_msg_find_element(res->msgs[0], "version");
        if (el) {
            if (el->num_values != 1) {
                ret = EINVAL;
                goto exit;
            }
            version = talloc_strndup(tmp_ctx,
                                     (char *)(el->values[0].data),
                                     el->values[0].length);
            if (!version) {
                ret = ENOMEM;
                goto exit;
            }

            if (strcmp(version, SYSDB_VERSION) == 0) {
                /* all fine, return */
                ret = EOK;
                goto exit;
            }

            DEBUG(4, ("Upgrading DB from version: %s\n", version));

            if (strcmp(version, SYSDB_VERSION_0_1) == 0) {
                /* convert database */
                ret = sysdb_upgrade_01(ldb, &version);
                if (ret != EOK) goto exit;
            }

            if (strcmp(version, SYSDB_VERSION_0_2) == 0) {
                /* need to convert database to split files */
                do_02_upgrade = true;
            }

        }
    }

    if (!do_02_upgrade) {
        /* not a v2 upgrade, return and let the normal code take over any
        * further upgrade */
        ret = EOK;
        goto exit;
    }

    /* == V2->V3 UPGRADE == */

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_3));

    /* ldb uses posix locks,
     * posix is stupid and kills all locks when you close *any* file
     * descriptor associated to the same file.
     * Therefore we must close and reopen the ldb file here */

    /* == Backup and reopen ldb == */

    /* close */
    talloc_zfree(ldb);

    /* backup*/
    ret = backup_file(ldb_file, 0);
    if (ret != EOK) {
        goto exit;
    }

    /* reopen */
    ret = sysdb_ldb_connect(tmp_ctx, ldb_file, &ldb);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_ldb_connect failed.\n"));
        return ret;
    }

    /* open a transaction */
    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
        ret = EIO;
        goto exit;
    }

    /* == Upgrade contents == */

    for (dom = domains; dom; dom = dom->next) {
        struct ldb_dn *domain_dn;
        struct ldb_dn *users_dn;
        struct ldb_dn *groups_dn;
        int i;

        /* skip local */
        if (strcasecmp(dom->provider, "local") == 0) {
            continue;
        }

        /* create new dom db */
        ret = sysdb_domain_init_internal(tmp_ctx, dom,
                                         db_path, false, &sysdb);
        if (ret != EOK) {
            goto done;
        }

        ret = ldb_transaction_start(sysdb->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
            ret = EIO;
            goto done;
        }
        ctx_trans = true;

        /* search all entries for this domain in local,
         * copy them all in the new database,
         * then remove them from local */

        domain_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                   SYSDB_DOM_BASE, sysdb->domain->name);
        if (!domain_dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(ldb, tmp_ctx, &res,
                         domain_dn, LDB_SCOPE_SUBTREE,
                         NULL, NULL);
        if (ret != LDB_SUCCESS) {
            ret = EIO;
            goto done;
        }

        users_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                 SYSDB_TMPL_USER_BASE, sysdb->domain->name);
        if (!users_dn) {
            ret = ENOMEM;
            goto done;
        }
        groups_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                   SYSDB_TMPL_GROUP_BASE, sysdb->domain->name);
        if (!groups_dn) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < res->count; i++) {

            struct ldb_dn *orig_dn;

            msg = res->msgs[i];

            /* skip pre-created congtainers */
            if ((ldb_dn_compare(msg->dn, domain_dn) == 0) ||
                (ldb_dn_compare(msg->dn, users_dn) == 0) ||
                (ldb_dn_compare(msg->dn, groups_dn) == 0)) {
                continue;
            }

            /* regenerate the DN against the new ldb as it may have different
             * casefolding rules (example: name changing from case insensitive
             * to case sensitive) */
            orig_dn = msg->dn;
            msg->dn = ldb_dn_new(msg, sysdb->ldb,
                                 ldb_dn_get_linearized(orig_dn));
            if (!msg->dn) {
                ret = ENOMEM;
                goto done;
            }

            ret = ldb_add(sysdb->ldb, msg);
            if (ret != LDB_SUCCESS) {
                DEBUG(0, ("WARNING: Could not add entry %s,"
                          " to new ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(msg->dn),
                          ret, ldb_errstring(sysdb->ldb)));
            }

            ret = ldb_delete(ldb, orig_dn);
            if (ret != LDB_SUCCESS) {
                DEBUG(0, ("WARNING: Could not remove entry %s,"
                          " from old ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(orig_dn),
                          ret, ldb_errstring(ldb)));
            }
        }

        /* now remove the basic containers from local */
        /* these were optional so debug at level 9 in case
         * of failure just for tracing */
        ret = ldb_delete(ldb, groups_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(groups_dn),
                      ret, ldb_errstring(ldb)));
        }
        ret = ldb_delete(ldb, users_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(users_dn),
                      ret, ldb_errstring(ldb)));
        }
        ret = ldb_delete(ldb, domain_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(domain_dn),
                      ret, ldb_errstring(ldb)));
        }

        ret = ldb_transaction_commit(sysdb->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
            ret = EIO;
            goto done;
        }
        ctx_trans = false;

        talloc_zfree(domain_dn);
        talloc_zfree(groups_dn);
        talloc_zfree(users_dn);
        talloc_zfree(res);
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_3);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_transaction_commit(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
        ret = EIO;
        goto exit;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        if (ctx_trans) {
            ret = ldb_transaction_cancel(sysdb->ldb);
            if (ret != LDB_SUCCESS) {
                DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
            }
        }
        ret = ldb_transaction_cancel(ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
        }
    }

exit:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_03(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_4));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Make this database case-sensitive */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "name", LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_4);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_4, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_04(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_5));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Add new index */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "originalDN");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* Rebuild memberuid and memberoif attributes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@MEMBEROF-REBUILD");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_5);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_5, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_05(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_6));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for dataExpireTimestamp */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "dataExpireTimestamp");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* Add index to speed up ONELEVEL searches */
    ret = ldb_msg_add_empty(msg, "@IDXONE", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXONE", "1");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_6);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_6, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_06(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_7));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Case insensitive search for originalDN */
    ret = ldb_msg_add_empty(msg, SYSDB_ORIG_DN, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_ORIG_DN, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_7);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_7, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_07(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_8));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for nameAlias */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "nameAlias");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_8);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_8, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_08(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_9));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for servicePort and serviceProtocol */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "servicePort");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", "serviceProtocol");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_9);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_9, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_09(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_10));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for servicePort and serviceProtocol */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", "sudoUser");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_10);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_10, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_10(struct sysdb_ctx *sysdb, const char **ver)
{

    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_result *res;
    struct ldb_message *msg;
    struct ldb_message *user;
    struct ldb_message_element *memberof_el;
    const char *name;
    struct ldb_dn *basedn;
    const char *filter = "(&(objectClass=user)(!(uidNumber=*))(memberOf=*))";
    const char *attrs[] = { "name", "memberof", NULL };
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_USER_BASE,
                            sysdb->domain->name);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_11));

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, basedn, LDB_SCOPE_SUBTREE,
                     attrs, "%s", filter);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        user = res->msgs[i];
        memberof_el = ldb_msg_find_element(user, "memberof");
        name = ldb_msg_find_attr_as_string(user, "name", NULL);
        if (name == NULL) {
            ret = EIO;
            goto done;
        }

        for (j = 0; j < memberof_el->num_values; j++) {
            msg = ldb_msg_new(tmp_ctx);
            if (msg == NULL) {
                ret = ENOMEM;
                goto done;
            }

            msg->dn = ldb_dn_from_ldb_val(tmp_ctx, sysdb->ldb, &memberof_el->values[j]);
            if (msg->dn == NULL) {
                ret = ENOMEM;
                goto done;
            }

            if (!ldb_dn_validate(msg->dn)) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("DN validation failed during "
                                             "upgrade: [%s]\n",
                                             memberof_el->values[j].data));
                talloc_zfree(msg);
                continue;
            }

            ret = ldb_msg_add_empty(msg, "ghost", LDB_FLAG_MOD_ADD, NULL);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }
            ret = ldb_msg_add_string(msg, "ghost", name);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }

            ret = ldb_msg_add_empty(msg, "member", LDB_FLAG_MOD_DELETE, NULL);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }
            ret = ldb_msg_add_string(msg, "member", ldb_dn_get_linearized(user->dn));
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }

            ret = ldb_modify(sysdb->ldb, msg);
            talloc_zfree(msg);
            if (ret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(ret);
                goto done;
            }
        }

        ret = ldb_delete(sysdb->ldb, user->dn);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_11);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    ret = finish_upgrade(ret, sysdb->ldb, SYSDB_VERSION_0_11, ver);
    talloc_free(tmp_ctx);
    return ret;
}
