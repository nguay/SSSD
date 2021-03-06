/*
   SSSD

   NSS Responder - Mmap Cache

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2011

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

#ifndef _NSSSRV_MMAP_CACHE_H_
#define _NSSSRV_MMAP_CACHE_H_

struct sss_mc_ctx;

enum sss_mc_type {
    SSS_MC_NONE = 0,
    SSS_MC_PASSWD,
    SSS_MC_GROUP,
};

errno_t sss_mmap_cache_init(TALLOC_CTX *mem_ctx, const char *name,
                            enum sss_mc_type type, size_t n_elem,
                            time_t valid_time, struct sss_mc_ctx **mcc);

errno_t sss_mmap_cache_pw_store(struct sss_mc_ctx *mcc,
                                struct sized_string *name,
                                struct sized_string *pw,
                                uid_t uid, gid_t gid,
                                struct sized_string *gecos,
                                struct sized_string *homedir,
                                struct sized_string *shell);

errno_t sss_mmap_cache_gr_store(struct sss_mc_ctx *mcc,
                                struct sized_string *name,
                                struct sized_string *pw,
                                gid_t gid, size_t memnum,
                                char *membuf, size_t memsize);

#endif /* _NSSSRV_MMAP_CACHE_H_ */
