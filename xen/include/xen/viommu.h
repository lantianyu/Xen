/*
 * include/xen/viommu.h
 *
 * Copyright (c) 2017, Intel Corporation
 * Author: Lan Tianyu <tianyu.lan@intel.com> 
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef __XEN_VIOMMU_H__
#define __XEN_VIOMMU_H__

#define NR_VIOMMU_PER_DOMAIN 1

struct viommu;

struct viommu_ops {
    u64 (*query_caps)(struct domain *d);
    int (*create)(struct domain *d, struct viommu *viommu);
    int (*destroy)(struct viommu *viommu);
};

struct viommu {
    u64 base_address;
    u64 length;
    u64 caps;
    u32 viommu_id;
    const struct viommu_ops *ops;
    void *priv;
};

struct viommu_info {
    u32 nr_viommu;
    struct viommu *viommu[NR_VIOMMU_PER_DOMAIN]; /* viommu array*/
};

#ifdef CONFIG_VIOMMU
extern bool_t opt_viommu;
static inline bool_t viommu_enabled(void) { return opt_viommu; }
int viommu_init_domain(struct domain *d);
int viommu_register_type(u64 type, struct viommu_ops * ops);
int viommu_setup(void);
#else
static inline int viommu_init_domain(struct domain *d) { return 0; }
static inline int viommu_register_type(u64 type, struct viommu_ops * ops)
{ return 0; }
static inline int __init viommu_setup(void) { return 0; }
static inline bool_t viommu_enabled(void) { return 0; }
#endif

#endif /* __XEN_VIOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
