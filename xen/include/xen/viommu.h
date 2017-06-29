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

struct viommu;

struct viommu_ops {
    int (*create)(struct domain *d, struct viommu *viommu);
    int (*destroy)(struct viommu *viommu);
};

struct viommu {
    uint64_t base_address;
    uint64_t caps;
    const struct viommu_ops *ops;
    void *priv;
};

#ifdef CONFIG_VIOMMU
extern bool opt_viommu;
static inline bool viommu_enabled(void)
{
    return opt_viommu;
}

int viommu_register_type(uint64_t type, struct viommu_ops *ops);
int viommu_destroy_domain(struct domain *d);
#else
static inline int viommu_register_type(uint64_t type, struct viommu_ops *ops)
{
    return -EINVAL;
}
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
