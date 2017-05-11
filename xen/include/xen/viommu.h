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

#include <asm/viommu.h>

#define NR_VIOMMU_PER_DOMAIN 1

struct viommu;

struct viommu_ops {
    u64 (*query_caps)(struct domain *d);
    int (*create)(struct domain *d, struct viommu *viommu);
    int (*destroy)(struct viommu *viommu);
    int (*handle_irq_request)(struct domain *d,
                              struct irq_remapping_request *request);
    int (*get_irq_info)(struct domain *d, struct irq_remapping_request *request,
                        struct irq_remapping_info *info);
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
int viommu_init_domain(struct domain *d);
int viommu_create(struct domain *d, u64 type, u64 base_address,
                  u64 length, u64 caps);
int viommu_destroy(struct domain *d, u32 viommu_id);
int viommu_register_type(u64 type, struct viommu_ops * ops);
void viommu_unregister_type(u64 type);
u64 viommu_query_caps(struct domain *d, u64 viommu_type);
int viommu_domctl(struct domain *d, struct xen_domctl_viommu_op *op,
                  bool_t *need_copy);
int viommu_setup(void);
int viommu_handle_irq_request(struct domain *d, u32 viommu_id,
                              struct irq_remapping_request *request);
int viommu_get_irq_info(struct domain *d, u32 viommu_id, 
                        struct irq_remapping_request *request,
                        struct irq_remapping_info *irq_info);
#else
static inline int viommu_init_domain(struct domain *d) { return 0 };
static inline int viommu_create(struct domain *d, u64 type, u64 base_address,
                                u64 length, u64 caps) { return -ENODEV };
static inline int viommu_destroy(struct domain *d, u32 viommu_id) { return 0 };
static inline int viommu_register_type(u64 type, struct viommu_ops * ops)
{ return 0; };
static inline void viommu_unregister_type(u64 type) { };
static inline u64 viommu_query_caps(struct domain *d, u64 viommu_type)
{ return -ENODEV };
static inline int __init viommu_setup(void) { return 0 };
static inline int viommu_domctl(struct domain *d,
                                struct xen_domctl_viommu_op *op,
                                bool_t *need_copy)
{ return -ENODEV };
static inline int viommu_handle_irq_request(struct domain *d, u32 viommu_id,
                              struct irq_remapping_request *request)
{ return 0 };
static inline int viommu_get_irq_info(struct domain *d, u32 viommu_id,
                                      struct irq_remapping_request *request,
                                      struct irq_remapping_info *irq_info)
{ return 0 };
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
