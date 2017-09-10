/*
 * common/viommu.c
 *
 * Copyright (c) 2017 Intel Corporation
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
 */

#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/types.h>
#include <xen/viommu.h>

bool __read_mostly opt_viommu;
boolean_param("viommu", opt_viommu);

static DEFINE_SPINLOCK(type_list_lock);
static LIST_HEAD(type_list);

struct viommu_type {
    uint64_t type;
    struct viommu_ops *ops;
    struct list_head node;
};

int viommu_destroy_domain(struct domain *d)
{
    int ret;

    if ( !d->viommu )
        return -EINVAL;

    ret = d->viommu->ops->destroy(d->viommu);
    if ( ret < 0 )
        return ret;

    xfree(d->viommu);
    d->viommu = NULL;
    return 0;
}

static struct viommu_type *viommu_get_type(uint64_t type)
{
    struct viommu_type *viommu_type = NULL;

    spin_lock(&type_list_lock);
    list_for_each_entry( viommu_type, &type_list, node )
    {
        if ( viommu_type->type == type )
        {
            spin_unlock(&type_list_lock);
            return viommu_type;
        }
    }
    spin_unlock(&type_list_lock);

    return NULL;
}

int viommu_register_type(uint64_t type, struct viommu_ops *ops)
{
    struct viommu_type *viommu_type = NULL;

    if ( !viommu_enabled() )
        return -ENODEV;

    if ( viommu_get_type(type) )
        return -EEXIST;

    viommu_type = xzalloc(struct viommu_type);
    if ( !viommu_type )
        return -ENOMEM;

    viommu_type->type = type;
    viommu_type->ops = ops;

    spin_lock(&type_list_lock);
    list_add_tail(&viommu_type->node, &type_list);
    spin_unlock(&type_list_lock);

    return 0;
}

static int viommu_create(struct domain *d, uint64_t type,
                         uint64_t base_address, uint64_t caps,
                         uint32_t *viommu_id)
{
    struct viommu *viommu;
    struct viommu_type *viommu_type = NULL;
    int rc;

    /* Only support one vIOMMU per domain. */
    if ( d->viommu )
        return -E2BIG;

    viommu_type = viommu_get_type(type);
    if ( !viommu_type )
        return -EINVAL;

    if ( !viommu_type->ops || !viommu_type->ops->create )
        return -EINVAL;

    viommu = xzalloc(struct viommu);
    if ( !viommu )
        return -ENOMEM;

    viommu->base_address = base_address;
    viommu->caps = caps;
    viommu->ops = viommu_type->ops;

    rc = viommu->ops->create(d, viommu);
    if ( rc < 0 )
    {
        xfree(viommu);
        return rc;
    }

    d->viommu = viommu;

    /* Only support one vIOMMU per domain. */
    *viommu_id = 0;
    return 0;
}

int viommu_domctl(struct domain *d, struct xen_domctl_viommu_op *op,
                  bool *need_copy)
{
    int rc = -EINVAL;

    if ( !viommu_enabled() )
        return -ENODEV;

    switch ( op->cmd )
    {
    case XEN_DOMCTL_create_viommu:
        rc = viommu_create(d, op->u.create.viommu_type,
                           op->u.create.base_address,
                           op->u.create.capabilities,
                           &op->u.create.viommu_id);
        if ( !rc )
            *need_copy = true;
        break;

    case XEN_DOMCTL_destroy_viommu:
        rc = viommu_destroy_domain(d);
        break;

    default:
        return -ENOSYS;
    }

    return rc;
}

int viommu_handle_irq_request(struct domain *d,
                              struct arch_irq_remapping_request *request)
{
    struct viommu *viommu = d->viommu;

    if ( !viommu )
        return -EINVAL;

    ASSERT(viommu->ops);
    if ( !viommu->ops->handle_irq_request )
        return -EINVAL;

    return viommu->ops->handle_irq_request(d, request);
}

int viommu_get_irq_info(struct domain *d,
                        struct arch_irq_remapping_request *request,
                        struct arch_irq_remapping_info *irq_info)
{
    struct viommu *viommu = d->viommu;

    if ( !viommu )
        return -EINVAL;

    ASSERT(viommu->ops);
    if ( !viommu->ops->get_irq_info )
        return -EINVAL;

    return viommu->ops->get_irq_info(d, request, irq_info);
}

bool viommu_check_irq_remapping(struct domain *d,
                                struct arch_irq_remapping_request *request)
{
    struct viommu *viommu = d->viommu;

    if ( !viommu )
        return false;

    ASSERT(viommu->ops);
    if ( !viommu->ops->check_irq_remapping)
        return false;

    return viommu->ops->check_irq_remapping(d, request);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
