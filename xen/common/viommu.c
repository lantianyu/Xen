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

#include <xen/types.h>
#include <xen/sched.h>
#include <xen/spinlock.h>

spinlock_t type_list_lock;
static struct list_head type_list;

struct viommu_type {
    u64 type;
    struct viommu_ops *ops;
    struct list_head node;
};

int viommu_domctl(struct domain *d, struct xen_domctl_viommu_op *op,
                  bool_t *need_copy)
{
    int rc = -EINVAL;

    switch ( op->cmd )
    {
    case XEN_DOMCTL_create_viommu:
		rc = viommu_create(d, op->u.create_viommu.viommu_type,
                           op->u.create_viommu.base_address,
                           op->u.create_viommu.length,
                           op->u.create_viommu.capabilities);
        if (rc >= 0) {
            op->u.create_viommu.viommu_id = rc;
            *need_copy = true;
        }
        break;

    case XEN_DOMCTL_destroy_viommu:
        rc = viommu_destroy(d, op->u.destroy_viommu.viommu_id);
        break;

    case XEN_DOMCTL_query_viommu_caps:
        op->u.query_caps.caps
                = viommu_query_caps(d, op->u.query_caps.viommu_type);
        *need_copy = true;
        break;

    default:
        break;
    }

    return rc;
}

int viommu_init_domain(struct domain *d)
{
    d->viommu.nr_viommu = 0;
    return 0;
}

struct viommu_type *viommu_get_type(u64 type)
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

int viommu_register_type(u64 type, struct viommu_ops * ops)
{
    struct viommu_type *viommu_type = NULL;

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

void viommu_unregister_type(u64 type)
{
    struct viommu_type *viommu_type = viommu_get_type(type);

    if ( viommu_type )
    {
        spin_lock(&type_list_lock);
        list_del(&viommu_type->node);
        spin_unlock(&type_list_lock);

        xfree(viommu_type);
    }
}

int viommu_create(struct domain *d, u64 type, u64 base_address,
                  u64 length, u64 caps)
{
    struct viommu_info *info = &d->viommu;
    struct viommu *viommu;
    struct viommu_type *viommu_type = NULL;
    int rc;

    viommu_type = viommu_get_type(type);
    if ( !viommu_type )
        return -EFAULT;

    if ( !info || info->nr_viommu >= NR_VIOMMU_PER_DOMAIN
        || !viommu_type->ops || !viommu_type->ops->create )
        return -EINVAL;

    viommu = xzalloc(struct viommu);
    if ( !viommu )
        return -ENOMEM;

    viommu->base_address = base_address;
    viommu->length = length;
    viommu->caps = caps;
    viommu->ops = viommu_type->ops;
    viommu->viommu_id = info->nr_viommu;

    info->viommu[info->nr_viommu] = viommu;
    info->nr_viommu++;

    rc = viommu->ops->create(d, viommu);
    if ( rc < 0 )
    {
        xfree(viommu);
        return rc;
    }

    return viommu->viommu_id;
}

int viommu_destroy(struct domain *d, u32 viommu_id)
{
    struct viommu_info *info = &d->viommu;

    if ( !info || viommu_id > info->nr_viommu || !info->viommu[viommu_id] )
        return -EINVAL;

    if ( info->viommu[viommu_id]->ops->destroy(info->viommu[viommu_id]) )
        return -EFAULT;

    info->viommu[viommu_id] = NULL;
    return 0;
}

u64 viommu_query_caps(struct domain *d, u64 type)
{
    struct viommu_type *viommu_type = viommu_get_type(type);

    if ( !viommu_type )
        return -EFAULT;

    return viommu_type->ops->query_caps(d);
}

int __init viommu_setup(void)
{
    INIT_LIST_HEAD(&type_list);
    spin_lock_init(&type_list_lock);
    return 0;
}

int viommu_handle_irq_request(struct domain *d, u32 viommu_id,
        struct irq_remapping_request *request)
{
    struct viommu_info *info = &d->viommu;

    if ( !info || viommu_id > info->nr_viommu
         || !info->viommu[viommu_id] )
        return -EINVAL;

    if ( !info->viommu[viommu_id]->ops->handle_irq_request )
        return -EINVAL;

    return info->viommu[viommu_id]->ops->handle_irq_request(d, request);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
