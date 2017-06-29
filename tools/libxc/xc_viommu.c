/*
 * xc_viommu.c
 *
 * viommu related API functions.
 *
 * Copyright (C) 2017 Intel Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2.1, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

int xc_viommu_query_cap(xc_interface *xch, domid_t dom,
                        uint64_t type, uint64_t *cap)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_viommu_op;
    domctl.domain = (domid_t)dom;
    domctl.u.viommu_op.cmd = XEN_DOMCTL_query_viommu_caps;
    domctl.u.viommu_op.u.query_caps.viommu_type = type;

    rc = do_domctl(xch, &domctl);
    if ( !rc )
        *cap = domctl.u.viommu_op.u.query_caps.capabilities;
    return rc;
}

int xc_viommu_create(xc_interface *xch, domid_t dom, uint64_t type,
                     uint64_t base_addr, uint64_t length, uint64_t cap,
                     uint32_t *viommu_id)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_viommu_op;
    domctl.domain = (domid_t)dom;
    domctl.u.viommu_op.cmd = XEN_DOMCTL_create_viommu;
    domctl.u.viommu_op.u.create_viommu.viommu_type = type;
    domctl.u.viommu_op.u.create_viommu.base_address = base_addr;
    domctl.u.viommu_op.u.create_viommu.length = length;
    domctl.u.viommu_op.u.create_viommu.capabilities = cap;

    rc = do_domctl(xch, &domctl);
    if ( !rc )
        *viommu_id = domctl.u.viommu_op.u.create_viommu.viommu_id;
    return rc;
}

int xc_viommu_destroy(xc_interface *xch, domid_t dom, uint32_t viommu_id)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_viommu_op;
    domctl.domain = (domid_t)dom;
    domctl.u.viommu_op.cmd = XEN_DOMCTL_destroy_viommu;
    domctl.u.viommu_op.u.destroy_viommu.viommu_id = viommu_id;

    return do_domctl(xch, &domctl);
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
