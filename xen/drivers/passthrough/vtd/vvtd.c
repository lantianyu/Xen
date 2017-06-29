/*
 * vvtd.c
 *
 * virtualize VTD for HVM.
 *
 * Copyright (C) 2017 Chao Gao, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/viommu.h>
#include <xen/xmalloc.h>
#include <asm/current.h>
#include <asm/hvm/domain.h>
#include <asm/page.h>

#include "iommu.h"

/* Supported capabilities by vvtd */
unsigned int vvtd_caps = VIOMMU_CAP_IRQ_REMAPPING;

union hvm_hw_vvtd_regs {
    uint32_t data32[256];
    uint64_t data64[128];
};

struct vvtd {
    /* Address range of remapping hardware register-set */
    uint64_t base_addr;
    uint64_t length;
    /* Point back to the owner domain */
    struct domain *domain;
    union hvm_hw_vvtd_regs *regs;
    struct page_info *regs_page;
};

/* Setting viommu_verbose enables debugging messages of vIOMMU */
bool __read_mostly viommu_verbose;
boolean_runtime_param("viommu_verbose", viommu_verbose);

#ifndef NDEBUG
#define vvtd_info(fmt...) do {                    \
    if ( viommu_verbose )                         \
        gprintk(XENLOG_G_INFO, ## fmt);           \
} while(0)
#define vvtd_debug(fmt...) do {                   \
    if ( viommu_verbose && printk_ratelimit() )   \
        printk(XENLOG_G_DEBUG fmt);               \
} while(0)
#else
#define vvtd_info(fmt...) do {} while(0)
#define vvtd_debug(fmt...) do {} while(0)
#endif

struct vvtd *domain_vvtd(struct domain *d)
{
    return (d->viommu) ? d->viommu->priv : NULL;
}

static inline void vvtd_set_reg(struct vvtd *vtd, uint32_t reg, uint32_t value)
{
    vtd->regs->data32[reg/sizeof(uint32_t)] = value;
}

static inline uint32_t vvtd_get_reg(struct vvtd *vtd, uint32_t reg)
{
    return vtd->regs->data32[reg/sizeof(uint32_t)];
}

static inline void vvtd_set_reg_quad(struct vvtd *vtd, uint32_t reg,
                                     uint64_t value)
{
    vtd->regs->data64[reg/sizeof(uint64_t)] = value;
}

static inline uint64_t vvtd_get_reg_quad(struct vvtd *vtd, uint32_t reg)
{
    return vtd->regs->data64[reg/sizeof(uint64_t)];
}

static int vvtd_in_range(struct vcpu *v, unsigned long addr)
{
    struct vvtd *vvtd = domain_vvtd(v->domain);

    if ( vvtd )
        return (addr >= vvtd->base_addr) &&
               (addr < vvtd->base_addr + PAGE_SIZE);
    return 0;
}

static int vvtd_read(struct vcpu *v, unsigned long addr,
                     unsigned int len, unsigned long *pval)
{
    struct vvtd *vvtd = domain_vvtd(v->domain);
    unsigned int offset = addr - vvtd->base_addr;

    vvtd_info("Read offset %x len %d\n", offset, len);

    if ( (len != 4 && len != 8) || (offset & (len - 1)) )
        return X86EMUL_OKAY;

    if ( len == 4 )
        *pval = vvtd_get_reg(vvtd, offset);
    else
        *pval = vvtd_get_reg_quad(vvtd, offset);

    return X86EMUL_OKAY;
}

static int vvtd_write(struct vcpu *v, unsigned long addr,
                      unsigned int len, unsigned long val)
{
    struct vvtd *vvtd = domain_vvtd(v->domain);
    unsigned int offset = addr - vvtd->base_addr;

    vvtd_info("Write offset %x len %d val %lx\n", offset, len, val);

    if ( (len != 4 && len != 8) || (offset & (len - 1)) )
        return X86EMUL_OKAY;

    if ( len == 4 )
    {
        switch ( offset )
        {
        case DMAR_IEDATA_REG:
        case DMAR_IEADDR_REG:
        case DMAR_IEUADDR_REG:
        case DMAR_FEDATA_REG:
        case DMAR_FEADDR_REG:
        case DMAR_FEUADDR_REG:
            vvtd_set_reg(vvtd, offset, val);
            break;

        default:
            break;
        }
    }

    return X86EMUL_OKAY;
}

static const struct hvm_mmio_ops vvtd_mmio_ops = {
    .check = vvtd_in_range,
    .read = vvtd_read,
    .write = vvtd_write
};

static void vvtd_reset(struct vvtd *vvtd, uint64_t capability)
{
    uint64_t cap = cap_set_num_fault_regs(1ULL) |
                   cap_set_fault_reg_offset(0x220ULL) |
                   cap_set_mgaw(39ULL) | DMA_CAP_SAGAW_39bit |
                   DMA_CAP_ND_64K;
    uint64_t ecap = DMA_ECAP_IR | DMA_ECAP_EIM | DMA_ECAP_QI;

    vvtd_set_reg(vvtd, DMAR_VER_REG, 0x10UL);
    vvtd_set_reg_quad(vvtd, DMAR_CAP_REG, cap);
    vvtd_set_reg_quad(vvtd, DMAR_ECAP_REG, ecap);
    vvtd_set_reg(vvtd, DMAR_FECTL_REG, 0x80000000UL);
    vvtd_set_reg(vvtd, DMAR_IECTL_REG, 0x80000000UL);
}

static int vvtd_create(struct domain *d, struct viommu *viommu)
{
    struct vvtd *vvtd;
    int ret;

    if ( !is_hvm_domain(d) || (viommu->base_address & (PAGE_SIZE - 1)) ||
        (~vvtd_caps & viommu->caps) )
        return -EINVAL;

    ret = -ENOMEM;
    vvtd = xzalloc_bytes(sizeof(struct vvtd));
    if ( !vvtd )
        return ret;

    vvtd->regs_page = alloc_domheap_page(d, MEMF_no_owner);
    if ( !vvtd->regs_page )
        goto out1;

    vvtd->regs = __map_domain_page_global(vvtd->regs_page);
    if ( !vvtd->regs )
        goto out2;
    clear_page(vvtd->regs);

    vvtd_reset(vvtd, viommu->caps);
    vvtd->base_addr = viommu->base_address;
    vvtd->domain = d;
    register_mmio_handler(d, &vvtd_mmio_ops);

    viommu->priv = vvtd;

    return 0;

 out2:
    free_domheap_page(vvtd->regs_page);
 out1:
    xfree(vvtd);
    return ret;
}

static int vvtd_destroy(struct viommu *viommu)
{
    struct vvtd *vvtd = viommu->priv;

    if ( vvtd )
    {
        unmap_domain_page_global(vvtd->regs);
        free_domheap_page(vvtd->regs_page);
        xfree(vvtd);
    }
    return 0;
}

struct viommu_ops vvtd_hvm_vmx_ops = {
    .create = vvtd_create,
    .destroy = vvtd_destroy
};

static int vvtd_register(void)
{
    viommu_register_type(VIOMMU_TYPE_INTEL_VTD, &vvtd_hvm_vmx_ops);
    return 0;
}
__initcall(vvtd_register);
