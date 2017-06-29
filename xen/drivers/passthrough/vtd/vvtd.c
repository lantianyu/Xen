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

struct hvm_hw_vvtd_regs {
    uint8_t data[1024];
};

/* Status field of struct vvtd */
#define VIOMMU_STATUS_DEFAULT                   (0)
#define VIOMMU_STATUS_IRQ_REMAPPING_ENABLED     (1 << 0)
#define VIOMMU_STATUS_DMA_REMAPPING_ENABLED     (1 << 1)

struct vvtd {
    /* VIOMMU_STATUS_XXX */
    int status;
    /* Address range of remapping hardware register-set */
    uint64_t base_addr;
    uint64_t length;
    /* Point back to the owner domain */
    struct domain *domain;
    struct hvm_hw_vvtd_regs *regs;
    struct page_info *regs_page;
};

#define __DEBUG_VVTD__
#ifdef __DEBUG_VVTD__
extern unsigned int vvtd_debug_level;
#define VVTD_DBG_INFO     1
#define VVTD_DBG_TRANS    (1<<1)
#define VVTD_DBG_RW       (1<<2)
#define VVTD_DBG_FAULT    (1<<3)
#define VVTD_DBG_EOI      (1<<4)
#define VVTD_DEBUG(lvl, _f, _a...) do { \
    if ( vvtd_debug_level & lvl ) \
        printk("VVTD %s:" _f "\n", __func__, ## _a);    \
} while(0)
#else
#define VVTD_DEBUG(fmt...) do {} while(0)
#endif

unsigned int vvtd_debug_level __read_mostly;
integer_param("vvtd_debug", vvtd_debug_level);

struct vvtd *domain_vvtd(struct domain *d)
{
    struct viommu_info *info = &d->viommu;

    BUILD_BUG_ON(NR_VIOMMU_PER_DOMAIN != 1);
    return (info && info->viommu[0]) ? info->viommu[0]->priv : NULL;
}

static inline struct vvtd *vcpu_vvtd(struct vcpu *v)
{
    return domain_vvtd(v->domain);
}

static inline void vvtd_set_reg(struct vvtd *vtd, uint32_t reg,
                                uint32_t value)
{
    *((uint32_t *)(&vtd->regs->data[reg])) = value;
}

static inline uint32_t vvtd_get_reg(struct vvtd *vtd, uint32_t reg)
{
    return *((uint32_t *)(&vtd->regs->data[reg]));
}

static inline uint8_t vvtd_get_reg_byte(struct vvtd *vtd, uint32_t reg)
{
    return *((uint8_t *)(&vtd->regs->data[reg]));
}

#define vvtd_get_reg_quad(vvtd, reg, val) do {  \
    (val) = vvtd_get_reg(vvtd, (reg) + 4 );     \
    (val) = (val) << 32;                        \
    (val) += vvtd_get_reg(vvtd, reg);           \
} while(0)
#define vvtd_set_reg_quad(vvtd, reg, val) do {  \
    vvtd_set_reg(vvtd, reg, (val));             \
    vvtd_set_reg(vvtd, (reg) + 4, (val) >> 32); \
} while(0)

static int vvtd_range(struct vcpu *v, unsigned long addr)
{
    struct vvtd *vvtd = vcpu_vvtd(v);

    if ( vvtd )
        return (addr >= vvtd->base_addr) &&
               (addr < vvtd->base_addr + PAGE_SIZE);
    return 0;
}

static int vvtd_read(struct vcpu *v, unsigned long addr,
                     unsigned int len, unsigned long *pval)
{
    struct vvtd *vvtd = vcpu_vvtd(v);
    unsigned int offset = addr - vvtd->base_addr;
    unsigned int offset_aligned = offset & ~3;

    VVTD_DEBUG(VVTD_DBG_RW, "READ INFO: offset %x len %d.", offset, len);

    if ( !pval )
        return X86EMUL_UNHANDLEABLE;

    if ( (offset & 3) || ((len != 4) && (len != 8)) )
    {
        VVTD_DEBUG(VVTD_DBG_RW, "Alignment or length is not canonical");
        return X86EMUL_UNHANDLEABLE;
    }

    if ( len == 4 )
        *pval = vvtd_get_reg(vvtd, offset_aligned);
    else
        vvtd_get_reg_quad(vvtd, offset_aligned, *pval);
    return X86EMUL_OKAY;
}

static int vvtd_write(struct vcpu *v, unsigned long addr,
                      unsigned int len, unsigned long val)
{
    struct vvtd *vvtd = vcpu_vvtd(v);
    unsigned int offset = addr - vvtd->base_addr;
    unsigned int offset_aligned = offset & ~0x3;
    int ret;

    VVTD_DEBUG(VVTD_DBG_RW, "WRITE INFO: offset %x len %d val %lx.",
               offset, len, val);

    if ( (offset & 3) || ((len != 4) && (len != 8)) )
    {
        VVTD_DEBUG(VVTD_DBG_RW, "Alignment or length is not canonical");
        return X86EMUL_UNHANDLEABLE;
    }

    ret = X86EMUL_UNHANDLEABLE;
    if ( len == 4 )
    {
        switch ( offset_aligned )
        {
        case DMAR_IEDATA_REG:
        case DMAR_IEADDR_REG:
        case DMAR_IEUADDR_REG:
        case DMAR_FEDATA_REG:
        case DMAR_FEADDR_REG:
        case DMAR_FEUADDR_REG:
            vvtd_set_reg(vvtd, offset_aligned, val);
            ret = X86EMUL_OKAY;
            break;

        default:
            break;
        }
    }

    return ret;
}

static const struct hvm_mmio_ops vvtd_mmio_ops = {
    .check = vvtd_range,
    .read = vvtd_read,
    .write = vvtd_write
};

static void vvtd_reset(struct vvtd *vvtd, uint64_t capability)
{
    uint64_t cap = DMA_CAP_NFR | DMA_CAP_SLLPS | DMA_CAP_FRO |
                   DMA_CAP_MGAW | DMA_CAP_SAGAW | DMA_CAP_ND;
    uint64_t ecap = DMA_ECAP_IR | DMA_ECAP_EIM | DMA_ECAP_QI;

    vvtd_set_reg(vvtd, DMAR_VER_REG, 0x10UL);
    vvtd_set_reg_quad(vvtd, DMAR_CAP_REG, cap);
    vvtd_set_reg_quad(vvtd, DMAR_ECAP_REG, ecap);
    vvtd_set_reg(vvtd, DMAR_FECTL_REG, 0x80000000UL);
    vvtd_set_reg(vvtd, DMAR_IECTL_REG, 0x80000000UL);
}

static u64 vvtd_query_caps(struct domain *d)
{
    return VIOMMU_CAP_IRQ_REMAPPING;
}

static int vvtd_create(struct domain *d, struct viommu *viommu)
{
    struct vvtd *vvtd;
    int ret;

    if ( !is_hvm_domain(d) || (viommu->length != PAGE_SIZE) ||
        (~vvtd_query_caps(d) & viommu->caps) )
        return -EINVAL;

    ret = -ENOMEM;
    vvtd = xmalloc_bytes(sizeof(struct vvtd));
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
    vvtd->length = viommu->length;
    vvtd->domain = d;
    vvtd->status = VIOMMU_STATUS_DEFAULT;
    register_mmio_handler(d, &vvtd_mmio_ops);
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
    .query_caps = vvtd_query_caps,
    .create = vvtd_create,
    .destroy = vvtd_destroy
};

static int vvtd_register(void)
{
    viommu_register_type(VIOMMU_TYPE_INTEL_VTD, &vvtd_hvm_vmx_ops);
    return 0;
}
__initcall(vvtd_register);
