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
#include <asm/apic.h>
#include <asm/current.h>
#include <asm/event.h>
#include <asm/hvm/domain.h>
#include <asm/io_apic.h>
#include <asm/page.h>
#include <asm/p2m.h>

#include "iommu.h"
#include "vtd.h"

struct hvm_hw_vvtd_regs {
    uint8_t data[1024];
};

/* Status field of struct vvtd */
#define VIOMMU_STATUS_DEFAULT                   (0)
#define VIOMMU_STATUS_IRQ_REMAPPING_ENABLED     (1 << 0)
#define VIOMMU_STATUS_DMA_REMAPPING_ENABLED     (1 << 1)

#define vvtd_irq_remapping_enabled(vvtd) \
    (vvtd->status & VIOMMU_STATUS_IRQ_REMAPPING_ENABLED)

struct vvtd {
    /* VIOMMU_STATUS_XXX */
    int status;
    /* Address range of remapping hardware register-set */
    uint64_t base_addr;
    uint64_t length;
    /* Point back to the owner domain */
    struct domain *domain;
    /* Is in Extended Interrupt Mode? */
    bool eim;
    /* Max remapping entries in IRT */
    int irt_max_entry;
    /* Interrupt remapping table base gfn */
    uint64_t irt;

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

static inline void __vvtd_set_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    return __set_bit(nr, (uint32_t *)&vvtd->regs->data[reg]);
}

static inline void __vvtd_clear_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    return __clear_bit(nr, (uint32_t *)&vvtd->regs->data[reg]);
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

static int map_guest_page(struct domain *d, uint64_t gfn, void **virt)
{
    struct page_info *p;

    p = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
    if ( !p )
        return -EINVAL;

    if ( !get_page_type(p, PGT_writable_page) )
    {
        put_page(p);
        return -EINVAL;
    }

    *virt = __map_domain_page_global(p);
    if ( !*virt )
    {
        put_page_and_type(p);
        return -ENOMEM;
    }
    return 0;
}

static void unmap_guest_page(void *virt)
{
    struct page_info *page;

    if ( !virt )
        return;

    virt = (void *)((unsigned long)virt & PAGE_MASK);
    page = mfn_to_page(domain_page_map_to_mfn(virt));

    unmap_domain_page_global(virt);
    put_page_and_type(page);
}

static void vvtd_inj_irq(
    struct vlapic *target,
    uint8_t vector,
    uint8_t trig_mode,
    uint8_t delivery_mode)
{
    VVTD_DEBUG(VVTD_DBG_INFO, "dest=v%d, delivery_mode=%x vector=%d "
               "trig_mode=%d.",
               vlapic_vcpu(target)->vcpu_id, delivery_mode,
               vector, trig_mode);

    ASSERT((delivery_mode == dest_Fixed) ||
           (delivery_mode == dest_LowestPrio));

    vlapic_set_irq(target, vector, trig_mode);
}

static int vvtd_delivery(
    struct domain *d, int vector,
    uint32_t dest, uint8_t dest_mode,
    uint8_t delivery_mode, uint8_t trig_mode)
{
    struct vlapic *target;
    struct vcpu *v;

    switch ( delivery_mode )
    {
    case dest_LowestPrio:
        target = vlapic_lowest_prio(d, NULL, 0, dest, dest_mode);
        if ( target != NULL )
        {
            vvtd_inj_irq(target, vector, trig_mode, delivery_mode);
            break;
        }
        VVTD_DEBUG(VVTD_DBG_INFO, "null round robin: vector=%02x\n", vector);
        break;

    case dest_Fixed:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest,
                                   dest_mode) )
                vvtd_inj_irq(vcpu_vlapic(v), vector,
                             trig_mode, delivery_mode);
        break;

    case dest_NMI:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest, dest_mode)
                 && !test_and_set_bool(v->nmi_pending) )
                vcpu_kick(v);
        break;

    default:
        printk(XENLOG_G_WARNING
               "%pv: Unsupported VTD delivery mode %d for Dom%d\n",
               current, delivery_mode, d->domain_id);
        return -EINVAL;
    }

    return 0;
}

static uint32_t irq_remapping_request_index(struct irq_remapping_request *irq)
{
    if ( irq->type == VIOMMU_REQUEST_IRQ_MSI )
    {
        struct msi_msg_remap_entry msi_msg = { { irq->msg.msi.addr }, 0,
                                               irq->msg.msi.data };

        return MSI_REMAP_ENTRY_INDEX(msi_msg);
    }
    else if ( irq->type == VIOMMU_REQUEST_IRQ_APIC )
    {
        struct IO_APIC_route_remap_entry remap_rte = { { irq->msg.rte } };

        return IOAPIC_REMAP_ENTRY_INDEX(remap_rte);
    }
    BUG();
    return 0;
}

static inline uint32_t irte_dest(struct vvtd *vvtd, uint32_t dest)
{
    uint64_t irta;

    vvtd_get_reg_quad(vvtd, DMAR_IRTA_REG, irta);
    /* In xAPIC mode, only 8-bits([15:8]) are valid */
    return DMA_IRTA_EIME(irta) ? dest : MASK_EXTR(dest, IRTE_xAPIC_DEST_MASK);
}

static int vvtd_record_fault(struct vvtd *vvtd,
                             struct irq_remapping_request *irq,
                             int reason)
{
    return 0;
}

static int vvtd_handle_gcmd_qie(struct vvtd *vvtd, uint32_t val)
{
    VVTD_DEBUG(VVTD_DBG_RW, "%sable Queue Invalidation.",
               (val & DMA_GCMD_QIE) ? "En" : "Dis");

    if ( val & DMA_GCMD_QIE )
        __vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_QIES_BIT);
    else
    {
        vvtd_set_reg_quad(vvtd, DMAR_IQH_REG, 0ULL);
        __vvtd_clear_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_QIES_BIT);
    }
    return X86EMUL_OKAY;
}

static int vvtd_handle_gcmd_ire(struct vvtd *vvtd, uint32_t val)
{
    VVTD_DEBUG(VVTD_DBG_RW, "%sable Interrupt Remapping.",
               (val & DMA_GCMD_IRE) ? "En" : "Dis");

    if ( val & DMA_GCMD_IRE )
    {
        vvtd->status |= VIOMMU_STATUS_IRQ_REMAPPING_ENABLED;
        __vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_IRES_BIT);
    }
    else
    {
        vvtd->status |= ~VIOMMU_STATUS_IRQ_REMAPPING_ENABLED;
        __vvtd_clear_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_IRES_BIT);
    }

    return X86EMUL_OKAY;
}

static int vvtd_handle_gcmd_sirtp(struct vvtd *vvtd, uint32_t val)
{
    uint64_t irta;

    if ( !(val & DMA_GCMD_SIRTP) )
        return X86EMUL_OKAY;

    if ( vvtd_irq_remapping_enabled(vvtd) )
        VVTD_DEBUG(VVTD_DBG_RW, "Update Interrupt Remapping Table when "
                   "active." );

    vvtd_get_reg_quad(vvtd, DMAR_IRTA_REG, irta);
    vvtd->irt = DMA_IRTA_ADDR(irta) >> PAGE_SHIFT;
    vvtd->irt_max_entry = DMA_IRTA_SIZE(irta);
    vvtd->eim = DMA_IRTA_EIME(irta);
    VVTD_DEBUG(VVTD_DBG_RW, "Update IR info (addr=%lx eim=%d size=%d).",
               vvtd->irt, vvtd->eim, vvtd->irt_max_entry);
    __vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_SIRTPS_BIT);

    return X86EMUL_OKAY;
}

static int vvtd_write_gcmd(struct vvtd *vvtd, uint32_t val)
{
    uint32_t orig = vvtd_get_reg(vvtd, DMAR_GSTS_REG);
    uint32_t changed;

    orig = orig & 0x96ffffff;    /* reset the one-shot bits */
    changed = orig ^ val;

    if ( !changed )
        return X86EMUL_OKAY;
    if ( (changed & (changed - 1)) )
        VVTD_DEBUG(VVTD_DBG_RW, "Guest attempts to update multiple fields "
                     "of GCMD_REG in one write transation.");

    if ( changed & DMA_GCMD_SIRTP )
        vvtd_handle_gcmd_sirtp(vvtd, val);
    if ( changed & DMA_GCMD_QIE )
        vvtd_handle_gcmd_qie(vvtd, val);
    if ( changed & DMA_GCMD_IRE )
        vvtd_handle_gcmd_ire(vvtd, val);
    if ( changed & ~(DMA_GCMD_QIE | DMA_GCMD_SIRTP | DMA_GCMD_IRE) )
        gdprintk(XENLOG_INFO, "Only QIE,SIRTP,IRE in GCMD_REG are handled.\n");

    return X86EMUL_OKAY;
}

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
        case DMAR_GCMD_REG:
            ret = vvtd_write_gcmd(vvtd, val);
            break;

        case DMAR_IEDATA_REG:
        case DMAR_IEADDR_REG:
        case DMAR_IEUADDR_REG:
        case DMAR_FEDATA_REG:
        case DMAR_FEADDR_REG:
        case DMAR_FEUADDR_REG:
        case DMAR_IRTA_REG:
        case DMAR_IRTA_REG_HI:
            vvtd_set_reg(vvtd, offset_aligned, val);
            ret = X86EMUL_OKAY;
            break;

        default:
            break;
        }
    }
    else /* len == 8 */
    {
        switch ( offset_aligned )
        {
        case DMAR_IRTA_REG:
            vvtd_set_reg_quad(vvtd, DMAR_IRTA_REG, val);
            ret = X86EMUL_OKAY;
            break;

        default:
            ret = X86EMUL_UNHANDLEABLE;
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

static bool ir_sid_valid(struct iremap_entry *irte, uint32_t source_id)
{
    return true;
}

/*
 * 'record_fault' is a flag to indicate whether we need recording a fault
 * and notifying guest when a fault happens during fetching vIRTE.
 */
static int vvtd_get_entry(struct vvtd *vvtd,
                          struct irq_remapping_request *irq,
                          struct iremap_entry *dest,
                          bool record_fault)
{
    int ret;
    uint32_t entry = irq_remapping_request_index(irq);
    struct iremap_entry  *irte, *irt_page;

    VVTD_DEBUG(VVTD_DBG_TRANS, "interpret a request with index %x", entry);

    if ( entry > vvtd->irt_max_entry )
    {
        ret = VTD_FR_IR_INDEX_OVER;
        goto handle_fault;
    }

    ret = map_guest_page(vvtd->domain, vvtd->irt + (entry >> IREMAP_ENTRY_ORDER),
                         (void**)&irt_page);
    if ( ret )
    {
        ret = VTD_FR_IR_ROOT_INVAL;
        goto handle_fault;
    }

    irte = irt_page + (entry % (1 << IREMAP_ENTRY_ORDER));
    dest->val = irte->val;
    if ( !qinval_present(*irte) )
    {
        ret = VTD_FR_IR_ENTRY_P;
        goto unmap_handle_fault;
    }

    /* Check reserved bits */
    if ( (irte->remap.res_1 || irte->remap.res_2 || irte->remap.res_3 ||
          irte->remap.res_4) )
    {
        ret = VTD_FR_IR_IRTE_RSVD;
        goto unmap_handle_fault;
    }

    if (!ir_sid_valid(irte, irq->source_id))
    {
        ret = VTD_FR_IR_SID_ERR;
        goto unmap_handle_fault;
    }
    unmap_guest_page(irt_page);
    return 0;

 unmap_handle_fault:
    unmap_guest_page(irt_page);
 handle_fault:
    if ( !record_fault )
        return ret;

    switch ( ret )
    {
    case VTD_FR_IR_SID_ERR:
    case VTD_FR_IR_IRTE_RSVD:
    case VTD_FR_IR_ENTRY_P:
        if ( qinval_fault_disable(*irte) )
            break;
    /* fall through */
    case VTD_FR_IR_INDEX_OVER:
    case VTD_FR_IR_ROOT_INVAL:
        vvtd_record_fault(vvtd, irq, ret);
        break;

    default:
        gdprintk(XENLOG_G_INFO, "Can't handle VT-d fault %x\n", ret);
    }
    return ret;
}

static int vvtd_irq_request_sanity_check(struct vvtd *vvtd,
                                         struct irq_remapping_request *irq)
{
    if ( irq->type == VIOMMU_REQUEST_IRQ_APIC )
    {
        struct IO_APIC_route_remap_entry rte = { { irq->msg.rte } };

        ASSERT(rte.format);
        return (!rte.reserved) ? 0 : VTD_FR_IR_REQ_RSVD;
    }
    else if ( irq->type == VIOMMU_REQUEST_IRQ_MSI )
    {
        struct msi_msg_remap_entry msi_msg = { { irq->msg.msi.addr } };

        ASSERT(msi_msg.address_lo.format);
        return 0;
    }
    BUG();
    return 0;
}

static int vvtd_handle_irq_request(struct domain *d,
                                   struct irq_remapping_request *irq)
{
    struct iremap_entry irte;
    int ret;
    struct vvtd *vvtd = domain_vvtd(d);

    if ( !vvtd || !vvtd_irq_remapping_enabled(vvtd) )
        return -EINVAL;

    ret = vvtd_irq_request_sanity_check(vvtd, irq);
    if ( ret )
    {
        vvtd_record_fault(vvtd, irq, ret);
        return ret;
    }

    if ( !vvtd_get_entry(vvtd, irq, &irte, true) )
    {
        vvtd_delivery(vvtd->domain, irte.remap.vector,
                      irte_dest(vvtd, irte.remap.dst), irte.remap.dm,
                      irte.remap.dlm, irte.remap.tm);
        return 0;
    }
    return -EFAULT;
}

static int vvtd_get_irq_info(struct domain *d,
                             struct irq_remapping_request *irq,
                             struct irq_remapping_info *info)
{
    int ret;
    struct iremap_entry irte;
    struct vvtd *vvtd = domain_vvtd(d);

    ret = vvtd_get_entry(vvtd, irq, &irte, false);
    if ( ret )
        return ret;

    info->vector = irte.remap.vector;
    info->dest = irte_dest(vvtd, irte.remap.dst);
    info->dest_mode = irte.remap.dm;
    info->delivery_mode = irte.remap.dlm;
    return 0;
}

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
    vvtd->eim = 0;
    vvtd->irt = 0;
    vvtd->irt_max_entry = 0;
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
    .destroy = vvtd_destroy,
    .handle_irq_request = vvtd_handle_irq_request,
    .get_irq_info = vvtd_get_irq_info
};

static int vvtd_register(void)
{
    viommu_register_type(VIOMMU_TYPE_INTEL_VTD, &vvtd_hvm_vmx_ops);
    return 0;
}
__initcall(vvtd_register);
