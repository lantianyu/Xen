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
#include <xen/lib.h>
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
#include <asm/viommu.h>

#include "iommu.h"
#include "vtd.h"

/* Supported capabilities by vvtd */
unsigned int vvtd_caps = VIOMMU_CAP_IRQ_REMAPPING;

struct hvm_hw_vvtd_status {
    uint32_t eim_enabled : 1,
             intremap_enabled : 1;
    uint32_t fault_index;
    uint32_t irt_max_entry;
    /* Interrupt remapping table base gfn */
    uint64_t irt;
};

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

    struct hvm_hw_vvtd_status status;
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

static inline int vvtd_test_and_set_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    return test_and_set_bit(nr, &vvtd->regs->data32[reg/sizeof(uint32_t)]);
}

static inline int vvtd_test_and_clear_bit(struct vvtd *vvtd, uint32_t reg,
                                          int nr)
{
    return test_and_clear_bit(nr, &vvtd->regs->data32[reg/sizeof(uint32_t)]);
}

static inline int vvtd_test_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    return test_bit(nr, &vvtd->regs->data32[reg/sizeof(uint32_t)]);
}

static inline void vvtd_set_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    __set_bit(nr, &vvtd->regs->data32[reg/sizeof(uint32_t)]);
}

static inline void vvtd_clear_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    __clear_bit(nr, &vvtd->regs->data32[reg/sizeof(uint32_t)]);
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

static void* map_guest_page(struct domain *d, uint64_t gfn)
{
    struct page_info *p;
    void *ret;

    p = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
    if ( !p )
        return ERR_PTR(-EINVAL);

    if ( !get_page_type(p, PGT_writable_page) )
    {
        put_page(p);
        return ERR_PTR(-EINVAL);
    }

    ret = __map_domain_page_global(p);
    if ( !ret )
    {
        put_page_and_type(p);
        return ERR_PTR(-ENOMEM);
    }

    return ret;
}

static void unmap_guest_page(void *virt)
{
    struct page_info *page;

    ASSERT((unsigned long)virt & PAGE_MASK);
    page = mfn_to_page(domain_page_map_to_mfn(virt));

    unmap_domain_page_global(virt);
    put_page_and_type(page);
}

static void vvtd_inj_irq(struct vlapic *target, uint8_t vector,
                         uint8_t trig_mode, uint8_t delivery_mode)
{
    vvtd_debug("dest=v%d, delivery_mode=%x vector=%d trig_mode=%d\n",
               vlapic_vcpu(target)->vcpu_id, delivery_mode, vector, trig_mode);

    ASSERT((delivery_mode == dest_Fixed) ||
           (delivery_mode == dest_LowestPrio));

    vlapic_set_irq(target, vector, trig_mode);
}

static int vvtd_delivery(struct domain *d, uint8_t vector,
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
        vvtd_debug("null round robin: vector=%02x\n", vector);
        break;

    case dest_Fixed:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest, dest_mode) )
                vvtd_inj_irq(vcpu_vlapic(v), vector, trig_mode, delivery_mode);
        break;

    case dest_NMI:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest, dest_mode) &&
                 !test_and_set_bool(v->nmi_pending) )
                vcpu_kick(v);
        break;

    default:
        gdprintk(XENLOG_WARNING, "Unsupported VTD delivery mode %d\n",
                 delivery_mode);
        return -EINVAL;
    }

    return 0;
}

void vvtd_generate_interrupt(const struct vvtd *vvtd, uint32_t addr,
                             uint32_t data)
{
    uint8_t dest, dm, dlm, tm, vector;

    vvtd_debug("Sending interrupt %x %x to d%d",
               addr, data, vvtd->domain->domain_id);

    dest = MASK_EXTR(addr, MSI_ADDR_DEST_ID_MASK);
    dm = !!(addr & MSI_ADDR_DESTMODE_MASK);
    dlm = MASK_EXTR(data, MSI_DATA_DELIVERY_MODE_MASK);
    tm = MASK_EXTR(data, MSI_DATA_TRIGGER_MASK);
    vector = data & MSI_DATA_VECTOR_MASK;

    vvtd_delivery(vvtd->domain, vector, dest, dm, dlm, tm);
}

static uint32_t irq_remapping_request_index(
    const struct arch_irq_remapping_request *irq)
{
    if ( irq->type == VIOMMU_REQUEST_IRQ_MSI )
    {
        uint32_t index;
        struct msi_msg_remap_entry msi_msg =
        {
            .address_lo = { .val = irq->msg.msi.addr },
            .data = irq->msg.msi.data,
        };

        index = (msi_msg.address_lo.index_15 << 15) +
                msi_msg.address_lo.index_0_14;
        if ( msi_msg.address_lo.SHV )
            index += (uint16_t)msi_msg.data;

        return index;
    }
    else if ( irq->type == VIOMMU_REQUEST_IRQ_APIC )
    {
        struct IO_APIC_route_remap_entry remap_rte = { .val = irq->msg.rte };

        return (remap_rte.index_15 << 15) + remap_rte.index_0_14;
    }
    ASSERT_UNREACHABLE();

    return 0;
}

static inline uint32_t irte_dest(struct vvtd *vvtd, uint32_t dest)
{
    /* In xAPIC mode, only 8-bits([15:8]) are valid */
    return vvtd->status.eim_enabled ? dest :
           MASK_EXTR(dest, IRTE_xAPIC_DEST_MASK);
}

static void vvtd_report_non_recoverable_fault(struct vvtd *vvtd, int reason)
{
    uint32_t fsts;

    fsts = vvtd_get_reg(vvtd, DMAR_FSTS_REG);
    vvtd_set_bit(vvtd, DMAR_FSTS_REG, reason);

    /*
     * Accoroding to VT-d spec "Non-Recoverable Fault Event" chapter, if
     * there are any previously reported interrupt conditions that are yet to
     * be sevices by software, the Fault Event interrrupt is not generated.
     */
    if ( fsts & DMA_FSTS_FAULTS )
        return;

    vvtd_set_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_SHIFT);
    if ( !vvtd_test_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IM_SHIFT) )
    {
        uint32_t fe_data, fe_addr;
        fe_data = vvtd_get_reg(vvtd, DMAR_FEDATA_REG);
        fe_addr = vvtd_get_reg(vvtd, DMAR_FEADDR_REG);
        vvtd_generate_interrupt(vvtd, fe_addr, fe_data);
        vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_SHIFT);
    }
}

static void vvtd_update_ppf(struct vvtd *vvtd)
{
    int i;
    uint64_t cap = vvtd_get_reg(vvtd, DMAR_CAP_REG);
    unsigned int base = cap_fault_reg_offset(cap);

    for ( i = 0; i < cap_num_fault_regs(cap); i++ )
    {
        if ( vvtd_test_bit(vvtd, base + i * DMA_FRCD_LEN + DMA_FRCD3_OFFSET,
                           DMA_FRCD_F_SHIFT) )
        {
            vvtd_report_non_recoverable_fault(vvtd, DMA_FSTS_PPF_SHIFT);
            return;
        }
    }
    /*
     * No Primary Fault is in Fault Record Registers, thus clear PPF bit in
     * FSTS.
     */
    vvtd_clear_bit(vvtd, DMAR_FSTS_REG, DMA_FSTS_PPF_SHIFT);

    /* If no fault is in FSTS, clear pending bit in FECTL. */
    if ( !(vvtd_get_reg(vvtd, DMAR_FSTS_REG) & DMA_FSTS_FAULTS) )
        vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_SHIFT);
}

/*
 * Commit a fault to emulated Fault Record Registers.
 */
static void vvtd_commit_frcd(struct vvtd *vvtd, int idx,
                             struct vtd_fault_record_register *frcd)
{
    uint64_t cap = vvtd_get_reg(vvtd, DMAR_CAP_REG);
    unsigned int base = cap_fault_reg_offset(cap);

    vvtd_set_reg_quad(vvtd, base + idx * DMA_FRCD_LEN, frcd->bits.lo);
    vvtd_set_reg_quad(vvtd, base + idx * DMA_FRCD_LEN + 8, frcd->bits.hi);
    vvtd_update_ppf(vvtd);
}

/*
 * Allocate a FRCD for the caller. If success, return the FRI. Or, return -1
 * when failure.
 */
static int vvtd_alloc_frcd(struct vvtd *vvtd)
{
    int prev;
    uint64_t cap = vvtd_get_reg(vvtd, DMAR_CAP_REG);
    unsigned int base = cap_fault_reg_offset(cap);

    /* Set the F bit to indicate the FRCD is in use. */
    if ( !vvtd_test_and_set_bit(vvtd,
                                base + vvtd->status.fault_index * DMA_FRCD_LEN +
                                DMA_FRCD3_OFFSET, DMA_FRCD_F_SHIFT) )
    {
        prev = vvtd->status.fault_index;
        vvtd->status.fault_index = (prev + 1) % cap_num_fault_regs(cap);
        return vvtd->status.fault_index;
    }
    return -ENOMEM;
}

static void vvtd_free_frcd(struct vvtd *vvtd, int i)
{
    uint64_t cap = vvtd_get_reg(vvtd, DMAR_CAP_REG);
    unsigned int base = cap_fault_reg_offset(cap);

    vvtd_clear_bit(vvtd, base + i * DMA_FRCD_LEN + DMA_FRCD3_OFFSET,
                   DMA_FRCD_F_SHIFT);
}

static int vvtd_record_fault(struct vvtd *vvtd,
                             struct arch_irq_remapping_request *request,
                             int reason)
{
    struct vtd_fault_record_register frcd;
    int fault_index;

    switch(reason)
    {
    case VTD_FR_IR_REQ_RSVD:
    case VTD_FR_IR_INDEX_OVER:
    case VTD_FR_IR_ENTRY_P:
    case VTD_FR_IR_ROOT_INVAL:
    case VTD_FR_IR_IRTE_RSVD:
    case VTD_FR_IR_REQ_COMPAT:
    case VTD_FR_IR_SID_ERR:
        if ( vvtd_test_bit(vvtd, DMAR_FSTS_REG, DMA_FSTS_PFO_SHIFT) )
            return X86EMUL_OKAY;

        /* No available Fault Record means Fault overflowed */
        fault_index = vvtd_alloc_frcd(vvtd);
        if ( fault_index == -1 )
        {
            vvtd_report_non_recoverable_fault(vvtd, DMA_FSTS_PFO_SHIFT);
            return X86EMUL_OKAY;
        }
        memset(&frcd, 0, sizeof(frcd));
        frcd.fields.fault_reason = (uint8_t)reason;
        frcd.fields.fault_info = ((uint64_t)irq_remapping_request_index(request)) << 36;
        frcd.fields.source_id = (uint16_t)request->source_id;
        frcd.fields.fault = 1;
        vvtd_commit_frcd(vvtd, fault_index, &frcd);
        return X86EMUL_OKAY;

    default:
        ASSERT_UNREACHABLE();
        break;
    }

    gdprintk(XENLOG_ERR, "Can't handle vVTD Fault (reason 0x%x).", reason);
    domain_crash(vvtd->domain);
    return X86EMUL_OKAY;
}

static int vvtd_write_frcd3(struct vvtd *vvtd, uint32_t val)
{
    /* Writing a 1 means clear fault */
    if ( val & DMA_FRCD_F )
    {
        vvtd_free_frcd(vvtd, 0);
        vvtd_update_ppf(vvtd);
    }
    return X86EMUL_OKAY;
}

static int vvtd_write_fectl(struct vvtd *vvtd, uint32_t val)
{
    /*
     * Only DMA_FECTL_IM bit is writable. Generate pending event when unmask.
     */
    if ( !(val & DMA_FECTL_IM) )
    {
        /* Clear IM */
        vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IM_SHIFT);
        if ( vvtd_test_and_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_SHIFT) )
        {
            uint32_t fe_data, fe_addr;

            fe_data = vvtd_get_reg(vvtd, DMAR_FEDATA_REG);
            fe_addr = vvtd_get_reg(vvtd, DMAR_FEADDR_REG);
            vvtd_generate_interrupt(vvtd, fe_addr, fe_data);
        }
    }
    else
        vvtd_set_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IM_SHIFT);

    return X86EMUL_OKAY;
}

static int vvtd_write_fsts(struct vvtd *vvtd, uint32_t val)
{
    int i, max_fault_index = DMA_FSTS_PRO_SHIFT;
    uint64_t bits_to_clear = val & DMA_FSTS_RW1CS;

    if ( bits_to_clear )
    {
        i = find_first_bit(&bits_to_clear, max_fault_index / 8 + 1);
        while ( i <= max_fault_index )
        {
            vvtd_clear_bit(vvtd, DMAR_FSTS_REG, i);
            i = find_next_bit(&bits_to_clear, max_fault_index / 8 + 1, i + 1);
        }
    }

    /*
     * Clear IP field when all status fields in the Fault Status Register
     * being clear.
     */
    if ( !((vvtd_get_reg(vvtd, DMAR_FSTS_REG) & DMA_FSTS_FAULTS)) )
        vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_SHIFT);

    return X86EMUL_OKAY;
}

static void vvtd_handle_gcmd_ire(struct vvtd *vvtd, uint32_t val)
{
    vvtd_info("%sable Interrupt Remapping",
              (val & DMA_GCMD_IRE) ? "En" : "Dis");

    if ( val & DMA_GCMD_IRE )
    {
        vvtd->status.intremap_enabled = true;
        vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_IRES_SHIFT);
    }
    else
    {
        vvtd->status.intremap_enabled = false;
        vvtd_clear_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_IRES_SHIFT);
    }
}

static void vvtd_handle_gcmd_qie(struct vvtd *vvtd, uint32_t val)
{
    vvtd_info("%sable Queue Invalidation", (val & DMA_GCMD_QIE) ? "En" : "Dis");

    if ( val & DMA_GCMD_QIE )
        vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_QIES_SHIFT);
    else
    {
        vvtd_set_reg_quad(vvtd, DMAR_IQH_REG, 0);
        vvtd_clear_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_QIES_SHIFT);
    }
}

static void vvtd_handle_gcmd_sirtp(struct vvtd *vvtd, uint32_t val)
{
    uint64_t irta = vvtd_get_reg_quad(vvtd, DMAR_IRTA_REG);

    if ( !(val & DMA_GCMD_SIRTP) )
        return;

    if ( vvtd->status.intremap_enabled )
        vvtd_info("Update Interrupt Remapping Table when active\n");

    vvtd->status.irt = DMA_IRTA_ADDR(irta) >> PAGE_SHIFT;
    vvtd->status.irt_max_entry = DMA_IRTA_SIZE(irta);
    vvtd->status.eim_enabled = !!(irta & IRTA_EIME);
    vvtd_info("Update IR info (addr=%lx eim=%d size=%d).",
              vvtd->status.irt, vvtd->status.eim_enabled,
              vvtd->status.irt_max_entry);
    vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_SIRTPS_SHIFT);
}

static int vvtd_write_gcmd(struct vvtd *vvtd, uint32_t val)
{
    uint32_t orig = vvtd_get_reg(vvtd, DMAR_GSTS_REG);
    uint32_t changed;

    orig = orig & DMA_GCMD_ONE_SHOT_MASK;   /* reset the one-shot bits */
    changed = orig ^ val;

    if ( !changed )
        return X86EMUL_OKAY;

    if ( changed & (changed - 1) )
        vvtd_info("Guest attempts to write %x to GCMD (current GSTS is %x)," 
                  "it would lead to update multiple fields",
                  val, orig);

    if ( changed & DMA_GCMD_SIRTP )
        vvtd_handle_gcmd_sirtp(vvtd, val);
    if ( changed & DMA_GCMD_IRE )
        vvtd_handle_gcmd_ire(vvtd, val);
    if ( changed & DMA_GCMD_QIE )
        vvtd_handle_gcmd_qie(vvtd, val);
    if ( changed & ~(DMA_GCMD_SIRTP | DMA_GCMD_IRE | DMA_GCMD_QIE) )
        vvtd_info("Only SIRTP, IRE, QIE in GCMD are handled");

    return X86EMUL_OKAY;
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
    uint64_t cap = vvtd_get_reg(vvtd, DMAR_CAP_REG);
    unsigned int offset = addr - vvtd->base_addr;
    unsigned int fault_offset = cap_fault_reg_offset(cap);

    vvtd_info("Write offset %x len %d val %lx\n", offset, len, val);

    if ( (len != 4 && len != 8) || (offset & (len - 1)) )
        return X86EMUL_OKAY;

    if ( len == 4 )
    {
        switch ( offset )
        {
        case DMAR_GCMD_REG:
            return vvtd_write_gcmd(vvtd, val);

        case DMAR_FSTS_REG:
            return vvtd_write_fsts(vvtd, val);

        case DMAR_FECTL_REG:
            return vvtd_write_fectl(vvtd, val);

        case DMAR_IEDATA_REG:
        case DMAR_IEADDR_REG:
        case DMAR_IEUADDR_REG:
        case DMAR_FEDATA_REG:
        case DMAR_FEADDR_REG:
        case DMAR_FEUADDR_REG:
        case DMAR_IRTA_REG:
        case DMAR_IRTA_REG_HI:
            vvtd_set_reg(vvtd, offset, val);
            break;

        default:
            if ( offset == fault_offset + DMA_FRCD3_OFFSET )
                return vvtd_write_frcd3(vvtd, val);

            break;
        }
    }
    else /* len == 8 */
    {
        switch ( offset )
        {
        case DMAR_IRTA_REG:
            vvtd_set_reg_quad(vvtd, DMAR_IRTA_REG, val);
            break;

        default:
            if ( offset == fault_offset + DMA_FRCD2_OFFSET )
                return vvtd_write_frcd3(vvtd, val >> 32);

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

static void vvtd_handle_fault(struct vvtd *vvtd,
                              struct arch_irq_remapping_request *irq,
                              struct iremap_entry *irte,
                              unsigned int fault,
                              bool record_fault)
{
   if ( !record_fault )
        return;

    switch ( fault )
    {
    case VTD_FR_IR_SID_ERR:
    case VTD_FR_IR_IRTE_RSVD:
    case VTD_FR_IR_ENTRY_P:
        if ( qinval_fault_disable(*irte) )
            break;
    /* fall through */
    case VTD_FR_IR_INDEX_OVER:
    case VTD_FR_IR_ROOT_INVAL:
        vvtd_record_fault(vvtd, irq, fault);
        break;

    default:
        gdprintk(XENLOG_INFO, "Can't handle VT-d fault %x\n", fault);
    }
    return;
}

static bool vvtd_irq_request_sanity_check(const struct vvtd *vvtd,
                                          struct arch_irq_remapping_request *irq)
{
    if ( irq->type == VIOMMU_REQUEST_IRQ_APIC )
    {
        struct IO_APIC_route_remap_entry rte = { .val = irq->msg.rte };

        ASSERT(rte.format);
        return !!rte.reserved;
    }
    else if ( irq->type == VIOMMU_REQUEST_IRQ_MSI )
    {
        struct msi_msg_remap_entry msi_msg =
        { .address_lo = { .val = irq->msg.msi.addr } };

        ASSERT(msi_msg.address_lo.format);
        return 0;
    }
    ASSERT_UNREACHABLE();

    return 0;
}

/*
 * 'record_fault' is a flag to indicate whether we need recording a fault
 * and notifying guest when a fault happens during fetching vIRTE.
 */
static int vvtd_get_entry(struct vvtd *vvtd,
                          struct arch_irq_remapping_request *irq,
                          struct iremap_entry *dest,
                          bool record_fault)
{
    uint32_t entry = irq_remapping_request_index(irq);
    struct iremap_entry  *irte, *irt_page;

    vvtd_debug("interpret a request with index %x\n", entry);

    if ( vvtd_irq_request_sanity_check(vvtd, irq) )
    {
        vvtd_handle_fault(vvtd, irq, NULL, VTD_FR_IR_REQ_RSVD, record_fault);
        return -EINVAL;
    }

    if ( entry > vvtd->status.irt_max_entry )
    {
        vvtd_handle_fault(vvtd, irq, NULL, VTD_FR_IR_INDEX_OVER, record_fault);
        return -EACCES;
    }

    irt_page = map_guest_page(vvtd->domain,
                              vvtd->status.irt + (entry >> IREMAP_ENTRY_ORDER));
    if ( IS_ERR(irt_page) )
    {
        vvtd_handle_fault(vvtd, irq, NULL, VTD_FR_IR_ROOT_INVAL, record_fault);
        return PTR_ERR(irt_page);
    }

    irte = irt_page + (entry % (1 << IREMAP_ENTRY_ORDER));
    dest->val = irte->val;
    if ( !qinval_present(*irte) )
    {
        vvtd_handle_fault(vvtd, irq, NULL, VTD_FR_IR_ENTRY_P, record_fault);
        unmap_guest_page(irt_page);
        return -ENOENT;
    }

    /* Check reserved bits */
    if ( (irte->remap.res_1 || irte->remap.res_2 || irte->remap.res_3 ||
          irte->remap.res_4) )
    {
        vvtd_handle_fault(vvtd, irq, NULL, VTD_FR_IR_IRTE_RSVD, record_fault);
        unmap_guest_page(irt_page);
        return -EINVAL;
    }

    /* FIXME: We don't check against the source ID */
    unmap_guest_page(irt_page);

    return 0;
}

static int vvtd_handle_irq_request(struct domain *d,
                                   struct arch_irq_remapping_request *irq)
{
    struct iremap_entry irte;
    int ret;
    struct vvtd *vvtd = domain_vvtd(d);

    if ( !vvtd || !vvtd->status.intremap_enabled )
        return -ENODEV;

    ret = vvtd_get_entry(vvtd, irq, &irte, true);
    if ( ret )
        return ret;

    return vvtd_delivery(vvtd->domain, irte.remap.vector,
                         irte_dest(vvtd, irte.remap.dst),
                         irte.remap.dm, irte.remap.dlm,
                         irte.remap.tm);
}

static int vvtd_get_irq_info(struct domain *d,
                             struct arch_irq_remapping_request *irq,
                             struct arch_irq_remapping_info *info)
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

/* Probe whether the interrupt request is an remapping format */
static bool vvtd_is_remapping(struct domain *d,
                              struct arch_irq_remapping_request *irq)
{
    if ( irq->type == VIOMMU_REQUEST_IRQ_APIC )
    {
        struct IO_APIC_route_remap_entry rte = { .val = irq->msg.rte };

        return rte.format;
    }
    else if ( irq->type == VIOMMU_REQUEST_IRQ_MSI )
    {
        struct msi_msg_remap_entry msi_msg =
        { .address_lo = { .val = irq->msg.msi.addr } };

        return msi_msg.address_lo.format;
    }
    ASSERT_UNREACHABLE();

    return 0;
}

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
    .destroy = vvtd_destroy,
    .handle_irq_request = vvtd_handle_irq_request,
    .get_irq_info = vvtd_get_irq_info,
    .check_irq_remapping = vvtd_is_remapping
};

static int vvtd_register(void)
{
    viommu_register_type(VIOMMU_TYPE_INTEL_VTD, &vvtd_hvm_vmx_ops);
    return 0;
}
__initcall(vvtd_register);
