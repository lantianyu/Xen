/*
 * include/asm-x86/viommu.h
 *
 * Copyright (c) 2017 Intel Corporation.
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
#ifndef __ARCH_X86_VIOMMU_H__
#define __ARCH_X86_VIOMMU_H__

#include <xen/viommu.h>
#include <asm/types.h>

/* IRQ request type */
#define VIOMMU_REQUEST_IRQ_MSI          0
#define VIOMMU_REQUEST_IRQ_APIC         1

struct irq_remapping_request
{
    union {
        /* MSI */
        struct {
            u64 addr;
            u32 data;
        } msi;
        /* Redirection Entry in IOAPIC */
        u64 rte;
    } msg;
    u16 source_id;
    u8 type;
};

static inline void irq_request_ioapic_fill(struct irq_remapping_request *req,
                             uint32_t ioapic_id, uint64_t rte)
{
    ASSERT(req);
    req->type = VIOMMU_REQUEST_IRQ_APIC;
    req->source_id = ioapic_id;
    req->msg.rte = rte;
}

static inline void irq_request_msi_fill(struct irq_remapping_request *req,
                          uint32_t source_id, uint64_t addr, uint32_t data)
{
    ASSERT(req);
    req->type = VIOMMU_REQUEST_IRQ_MSI;
    req->source_id = source_id;
    req->msg.msi.addr = addr;
    req->msg.msi.data = data;
}

#endif /* __ARCH_X86_VIOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
