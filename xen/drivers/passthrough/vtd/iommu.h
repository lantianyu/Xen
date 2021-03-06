/*
 * Copyright (c) 2006, Intel Corporation.
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
 * Copyright (C) Ashok Raj <ashok.raj@intel.com>
 */

#ifndef _INTEL_IOMMU_H_
#define _INTEL_IOMMU_H_

#include <xen/iommu.h>
#include <asm/msi.h>

/*
 * Intel IOMMU register specification per version 2.4 public spec.
 */

#define DMAR_VER_REG            0x0  /* Arch version supported by this IOMMU */
#define DMAR_CAP_REG            0x8  /* Hardware supported capabilities */
#define DMAR_ECAP_REG           0x10 /* Extended capabilities supported */
#define DMAR_GCMD_REG           0x18 /* Global command register */
#define DMAR_GSTS_REG           0x1c /* Global status register */
#define DMAR_RTADDR_REG         0x20 /* Root entry table */
#define DMAR_CCMD_REG           0x28 /* Context command reg */
#define DMAR_FSTS_REG           0x34 /* Fault Status register */
#define DMAR_FECTL_REG          0x38 /* Fault control register */
#define DMAR_FEDATA_REG         0x3c /* Fault event interrupt data register */
#define DMAR_FEADDR_REG         0x40 /* Fault event interrupt addr register */
#define DMAR_FEUADDR_REG        0x44 /* Upper address register */
#define DMAR_AFLOG_REG          0x58 /* Advanced Fault control */
#define DMAR_PMEN_REG           0x64 /* Enable Protected Memory Region */
#define DMAR_PLMBASE_REG        0x68 /* PMRR Low addr */
#define DMAR_PLMLIMIT_REG       0x6c /* PMRR low limit */
#define DMAR_PHMBASE_REG        0x70 /* pmrr high base addr */
#define DMAR_PHMLIMIT_REG       0x78 /* pmrr high limit */
#define DMAR_IQH_REG            0x80 /* invalidation queue head */
#define DMAR_IQT_REG            0x88 /* invalidation queue tail */
#define DMAR_IQT_REG_HI         0x8c
#define DMAR_IQA_REG            0x90 /* invalidation queue addr */
#define DMAR_IQA_REG_HI         0x94
#define DMAR_ICS_REG            0x9c /* Invalidation complete status */
#define DMAR_IECTL_REG          0xa0 /* Invalidation event control */
#define DMAR_IEDATA_REG         0xa4 /* Invalidation event data */
#define DMAR_IEADDR_REG         0xa8 /* Invalidation event address */
#define DMAR_IEUADDR_REG        0xac /* Invalidation event address */
#define DMAR_IRTA_REG           0xb8 /* Interrupt remapping table addr */
#define DMAR_IRTA_REG_HI        0xbc
#define DMAR_PQH_REG            0xc0 /* Page request queue head */
#define DMAR_PQH_REG_HI         0xc4
#define DMAR_PQT_REG            0xc8 /* Page request queue tail*/
#define DMAR_PQT_REG_HI         0xcc
#define DMAR_PQA_REG            0xd0 /* Page request queue address */
#define DMAR_PQA_REG_HI         0xd4
#define DMAR_PRS_REG            0xdc /* Page request status */
#define DMAR_PECTL_REG          0xe0 /* Page request event control */
#define DMAR_PEDATA_REG         0xe4 /* Page request event data */
#define DMAR_PEADDR_REG         0xe8 /* Page request event address */
#define DMAR_PEUADDR_REG        0xec /* Page event upper address */
#define DMAR_MTRRCAP_REG        0x100 /* MTRR capability */
#define DMAR_MTRRCAP_REG_HI     0x104
#define DMAR_MTRRDEF_REG        0x108 /* MTRR default type */
#define DMAR_MTRRDEF_REG_HI     0x10c

#define OFFSET_STRIDE        (9)
#define dmar_readl(dmar, reg) readl((dmar) + (reg))
#define dmar_readq(dmar, reg) readq((dmar) + (reg))
#define dmar_writel(dmar, reg, val) writel(val, (dmar) + (reg))
#define dmar_writeq(dmar, reg, val) writeq(val, (dmar) + (reg))

#define VER_MAJOR(v)        (((v) & 0xf0) >> 4)
#define VER_MINOR(v)        ((v) & 0x0f)

/* CAP_REG */
/* (offset >> 4) << 24 */
#define DMA_DOMAIN_ID_SHIFT         16  /* 16-bit domain id for 64K domains */
#define DMA_DOMAIN_ID_MASK          ((1UL << DMA_DOMAIN_ID_SHIFT) - 1)
#define DMA_CAP_ND                  (((DMA_DOMAIN_ID_SHIFT - 4) / 2) & 7ULL)
#define DMA_MGAW                    39  /* Maximum Guest Address Width */
#define DMA_CAP_MGAW                (((DMA_MGAW - 1) & 0x3fULL) << 16)
#define DMA_MAMV                    18ULL
#define DMA_CAP_MAMV                (DMA_MAMV << 48)
#define DMA_CAP_PSI                 (1ULL << 39)
#define DMA_CAP_SLLPS               ((1ULL << 34) | (1ULL << 35))
#define DMAR_FRCD_REG_NR            1ULL
#define DMA_CAP_FRO_OFFSET          0x220ULL
#define DMA_CAP_FRO                 (DMA_CAP_FRO_OFFSET << 20)
#define DMA_CAP_NFR                 ((DMAR_FRCD_REG_NR - 1) << 40)

/* Supported Adjusted Guest Address Widths */
#define DMA_CAP_SAGAW_SHIFT         8
#define DMA_CAP_SAGAW_MASK          (0x1fULL << DMA_CAP_SAGAW_SHIFT)
 /* 39-bit AGAW, 3-level page-table */
#define DMA_CAP_SAGAW_39bit         (0x2ULL << DMA_CAP_SAGAW_SHIFT)
 /* 48-bit AGAW, 4-level page-table */
#define DMA_CAP_SAGAW_48bit         (0x4ULL << DMA_CAP_SAGAW_SHIFT)
#define DMA_CAP_SAGAW               DMA_CAP_SAGAW_39bit

/*
 * Decoding Capability Register
 */
#define cap_intr_post(c)       (((c) >> 59) & 1)
#define cap_read_drain(c)      (((c) >> 55) & 1)
#define cap_write_drain(c)     (((c) >> 54) & 1)
#define cap_max_amask_val(c)   (((c) >> 48) & 0x3f)
#define cap_num_fault_regs(c)  ((((c) >> 40) & 0xff) + 1)
#define cap_pgsel_inv(c)       (((c) >> 39) & 1)

#define cap_super_page_val(c)  (((c) >> 34) & 0xf)
#define cap_super_offset(c)    (((find_first_bit(&cap_super_page_val(c), 4)) \
                                 * OFFSET_STRIDE) + 21)
#define cap_sps_2mb(c)         ((c >> 34) & 1)
#define cap_sps_1gb(c)         ((c >> 35) & 1)
#define cap_sps_512gb(c)       ((c >> 36) & 1)
#define cap_sps_1tb(c)         ((c >> 37) & 1)

#define cap_fault_reg_offset(c)    ((((c) >> 24) & 0x3ff) * 16)

#define cap_isoch(c)        (((c) >> 23) & 1)
#define cap_qos(c)        (((c) >> 22) & 1)
#define cap_mgaw(c)        ((((c) >> 16) & 0x3f) + 1)
#define cap_sagaw(c)        (((c) >> 8) & 0x1f)
#define cap_caching_mode(c)    (((c) >> 7) & 1)
#define cap_phmr(c)        (((c) >> 6) & 1)
#define cap_plmr(c)        (((c) >> 5) & 1)
#define cap_rwbf(c)        (((c) >> 4) & 1)
#define cap_afl(c)        (((c) >> 3) & 1)
#define cap_ndoms(c)        (1 << (4 + 2 * ((c) & 0x7)))

/* ECAP_REG */
/* (offset >> 4) << 8 */
#define DMA_ECAP_QI                 (1ULL << 1)
/* Interrupt Remapping support */
#define DMA_ECAP_IR                 (1ULL << 3)
#define DMA_ECAP_EIM                (1ULL << 4)
#define DMA_ECAP_MHMV               (15ULL << 20)

/*
 * Extended Capability Register
 */

#define ecap_niotlb_iunits(e)    ((((e) >> 24) & 0xff) + 1)
#define ecap_iotlb_offset(e)     ((((e) >> 8) & 0x3ff) * 16)
#define ecap_coherent(e)         ((e >> 0) & 0x1)
#define ecap_queued_inval(e)     ((e >> 1) & 0x1)
#define ecap_dev_iotlb(e)        ((e >> 2) & 0x1)
#define ecap_intr_remap(e)       ((e >> 3) & 0x1)
#define ecap_eim(e)              ((e >> 4) & 0x1)
#define ecap_cache_hints(e)      ((e >> 5) & 0x1)
#define ecap_pass_thru(e)        ((e >> 6) & 0x1)
#define ecap_snp_ctl(e)          ((e >> 7) & 0x1)

/* IOTLB_REG */
#define DMA_TLB_FLUSH_GRANU_OFFSET  60
#define DMA_TLB_GLOBAL_FLUSH (((u64)1) << 60)
#define DMA_TLB_DSI_FLUSH (((u64)2) << 60)
#define DMA_TLB_PSI_FLUSH (((u64)3) << 60)
#define DMA_TLB_IIRG(x) (((x) >> 60) & 7) 
#define DMA_TLB_IAIG(val) (((val) >> 57) & 7)
#define DMA_TLB_DID(x) (((u64)(x & 0xffff)) << 32)

#define DMA_TLB_READ_DRAIN (((u64)1) << 49)
#define DMA_TLB_WRITE_DRAIN (((u64)1) << 48)
#define DMA_TLB_IVT (((u64)1) << 63)

#define DMA_TLB_IVA_ADDR(x) ((((u64)x) >> 12) << 12)
#define DMA_TLB_IVA_HINT(x) ((((u64)x) & 1) << 6)

/* GCMD_REG */
#define DMA_GCMD_TE     (((u64)1) << 31)
#define DMA_GCMD_SRTP   (((u64)1) << 30)
#define DMA_GCMD_SFL    (((u64)1) << 29)
#define DMA_GCMD_EAFL   (((u64)1) << 28)
#define DMA_GCMD_WBF    (((u64)1) << 27)
#define DMA_GCMD_QIE    (((u64)1) << 26)
#define DMA_GCMD_IRE    (((u64)1) << 25)
#define DMA_GCMD_SIRTP  (((u64)1) << 24)
#define DMA_GCMD_CFI    (((u64)1) << 23)

/* GSTS_REG */
#define DMA_GSTS_TES    (((u64)1) << 31)
#define DMA_GSTS_RTPS   (((u64)1) << 30)
#define DMA_GSTS_FLS    (((u64)1) << 29)
#define DMA_GSTS_AFLS   (((u64)1) << 28)
#define DMA_GSTS_WBFS   (((u64)1) << 27)
#define DMA_GSTS_QIES_BIT       26
#define DMA_GSTS_QIES           (((u64)1) << DMA_GSTS_QIES_BIT)
#define DMA_GSTS_IRES_BIT       25
#define DMA_GSTS_IRES   (((u64)1) << DMA_GSTS_IRES_BIT)
#define DMA_GSTS_SIRTPS_BIT     24
#define DMA_GSTS_SIRTPS (((u64)1) << DMA_GSTS_SIRTPS_BIT)
#define DMA_GSTS_CFIS   (((u64)1) <<23)

/* IRTA_REG */
#define DMA_IRTA_ADDR(val)      (val & ~0xfffULL)
#define DMA_IRTA_EIME(val)      (!!(val & (1 << 11)))
#define DMA_IRTA_S(val)         (val & 0xf)
#define DMA_IRTA_SIZE(val)      (1UL << (DMA_IRTA_S(val) + 1))

/* IQH_REG */
#define DMA_IQH_QH_SHIFT        4
#define DMA_IQH_QH(val)         ((val >> 4) & 0x7fffULL)

/* IQT_REG */
#define DMA_IQT_QT_SHIFT        4
#define DMA_IQT_QT(val)         ((val >> 4) & 0x7fffULL)
#define DMA_IQT_RSVD            0xfffffffffff80007ULL

/* IQA_REG */
#define DMA_MGAW                39  /* Maximum Guest Address Width */
#define DMA_IQA_ADDR(val)       (val & ~0xfffULL)
#define DMA_IQA_QS(val)         (val & 0x7)
#define DMA_IQA_ENTRY_PER_PAGE  (1 << 8)
#define DMA_IQA_RSVD            (~((1ULL << DMA_MGAW) -1 ) | 0xff8ULL)

/* IECTL_REG */
#define DMA_IECTL_IM_BIT 31
#define DMA_IECTL_IM            (1 << DMA_IECTL_IM_BIT)
#define DMA_IECTL_IP_BIT 30
#define DMA_IECTL_IP (((u64)1) << DMA_IECTL_IP_BIT)

/* ICS_REG */
#define DMA_ICS_IWC_BIT         0
#define DMA_ICS_IWC             (1 << DMA_ICS_IWC_BIT)

/* PMEN_REG */
#define DMA_PMEN_EPM    (((u32)1) << 31)
#define DMA_PMEN_PRS    (((u32)1) << 0)

/* CCMD_REG */
#define DMA_CCMD_INVL_GRANU_OFFSET  61
#define DMA_CCMD_ICC   (((u64)1) << 63)
#define DMA_CCMD_GLOBAL_INVL (((u64)1) << 61)
#define DMA_CCMD_DOMAIN_INVL (((u64)2) << 61)
#define DMA_CCMD_DEVICE_INVL (((u64)3) << 61)
#define DMA_CCMD_FM(m) (((u64)((m) & 0x3)) << 32)
#define DMA_CCMD_CIRG(x) ((((u64)3) << 61) & x)
#define DMA_CCMD_MASK_NOBIT 0
#define DMA_CCMD_MASK_1BIT 1
#define DMA_CCMD_MASK_2BIT 2
#define DMA_CCMD_MASK_3BIT 3
#define DMA_CCMD_SID(s) (((u64)((s) & 0xffff)) << 16)
#define DMA_CCMD_DID(d) ((u64)((d) & 0xffff))

#define DMA_CCMD_CAIG_MASK(x) (((u64)x) & ((u64) 0x3 << 59))

/* FECTL_REG */
#define DMA_FECTL_IM_BIT 31
#define DMA_FECTL_IM (((u64)1) << DMA_FECTL_IM_BIT)
#define DMA_FECTL_IP_BIT 30
#define DMA_FECTL_IP (((u64)1) << DMA_FECTL_IP_BIT)

/* FSTS_REG */
#define DMA_FSTS_PFO_BIT 0
#define DMA_FSTS_PFO ((u64)1 << DMA_FSTS_PFO_BIT)
#define DMA_FSTS_PPF_BIT 1
#define DMA_FSTS_PPF ((u64)1 << DMA_FSTS_PPF_BIT)
#define DMA_FSTS_AFO ((u64)1 << 2)
#define DMA_FSTS_APF ((u64)1 << 3)
#define DMA_FSTS_IQE_BIT 4
#define DMA_FSTS_IQE ((u64)1 << DMA_FSTS_IQE_BIT)
#define DMA_FSTS_ICE ((u64)1 << 5)
#define DMA_FSTS_ITE ((u64)1 << 6)
#define DMA_FSTS_PRO_BIT 7
#define DMA_FSTS_PRO ((u64)1 << DMA_FSTS_PRO_BIT)
#define DMA_FSTS_FAULTS    (DMA_FSTS_PFO | DMA_FSTS_PPF | DMA_FSTS_AFO | DMA_FSTS_APF | DMA_FSTS_IQE | DMA_FSTS_ICE | DMA_FSTS_ITE | DMA_FSTS_PRO)
#define DMA_FSTS_RW1CS     (DMA_FSTS_PFO | DMA_FSTS_AFO | DMA_FSTS_APF | DMA_FSTS_IQE | DMA_FSTS_ICE | DMA_FSTS_ITE | DMA_FSTS_PRO)
#define dma_fsts_fault_record_index(s) (((s) >> 8) & 0xff)

/* FRCD_REG, 32 bits access */
#define DMA_FRCD_LEN            0x10
#define DMA_FRCD0_OFFSET        0x0
#define DMA_FRCD1_OFFSET        0x4
#define DMA_FRCD2_OFFSET        0x8
#define DMA_FRCD3_OFFSET        0xc
#define DMA_FRCD3_FR_MASK       0xffUL
#define DMA_FRCD_F_BIT 31
#define DMA_FRCD_F ((u64)1 << DMA_FRCD_F_BIT)
#define DMA_FRCD(idx, offset) (DMA_CAP_FRO_OFFSET + DMA_FRCD_LEN * idx + offset)
#define dma_frcd_type(d) ((d >> 30) & 1)
#define dma_frcd_fault_reason(c) (c & 0xff)
#define dma_frcd_source_id(c) (c & 0xffff)
#define dma_frcd_page_addr(d) (d & (((u64)-1) << 12)) /* low 64 bit */

struct vtd_fault_record_register
{
    union {
        struct {
            u64 lo;
            u64 hi;
        } bits;
        struct {
            u64 rsvd0   :12,
                FI      :52; /* Fault Info */
            u64 SID     :16, /* Source Identifier */
                rsvd1   :9,
                PRIV    :1,  /* Privilege Mode Requested */
                EXE     :1,  /* Execute Permission Requested */
                PP      :1,  /* PASID Present */
                FR      :8,  /* Fault Reason */
                PV      :20, /* PASID Value */
                AT      :2,  /* Address Type */
                T       :1,  /* Type. (0) Write Request (1) Read Request or
                              * AtomicOp request
                              */
                F       :1;  /* Fault */
        } fields;
    };
};

enum VTD_FAULT_TYPE
{
    /* Interrupt remapping transition faults */
    VTD_FR_IR_REQ_RSVD = 0x20,   /* One or more IR request reserved
                                  * fields set */
    VTD_FR_IR_INDEX_OVER = 0x21, /* Index value greater than max */
    VTD_FR_IR_ENTRY_P = 0x22,    /* Present (P) not set in IRTE */
    VTD_FR_IR_ROOT_INVAL = 0x23, /* IR Root table invalid */
    VTD_FR_IR_IRTE_RSVD = 0x24,  /* IRTE Rsvd field non-zero with
                                  * Present flag set */
    VTD_FR_IR_REQ_COMPAT = 0x25, /* Encountered compatible IR
                                  * request while disabled */
    VTD_FR_IR_SID_ERR = 0x26,    /* Invalid Source-ID */
};

/*
 * 0: Present
 * 1-11: Reserved
 * 12-63: Context Ptr (12 - (haw-1))
 * 64-127: Reserved
 */
struct root_entry {
    u64    val;
    u64    rsvd1;
};
#define root_present(root)    ((root).val & 1)
#define set_root_present(root) do {(root).val |= 1;} while(0)
#define get_context_addr(root) ((root).val & PAGE_MASK_4K)
#define set_root_value(root, value) \
    do {(root).val |= ((value) & PAGE_MASK_4K);} while(0)

struct context_entry {
    u64 lo;
    u64 hi;
};
#define ROOT_ENTRY_NR (PAGE_SIZE_4K/sizeof(struct root_entry))
#define context_present(c) ((c).lo & 1)
#define context_fault_disable(c) (((c).lo >> 1) & 1)
#define context_translation_type(c) (((c).lo >> 2) & 3)
#define context_address_root(c) ((c).lo & PAGE_MASK_4K)
#define context_address_width(c) ((c).hi &  7)
#define context_domain_id(c) (((c).hi >> 8) & ((1 << 16) - 1))

#define context_set_present(c) do {(c).lo |= 1;} while(0)
#define context_clear_present(c) do {(c).lo &= ~1;} while(0)
#define context_set_fault_enable(c) \
    do {(c).lo &= (((u64)-1) << 2) | 1;} while(0)

#define context_set_translation_type(c, val) do { \
        (c).lo &= (((u64)-1) << 4) | 3; \
        (c).lo |= (val & 3) << 2; \
    } while(0)
#define CONTEXT_TT_MULTI_LEVEL 0
#define CONTEXT_TT_DEV_IOTLB   1
#define CONTEXT_TT_PASS_THRU   2

#define context_set_address_root(c, val) \
    do {(c).lo &= 0xfff; (c).lo |= (val) & PAGE_MASK_4K ;} while(0)
#define context_set_address_width(c, val) \
    do {(c).hi &= 0xfffffff8; (c).hi |= (val) & 7;} while(0)
#define context_clear_entry(c) do {(c).lo = 0; (c).hi = 0;} while(0)

/* page table handling */
#define LEVEL_STRIDE       (9)
#define LEVEL_MASK         ((1 << LEVEL_STRIDE) - 1)
#define PTE_NUM            (1 << LEVEL_STRIDE)
#define level_to_agaw(val) ((val) - 2)
#define agaw_to_level(val) ((val) + 2)
#define agaw_to_width(val) (30 + val * LEVEL_STRIDE)
#define width_to_agaw(w)   ((w - 30)/LEVEL_STRIDE)
#define level_to_offset_bits(l) (12 + (l - 1) * LEVEL_STRIDE)
#define address_level_offset(addr, level) \
            ((addr >> level_to_offset_bits(level)) & LEVEL_MASK)
#define offset_level_address(offset, level) \
            ((u64)(offset) << level_to_offset_bits(level))
#define level_mask(l) (((u64)(-1)) << level_to_offset_bits(l))
#define level_size(l) (1 << level_to_offset_bits(l))
#define align_to_level(addr, l) ((addr + level_size(l) - 1) & level_mask(l))

/*
 * 0: readable
 * 1: writable
 * 2-6: reserved
 * 7: super page
 * 8-11: available
 * 12-63: Host physcial address
 */
struct dma_pte {
    u64 val;
};
#define DMA_PTE_READ (1)
#define DMA_PTE_WRITE (2)
#define DMA_PTE_PROT (DMA_PTE_READ | DMA_PTE_WRITE)
#define DMA_PTE_SP   (1 << 7)
#define DMA_PTE_SNP  (1 << 11)
#define dma_clear_pte(p)    do {(p).val = 0;} while(0)
#define dma_set_pte_readable(p) do {(p).val |= DMA_PTE_READ;} while(0)
#define dma_set_pte_writable(p) do {(p).val |= DMA_PTE_WRITE;} while(0)
#define dma_set_pte_superpage(p) do {(p).val |= DMA_PTE_SP;} while(0)
#define dma_set_pte_snp(p)  do {(p).val |= DMA_PTE_SNP;} while(0)
#define dma_set_pte_prot(p, prot) do { \
        (p).val = ((p).val & ~DMA_PTE_PROT) | ((prot) & DMA_PTE_PROT); \
    } while (0)
#define dma_pte_addr(p) ((p).val & PADDR_MASK & PAGE_MASK_4K)
#define dma_set_pte_addr(p, addr) do {\
            (p).val |= ((addr) & PAGE_MASK_4K); } while (0)
#define dma_pte_present(p) (((p).val & DMA_PTE_PROT) != 0)
#define dma_pte_superpage(p) (((p).val & DMA_PTE_SP) != 0)

/* interrupt remap entry */
struct iremap_entry {
  union {
    __uint128_t val;
    struct { u64 lo, hi; };
    struct {
        u16 p       : 1,
            fpd     : 1,
            dm      : 1,
            rh      : 1,
            tm      : 1,
            dlm     : 3,
            avail   : 4,
            res_1   : 3,
            im      : 1;
        u8  vector;
        u8  res_2;
        u32 dst;
        u16 sid;
        u16 sq      : 2,
            svt     : 2,
            res_3   : 12;
        u32 res_4;
    } remap;
    struct {
        u16 p       : 1,
            fpd     : 1,
            res_1   : 6,
            avail   : 4,
            res_2   : 2,
            urg     : 1,
            im      : 1;
        u8  vector;
        u8  res_3;
        u32 res_4   : 6,
            pda_l   : 26;
        u16 sid;
        u16 sq      : 2,
            svt     : 2,
            res_5   : 12;
        u32 pda_h;
    } post;
  };
};

/*
 * Posted-interrupt descriptor address is 64 bits with 64-byte aligned, only
 * the upper 26 bits of lest significiant 32 bits is available.
 */
#define PDA_LOW_BIT    26

/* Max intr remapping table page order is 8, as max number of IRTEs is 64K */
#define IREMAP_PAGE_ORDER  8

/*
 * VTd engine handles 4K page, while CPU may have different page size on
 * different arch. E.g. 16K on IPF.
 */
#define IREMAP_ARCH_PAGE_ORDER  (IREMAP_PAGE_ORDER + PAGE_SHIFT_4K - PAGE_SHIFT)
#define IREMAP_ARCH_PAGE_NR     ( IREMAP_ARCH_PAGE_ORDER < 0 ?  \
                                1 :                             \
                                1 << IREMAP_ARCH_PAGE_ORDER )

/* Each entry is 16 bytes, so 2^8 entries per 4K page */
#define IREMAP_ENTRY_ORDER  ( PAGE_SHIFT - 4 )
#define IREMAP_ENTRY_NR     ( 1 << ( IREMAP_PAGE_ORDER + 8 ) )

#define iremap_present(v) ((v).lo & 1)
#define iremap_fault_disable(v) (((v).lo >> 1) & 1)

#define iremap_set_present(v) do {(v).lo |= 1;} while(0)
#define iremap_clear_present(v) do {(v).lo &= ~1;} while(0)

/*
 * Get the intr remap entry:
 * maddr   - machine addr of the table
 * index   - index of the entry
 * entries - return addr of the page holding this entry, need unmap it
 * entry   - return required entry
 */
#define GET_IREMAP_ENTRY(maddr, index, entries, entry)                        \
do {                                                                          \
    entries = (struct iremap_entry *)map_vtd_domain_page(                     \
              (maddr) + (( (index) >> IREMAP_ENTRY_ORDER ) << PAGE_SHIFT ) ); \
    entry = &entries[(index) % (1 << IREMAP_ENTRY_ORDER)];                    \
} while(0)

/* queue invalidation entry */
struct qinval_entry {
    union {
        struct {
            u64 lo;
            u64 hi;
        }val;
        struct {
            struct {
                u64 type    : 4,
                    granu   : 2,
                    res_1   : 10,
                    did     : 16,
                    sid     : 16,
                    fm      : 2,
                    res_2   : 14;
            }lo;
            struct {
                u64 res;
            }hi;
        }cc_inv_dsc;
        struct {
            struct {
                u64 type    : 4,
                    granu   : 2,
                    dw      : 1,
                    dr      : 1,
                    res_1   : 8,
                    did     : 16,
                    res_2   : 32;
            }lo;
            struct {
                u64 am      : 6,
                    ih      : 1,
                    res_1   : 5,
                    addr    : 52;
            }hi;
        }iotlb_inv_dsc;
        struct {
            struct {
                u64 type    : 4,
                    res_1   : 12,
                    max_invs_pend: 5,
                    res_2   : 11,
                    sid     : 16,
                    res_3   : 16;
            }lo;
            struct {
                u64 size    : 1,
                    res_1   : 11,
                    addr    : 52;
            }hi;
        }dev_iotlb_inv_dsc;
        struct {
            struct {
                u64 type    : 4,
                    granu   : 1,
                    res_1   : 22,
                    im      : 5,
                    iidx    : 16,
                    res_2   : 16;
            }lo;
            struct {
                u64 res;
            }hi;
        }iec_inv_dsc;
        struct {
            struct {
                u64 type    : 4,
                    iflag   : 1,
                    sw      : 1,
                    fn      : 1,
                    res_1   : 25,
                    sdata   : 32;
            }lo;
            struct {
                u64 res_1   : 2,
                    saddr   : 62;
            }hi;
        }inv_wait_dsc;
    }q;
};

/* Order of queue invalidation pages(max is 8) */
#define QINVAL_PAGE_ORDER   2

#define QINVAL_ARCH_PAGE_ORDER  (QINVAL_PAGE_ORDER + PAGE_SHIFT_4K - PAGE_SHIFT)
#define QINVAL_ARCH_PAGE_NR     ( QINVAL_ARCH_PAGE_ORDER < 0 ?  \
                                1 :                             \
                                1 << QINVAL_ARCH_PAGE_ORDER )

/* Each entry is 16 bytes, so 2^8 entries per page */
#define QINVAL_ENTRY_ORDER  ( PAGE_SHIFT - 4 )
#define QINVAL_ENTRY_NR     (1 << (QINVAL_PAGE_ORDER + 8))

/* Status data flag */
#define QINVAL_STAT_INIT  0
#define QINVAL_STAT_DONE  1

/* Queue invalidation head/tail shift */
#define QINVAL_INDEX_SHIFT 4

#define qinval_present(v) ((v).lo & 1)
#define qinval_fault_disable(v) (((v).lo >> 1) & 1)

#define qinval_set_present(v) do {(v).lo |= 1;} while(0)
#define qinval_clear_present(v) do {(v).lo &= ~1;} while(0)

#define RESERVED_VAL        0

#define TYPE_INVAL_CONTEXT      0x1
#define TYPE_INVAL_IOTLB        0x2
#define TYPE_INVAL_DEVICE_IOTLB 0x3
#define TYPE_INVAL_IEC          0x4
#define TYPE_INVAL_WAIT         0x5

#define NOTIFY_TYPE_POLL        1
#define NOTIFY_TYPE_INTR        1
#define INTERRUTP_FLAG          1
#define STATUS_WRITE            1
#define FENCE_FLAG              1

#define IEC_GLOBAL_INVL         0
#define IEC_INDEX_INVL          1
#define IRTA_EIME               (((u64)1) << 11)

/* 2^(IRTA_REG_TABLE_SIZE + 1) = IREMAP_ENTRY_NR */
#define IRTA_REG_TABLE_SIZE     ( IREMAP_PAGE_ORDER + 7 )

#define VTD_PAGE_TABLE_LEVEL_3  3
#define VTD_PAGE_TABLE_LEVEL_4  4

#define MAX_IOMMU_REGS 0xc0

extern struct list_head acpi_drhd_units;
extern struct list_head acpi_rmrr_units;
extern struct list_head acpi_ioapic_units;

struct qi_ctrl {
    u64 qinval_maddr;  /* queue invalidation page machine address */
};

struct ir_ctrl {
    u64 iremap_maddr;            /* interrupt remap table machine address */
    int iremap_num;              /* total num of used interrupt remap entry */
    spinlock_t iremap_lock;      /* lock for irq remappping table */
};

struct iommu_flush {
    int __must_check (*context)(void *iommu, u16 did, u16 source_id,
                                u8 function_mask, u64 type,
                                bool_t non_present_entry_flush);
    int __must_check (*iotlb)(void *iommu, u16 did, u64 addr,
                              unsigned int size_order, u64 type,
                              bool_t flush_non_present_entry,
                              bool_t flush_dev_iotlb);
};

struct intel_iommu {
    struct qi_ctrl qi_ctrl;
    struct ir_ctrl ir_ctrl;
    struct iommu_flush flush;
    struct acpi_drhd_unit *drhd;
};

struct iommu {
    struct list_head list;
    void __iomem *reg; /* Pointer to hardware regs, virtual addr */
    u32	index;         /* Sequence number of iommu */
    u32 nr_pt_levels;
    u64	cap;
    u64	ecap;
    spinlock_t lock; /* protect context, domain ids */
    spinlock_t register_lock; /* protect iommu register handling */
    u64 root_maddr; /* root entry machine address */
    struct msi_desc msi;
    struct intel_iommu *intel;
    struct list_head ats_devices;
    unsigned long *domid_bitmap;  /* domain id bitmap */
    u16 *domid_map;               /* domain id mapping array */
};

static inline struct qi_ctrl *iommu_qi_ctrl(struct iommu *iommu)
{
    return iommu ? &iommu->intel->qi_ctrl : NULL;
}

static inline struct ir_ctrl *iommu_ir_ctrl(struct iommu *iommu)
{
    return iommu ? &iommu->intel->ir_ctrl : NULL;
}

static inline struct iommu_flush *iommu_get_flush(struct iommu *iommu)
{
    return iommu ? &iommu->intel->flush : NULL;
}

#define INTEL_IOMMU_DEBUG(fmt, args...) \
    do  \
    {   \
        if ( iommu_debug )  \
            dprintk(XENLOG_WARNING VTDPREFIX, fmt, ## args);    \
    } while(0)

#endif
