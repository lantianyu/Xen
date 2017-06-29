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

#define OFFSET_STRIDE        (9)
#define dmar_readl(dmar, reg) readl((dmar) + (reg))
#define dmar_readq(dmar, reg) readq((dmar) + (reg))
#define dmar_writel(dmar, reg, val) writel(val, (dmar) + (reg))
#define dmar_writeq(dmar, reg, val) writeq(val, (dmar) + (reg))

#define VER_MAJOR(v)        (((v) & 0xf0) >> 4)
#define VER_MINOR(v)        ((v) & 0x0f)

/* Supported Adjusted Guest Address Widths */
#define DMA_CAP_SAGAW_SHIFT         8
 /* 39-bit AGAW, 3-level page-table */
#define DMA_CAP_SAGAW_39bit         (0x2ULL << DMA_CAP_SAGAW_SHIFT)
#define DMA_CAP_ND_64K              6ULL

/*
 * Decoding Capability Register
 */
#define cap_intr_post(c)       (((c) >> 59) & 1)
#define cap_read_drain(c)      (((c) >> 55) & 1)
#define cap_write_drain(c)     (((c) >> 54) & 1)
#define cap_max_amask_val(c)   (((c) >> 48) & 0x3f)
#define cap_num_fault_regs(c)  ((((c) >> 40) & 0xff) + 1)
#define cap_set_num_fault_regs(c)  ((((c) - 1) & 0xff) << 40)
#define cap_pgsel_inv(c)       (((c) >> 39) & 1)

#define cap_super_page_val(c)  (((c) >> 34) & 0xf)
#define cap_super_offset(c)    (((find_first_bit(&cap_super_page_val(c), 4)) \
                                 * OFFSET_STRIDE) + 21)
#define cap_sps_2mb(c)         ((c >> 34) & 1)
#define cap_sps_1gb(c)         ((c >> 35) & 1)
#define cap_sps_512gb(c)       ((c >> 36) & 1)
#define cap_sps_1tb(c)         ((c >> 37) & 1)

#define cap_fault_reg_offset(c)    ((((c) >> 24) & 0x3ff) * 16)
#define cap_set_fault_reg_offset(c) ((((c) / 16) & 0x3ff) << 24 )

#define cap_isoch(c)        (((c) >> 23) & 1)
#define cap_qos(c)        (((c) >> 22) & 1)
#define cap_mgaw(c)        ((((c) >> 16) & 0x3f) + 1)
#define cap_set_mgaw(c)     ((((c) - 1) & 0x3f) << 16)
#define cap_sagaw(c)        (((c) >> DMA_CAP_SAGAW_SHIFT) & 0x1f)
#define cap_caching_mode(c)    (((c) >> 7) & 1)
#define cap_phmr(c)        (((c) >> 6) & 1)
#define cap_plmr(c)        (((c) >> 5) & 1)
#define cap_rwbf(c)        (((c) >> 4) & 1)
#define cap_afl(c)        (((c) >> 3) & 1)
#define cap_ndoms(c)        (1 << (4 + 2 * ((c) & 0x7)))

/*
 * Extended Capability Register
 */

#define ecap_niotlb_iunits(e)    ((((e) >> 24) & 0xff) + 1)
#define ecap_iotlb_offset(e)     ((((e) >> 8) & 0x3ff) * 16)
#define ecap_coherent(e)         ((e >> 0) & 0x1)
#define DMA_ECAP_QI_SHIFT        1
#define DMA_ECAP_QI              (1ULL << DMA_ECAP_QI_SHIFT)
#define ecap_queued_inval(e)     ((e >> DMA_ECAP_QI_SHIFT) & 0x1)
#define ecap_dev_iotlb(e)        ((e >> 2) & 0x1)
#define DMA_ECAP_IR_SHIFT        3
#define DMA_ECAP_IR              (1ULL << DMA_ECAP_IR_SHIFT)
#define ecap_intr_remap(e)       ((e >> DMA_ECAP_IR_SHIFT) & 0x1)
#define DMA_ECAP_EIM_SHIFT       4
#define DMA_ECAP_EIM             (1ULL << DMA_ECAP_EIM_SHIFT)
#define ecap_eim(e)              ((e >> DMA_ECAP_EIM_SHIFT) & 0x1)
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
/* mask of one-shot bits */
#define DMA_GCMD_ONE_SHOT_MASK 0x96ffffff 

/* GSTS_REG */
#define DMA_GSTS_TES    (((u64)1) << 31)
#define DMA_GSTS_RTPS   (((u64)1) << 30)
#define DMA_GSTS_FLS    (((u64)1) << 29)
#define DMA_GSTS_AFLS   (((u64)1) << 28)
#define DMA_GSTS_WBFS   (((u64)1) << 27)
#define DMA_GSTS_QIES_SHIFT     26
#define DMA_GSTS_QIES   (((u64)1) << DMA_GSTS_QIES_SHIFT)
#define DMA_GSTS_IRES_SHIFT     25
#define DMA_GSTS_IRES   (((u64)1) << DMA_GSTS_IRES_SHIFT)
#define DMA_GSTS_SIRTPS_SHIFT   24
#define DMA_GSTS_SIRTPS (((u64)1) << DMA_GSTS_SIRTPS_SHIFT)
#define DMA_GSTS_CFIS   (((u64)1) <<23)

/* IRTA_REG */
/* The base of 4KB aligned interrupt remapping table */
#define DMA_IRTA_ADDR(val)      ((val) & ~0xfffULL)
/* The size of remapping table is 2^(x+1), where x is the size field in IRTA */
#define DMA_IRTA_S(val)         (val & 0xf)
#define DMA_IRTA_SIZE(val)      (1UL << (DMA_IRTA_S(val) + 1))

/* IQA_REG */
#define DMA_IQA_ADDR(val)       (val & ~0xfffULL)
#define DMA_IQA_QS(val)         (val & 0x7)
#define DMA_IQA_RSVD            0xff8ULL

/* IECTL_REG */
#define DMA_IECTL_IM_SHIFT 31
#define DMA_IECTL_IM            (1 << DMA_IECTL_IM_SHIFT)
#define DMA_IECTL_IP_SHIFT 30
#define DMA_IECTL_IP            (1 << DMA_IECTL_IP_SHIFT)

/* ICS_REG */
#define DMA_ICS_IWC_SHIFT       0
#define DMA_ICS_IWC             (1 << DMA_ICS_IWC_SHIFT)

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
#define DMA_FECTL_IM_SHIFT 31
#define DMA_FECTL_IM (1U << DMA_FECTL_IM_SHIFT)
#define DMA_FECTL_IP_SHIFT 30
#define DMA_FECTL_IP (1U << DMA_FECTL_IP_SHIFT)

/* FSTS_REG */
#define DMA_FSTS_PFO_SHIFT 0
#define DMA_FSTS_PFO (1U << DMA_FSTS_PFO_SHIFT)
#define DMA_FSTS_PPF_SHIFT 1
#define DMA_FSTS_PPF (1U << DMA_FSTS_PPF_SHIFT)
#define DMA_FSTS_AFO (1U << 2)
#define DMA_FSTS_APF (1U << 3)
#define DMA_FSTS_IQE_SHIFT 4
#define DMA_FSTS_IQE (1U << DMA_FSTS_IQE_SHIFT)
#define DMA_FSTS_ICE (1U << 5)
#define DMA_FSTS_ITE (1U << 6)
#define DMA_FSTS_PRO_SHIFT 7
#define DMA_FSTS_PRO (1U << DMA_FSTS_PRO_SHIFT)
#define DMA_FSTS_FAULTS    (DMA_FSTS_PFO | DMA_FSTS_PPF | DMA_FSTS_AFO | \
                            DMA_FSTS_APF | DMA_FSTS_IQE | DMA_FSTS_ICE | \
                            DMA_FSTS_ITE | DMA_FSTS_PRO)
#define DMA_FSTS_RW1CS     (DMA_FSTS_PFO | DMA_FSTS_AFO | DMA_FSTS_APF | \
                            DMA_FSTS_IQE | DMA_FSTS_ICE | DMA_FSTS_ITE | \
                            DMA_FSTS_PRO)
#define dma_fsts_fault_record_index(s) (((s) >> 8) & 0xff)

/* FRCD_REG, 32 bits access */
#define DMA_FRCD_LEN            0x10
#define DMA_FRCD2_OFFSET        0x8
#define DMA_FRCD3_OFFSET        0xc
#define DMA_FRCD_F_SHIFT        31
#define DMA_FRCD_F ((u64)1 << DMA_FRCD_F_SHIFT)
#define dma_frcd_type(d) ((d >> 30) & 1)
#define dma_frcd_fault_reason(c) (c & 0xff)
#define dma_frcd_source_id(c) (c & 0xffff)
#define dma_frcd_page_addr(d) (d & (((u64)-1) << 12)) /* low 64 bit */

struct vtd_fault_record_register
{
    union {
        struct {
            uint64_t lo;
            uint64_t hi;
        } bits;
        struct {
            uint64_t rsvd0          :12,
                     fault_info     :52;
            uint64_t source_id      :16,
                     rsvd1          :9,
                     pmr            :1,  /* Privilege Mode Requested */
                     exe            :1,  /* Execute Permission Requested */
                     pasid_p        :1,  /* PASID Present */
                     fault_reason   :8,  /* Fault Reason */
                     pasid_val      :20, /* PASID Value */
                     addr_type      :2,  /* Address Type */
                     type           :1,  /* Type. (0) Write (1) Read/AtomicOp */
                     fault          :1;  /* Fault */
        } fields;
    };
};

enum VTD_FAULT_TYPE
{
    /* Interrupt remapping transition faults */
    VTD_FR_IR_REQ_RSVD      = 0x20, /* One or more IR request reserved
                                     * fields set */
    VTD_FR_IR_INDEX_OVER    = 0x21, /* Index value greater than max */
    VTD_FR_IR_ENTRY_P       = 0x22, /* Present (P) not set in IRTE */
    VTD_FR_IR_ROOT_INVAL    = 0x23, /* IR Root table invalid */
    VTD_FR_IR_IRTE_RSVD     = 0x24, /* IRTE Rsvd field non-zero with
                                     * Present flag set */
    VTD_FR_IR_REQ_COMPAT    = 0x25, /* Encountered compatible IR
                                     * request while disabled */
    VTD_FR_IR_SID_ERR       = 0x26, /* Invalid Source-ID */
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
 * When VT-d doesn't enable Extended Interrupt Mode. Hardware only interprets
 * only 8-bits ([15:8]) of Destination-ID field in the IRTEs.
 */
#define IRTE_xAPIC_DEST_MASK 0xff00

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
#define QINVAL_INDEX_MASK  0x7fff0ULL

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
