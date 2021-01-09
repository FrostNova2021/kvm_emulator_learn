
#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#define DEFAULT_CODE_MEMORY_SIZE 0x8000
#define DEFAULT_MMIO_SIZE 0x4000
#define DEFAULT_STACK_SIZE 0x4000

#define PAGE_CODE_OFFSET  0x0000
#define PAGE_STACK_OFFSET 0x8000
#define PAGE_STACK_ENTRY  0xA000
#define PAGE_MMIO_OFFSET  0xC000



unsigned char code_buffer[] = {
  0xb8, 0x00, 0x00, 0xba, 0x02, 0x00, 0xe5, 0x18, 0x01, 0xd0, 0xe7, 0x17,
  0x8b, 0x16, 0x00, 0x80, 0x01, 0xc2, 0x89, 0x16, 0x04, 0x80, 0xf4
};


//unsigned char code_buffer[] = "\xb0\x61\xba\x17\x02\xee\xb0\x0a\xee\xba\x18\x02\xec\xf4";
//"\xB0\x61\xBA\x17\x02\xEE\xB0\n\xEE\xF4";

int main(int argc,char** argv) {
    int kvm_handle = open("/dev/kvm", O_RDWR | O_CLOEXEC);

    if (-1 == kvm_handle) {
        printf("Not FOUND /dev/kvm .see it :\n",kvm_handle);
        printf("  https://blog.csdn.net/qq_27061049/article/details/99291417\n");

        return 0;
    }

    uint kvm_version = ioctl(kvm_handle, KVM_GET_API_VERSION, NULL);

    printf("Current KVM VERSION:%d \n",kvm_version);

    int vm_fd = ioctl(kvm_handle, KVM_CREATE_VM, NULL);

    if (-1 == vm_fd) {
        printf("Create KVM-VM Error..\n");

        return 0;
    }

    unsigned char* code_memory = (unsigned char*)mmap(0, DEFAULT_CODE_MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    struct kvm_userspace_memory_region kvm_outside_region = {
        .slot = 0,
        .flags = 0,
        .guest_phys_addr = PAGE_CODE_OFFSET,
        .memory_size = DEFAULT_CODE_MEMORY_SIZE,
        .userspace_addr = (u_int64_t)code_memory
    };

    memset(code_memory,0,DEFAULT_CODE_MEMORY_SIZE);
    memcpy(code_memory,&code_buffer,sizeof(code_buffer));
    ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &kvm_outside_region);

    unsigned char* mmio_memory = (unsigned char*)mmap(0, DEFAULT_MMIO_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    kvm_outside_region.flags = KVM_MEM_READONLY;
    kvm_outside_region.guest_phys_addr = PAGE_MMIO_OFFSET;
    kvm_outside_region.memory_size = DEFAULT_MMIO_SIZE;
    kvm_outside_region.userspace_addr = (u_int64_t)mmio_memory;

    memset(mmio_memory,0,DEFAULT_MMIO_SIZE);
    ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &kvm_outside_region);

    struct kvm_memory_region kvm_inside_region = {
        .slot = 0,
        .flags = 0,
        .guest_phys_addr = PAGE_STACK_OFFSET,
        .memory_size = DEFAULT_STACK_SIZE,
    };

    ioctl(vm_fd, KVM_SET_MEMORY_REGION, &kvm_inside_region);


    int vcpu_mmap_size = ioctl(kvm_handle, KVM_GET_VCPU_MMAP_SIZE, NULL);
    int vcpu_handle = ioctl(vm_fd, KVM_CREATE_VCPU, NULL);
    struct kvm_run* run_mem = (struct kvm_run*)mmap(NULL, vcpu_mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, vcpu_handle, 0);

    struct kvm_regs regs;
    ioctl(vcpu_handle, KVM_GET_REGS, &regs);
    regs.rip = 0x0;
    regs.rbp = regs.rsp = PAGE_STACK_ENTRY;
    regs.rflags = 0x2;
    ioctl(vcpu_handle, KVM_SET_REGS, &regs);

    struct kvm_sregs sregs;
    ioctl(vcpu_handle, KVM_GET_SREGS, &sregs);
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    ioctl(vcpu_handle, KVM_SET_SREGS, &sregs);



    while(1) {
        ioctl(vcpu_handle, KVM_RUN, 0);
        int exit_reason = run_mem->exit_reason;

        switch(exit_reason) {
            case KVM_EXIT_UNKNOWN:
                printf("KVM_EXIT_UNKNOWN Reason = %d\n",run_mem->hw.hardware_exit_reason);
            case KVM_EXIT_HLT:
            case KVM_EXIT_SHUTDOWN:
                printf("KVM VM Shutdown! \n");

                return 1;
            case KVM_EXIT_INTERNAL_ERROR: {
                switch(run_mem->internal.suberror) {
                    case KVM_INTERNAL_ERROR_EMULATION:
                        printf("KVM Execute Invalid Instruction\n");

                        break;
                    default:
                        printf("  Error Code = %d\n",run_mem->internal.suberror);
                }

                printf("  KVM_EXIT_INTERNAL_ERROR Reason => %s\n",run_mem->internal.data);

                cpu_status_dump(vcpu_handle);

                return 0;
            } case KVM_EXIT_IO: {
                unsigned char io_direction = run_mem->io.direction;
                unsigned char io_data_size = run_mem->io.size;
                unsigned short io_port = run_mem->io.port;
                void* io_data_point = (void*)&((unsigned char*)run_mem)[run_mem->io.data_offset];

                if (KVM_EXIT_IO_OUT == io_direction) {
                    unsigned long io_data = 0;

                    switch(io_data_size) {
                        case sizeof(char):
                            io_data = *(unsigned char*)io_data_point;
                        case sizeof(short):
                            io_data = *(unsigned short*)io_data_point;
                        case sizeof(int):
                            io_data = *(unsigned int*)io_data_point;
                        default:
                            break;
                    }

                    printf("KVM IO_OUT ==> IO size = %X ;IO port = %X ;IO data = %X \n",io_data_size,io_port,io_data);
                } else if (KVM_EXIT_IO_IN == io_direction) {
                    printf("KVM IO_IN ==> IO size = %X ;IO port = %X \n",io_data_size,io_port);
                
                    switch(io_data_size) {
                        case sizeof(char):
                            *(unsigned char*)io_data_point = 0x10;
                        case sizeof(short):
                            *(unsigned short*)io_data_point = 0x10;
                        case sizeof(int):
                            *(unsigned int*)io_data_point = 0x10;
                        default:
                            break;
                    } 
                }

                break;
            } case KVM_EXIT_MMIO: {
                unsigned long memory_address = run_mem->mmio.phys_addr;
                unsigned long memory_data_size = run_mem->mmio.len;
                void* memory_data = (void*)&run_mem->mmio.data;

                if (run_mem->mmio.is_write) {
                    unsigned long data = 0;

                    switch(memory_data_size) {
                        case sizeof(char):
                            data = *(unsigned char*)memory_data;
                        case sizeof(short):
                            data = *(unsigned short*)memory_data;
                        case sizeof(int):
                            data = *(unsigned int*)memory_data;
                        default:
                            break;
                    }

                    printf("KVM MMIO Write = 0x%X (%X) ;Data = %X \n",memory_address,memory_data_size,data);

                } else {
                    if (0x8000 == memory_address) {
                        switch(memory_data_size) {
                            case sizeof(char):
                                *(unsigned char*)memory_data = 0xAA;
                            case sizeof(short):
                                *(unsigned short*)memory_data = 0xAA;
                            case sizeof(int):
                                *(unsigned int*)memory_data = 0xAA;
                            default:
                                break;
                        }
                    }

                    printf("KVM MMIO Read = 0x%X (%X) \n",memory_address,memory_data_size);
                }

                break;
            } default:
                printf("KVM-Exit Reason: %d\n",exit_reason);
        }
    }

    return 1;
}


void cpu_status_dump(int vcpu_handle) {
    struct kvm_regs regs;
    struct kvm_sregs sregs;

    ioctl(vcpu_handle, KVM_GET_REGS, &regs);
    ioctl(vcpu_handle, KVM_GET_SREGS, &sregs);

    printf("==== KVM VCPU Status Dumper ====\n");

    printf(" Normal Register:\n");
    printf("  RAX = %X\n",regs.rax);
    printf("  RBX = %X\n",regs.rbx);
    printf("  RCX = %X\n",regs.rcx);
    printf("  RDX = %X\n",regs.rdx);
    printf("  RSI = %X\n",regs.rsi);
    printf("  RDI = %X\n",regs.rdi);
    printf("  RSP = %X\n",regs.rsp);
    printf("  RBP = %X\n",regs.rbp);
    printf("  R8  = %X\n",regs.r8);
    printf("  R9  = %X\n",regs.r9);
    printf("  R10 = %X\n",regs.r10);
    printf("  R11 = %X\n",regs.r11);
    printf("  R12 = %X\n",regs.r12);
    printf("  R13 = %X\n",regs.r13);
    printf("  R14 = %X\n",regs.r14);
    printf("  R15 = %X\n",regs.r15);
    printf("  RIP = %X\n",regs.rip);
    printf("  RFLAGS = %X\n",regs.rflags);

    printf("Code => %X %X %X %X\n",
        code_buffer[regs.rip],
        code_buffer[regs.rip + 1],
        code_buffer[regs.rip + 2],
        code_buffer[regs.rip + 3]);

    printf(" Special Register:\n");
    printf(" lueluelue~\n");

    printf("==== Exit ====\n");

}







