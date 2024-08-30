/*
 * QEMU KVM SVSM support
 *
 * Copyright (C) 2023 Fabian Schwarz
 * Copyright (C) 2023 CISPA Helmholtz Center for Information Security
 *
 * Authors:
 *  Fabian Schwarz <fabian.schwarz@cispa.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sev_svsm.h"

#include "cpu.h"
#include "target/i386/cpu.h"

#include "qemu/error-report.h"

#include "sysemu/cpus.h"

//#include "exec/cpu-common.h" // cpu_physical_memory_map

#include <linux/kvm.h> // struct kvm_run

//#define SYSSEC_DEBUG_PRINTS 1
#undef SYSSEC_DEBUG_PRINTS

#define VMICALL_PAUSE		0
#define VMICALL_RESUME		1

/* TODO: current implementation is simplified:
 *  we stop all vCPUs except of vCPU 0, which is where we schedule
 *  our agent on virtio-mmio events (new messages);
 */
static int resume_vmpl1(void) {
    // we expect this to be called from vCPU 0 atm
    if (!current_cpu || current_cpu->cpu_index != 0) {
        warn_report("syssec: resume called from vCPU != 0");
        return -1;
    }

    // TODO: probably should adapt and schedule on iothread
    request_resume_all_vcpus_except_current();
    return 0; // success
}

static int pause_vmpl1(void) {
    // we expect this to be called from vCPU 0 atm
    if (!current_cpu || current_cpu->cpu_index != 0) {
        warn_report("syssec: pause called from vCPU != 0");
        return -1;
    }

    // TODO: probably should adapt and schedule on iothread
    request_pause_all_vcpus_except_current();
    return 0; // success
}

// TODO: check for sev_snp enabled?
int kvm_svsm_handle_exit(X86CPU *cpu, struct kvm_svsm_exit *exit)
{
    //CPUX86State *env = &cpu->env;
    switch (exit->type) {
    case KVM_EXIT_SVSM_VMICALL: {
        switch (exit->u.vmicall.input) {
        case VMICALL_PAUSE: {
            //async_run_on_cpu(CPU(cpu), async_schedule_vmpl, RUN_ON_CPU_HOST_INT(0));
#ifdef SYSSEC_DEBUG_PRINTS
            info_report("syssec: PAUSE VMI call reached QEMU handler");
#endif
            exit->u.vmicall.result = pause_vmpl1(); // TODO: same err value
            break;
        }
        case VMICALL_RESUME: {
            //async_run_on_cpu(CPU(cpu), async_schedule_vmpl, RUN_ON_CPU_HOST_INT(0));
#ifdef SYSSEC_DEBUG_PRINTS
            info_report("syssec: RESUME VMI call reached QEMU handler");
#endif
            exit->u.vmicall.result = resume_vmpl1(); // TODO: same err value
            break;
        }
        default:
            exit->u.vmicall.result = 1; // err
        }
        return 0;
    }

    default:
        return -1;
    }
}