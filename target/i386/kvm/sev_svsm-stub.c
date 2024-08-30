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

#include <linux/kvm.h> // struct kvm_run

#include "qemu/error-report.h"

int kvm_svsm_handle_exit(X86CPU *cpu, struct kvm_svsm_exit *exit)
{
    info_report("syssec: VMI call stub");
    //CPUX86State *env = &cpu->env;
    switch (exit->type) {
    case KVM_EXIT_SVSM_VMICALL: {
        switch (exit->u.vmicall.input): {
        case VMICALL_PAUSE:
            exit->u.vmicall.result = 0;
        case VMICALL_RESUME:
            exit->u.vmicall.result = 0;
        default:
            exit->u.vmicall.result = 1; // err
        }
        return 0;
    }

    default:
        return -1;
    }
}