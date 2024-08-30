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

#ifndef TARGET_I386_SVSM_H
#define TARGET_I386_SVSM_H

#include "cpu.h"
#include "sysemu/kvm.h"

// #ifdef CONFIG_SEV?
#ifdef CONFIG_KVM
int kvm_svsm_handle_exit(X86CPU *cpu, struct kvm_svsm_exit *exit);
#endif

#endif
