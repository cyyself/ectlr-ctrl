#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>

MODULE_AUTHOR("Yangyu Chen <cyy@cyyself.name>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ARM ECTLR control driver");

enum ectlr_reg {
    ECTLR_EL1 = 0,
    ECTLR2_EL1,
    ECTLR_REG_MAX,
};

struct ectlr_load_info {
    u64 val;
    enum ectlr_reg reg;
    int result;
};

struct ectlr_store_info {
    u64 val;
    enum ectlr_reg reg;
    int result;
};

struct ectlr_white_list_entry {
    u64 midr;
    u64 mask;
};

static struct kobject *ectlr_kobj;
static struct kobject *ectlr_cpu_kobjs[NR_CPUS];
static struct ectlr_store_info ectlr_store_infos[NR_CPUS];

static struct ectlr_white_list_entry ecltr_ectlr_el1_white_list[] = {
    { .midr = 0x410fd800, .mask = 0xfffffff0 }, // Cortex-A520
    { .midr = 0x410fd810, .mask = 0xfffffff0 }, // Cortex-A720
    { .midr = 0x410fd490, .mask = 0xfffffff0 }, // Neoverse N2
    { .midr = 0x410fd4f0, .mask = 0xfffffff0 }, // Neoverse V2
    // Add more entries as needed
    { .midr = 0x00000000, .mask = 0x00000000  } // End marker
};

static struct ectlr_white_list_entry ecltr_ectlr2_el1_white_list[] = {
    { .midr = 0x410fd810, .mask = 0xfffffff0 }, // Cortex-A720
    { .midr = 0x410fd490, .mask = 0xfffffff0 }, // Neoverse N2
    { .midr = 0x410fd4f0, .mask = 0xfffffff0 }, // Neoverse V2
    // Add more entries as needed
    { .midr = 0x00000000, .mask = 0x00000000  } // End marker
};

static bool ectlr_has_ectlr_el1_feature(u64 midr) {
    struct ectlr_white_list_entry *entry = ecltr_ectlr_el1_white_list;
    while (entry->midr != 0 || entry->mask != 0) {
        if ((midr & entry->mask) == entry->midr) {
            return true;
        }
        entry++;
    }
    return false;
}

static bool ectlr_has_ectlr2_el1_feature(u64 midr) {
    struct ectlr_white_list_entry *entry = ecltr_ectlr2_el1_white_list;
    while (entry->midr != 0 || entry->mask != 0) {
        if ((midr & entry->mask) == entry->midr) {
            return true;
        }
        entry++;
    }
    return false;
}

static void _ectlr_load(void *info) {
    struct ectlr_load_info *qinfo = (struct ectlr_load_info *)info;
    if (qinfo->reg == ECTLR_EL1) {
        asm volatile("mrs %0, S3_0_C15_C1_4" : "=r" (qinfo->val));
        qinfo->result = 0;
    } else if (qinfo->reg == ECTLR2_EL1) {
        asm volatile("mrs %0, S3_0_C15_C1_5" : "=r" (qinfo->val));
        qinfo->result = 0;
    }
    else {
        qinfo->result = -EINVAL;
    }
}

static int ectlr_get_cpu_id(struct kobject *kobj) {
    for (int cpu = 0; cpu < NR_CPUS; cpu++) {
        if (ectlr_cpu_kobjs[cpu] == kobj) {
            return cpu;
        }
    }
    return -1;
}

static void _ectlr_store(void *info) {
    // struct ectlr_store_info *qinfo = (struct ectlr_store_info *)info;
    struct ectlr_store_info *qinfo = &ectlr_store_infos[smp_processor_id()];
    int cpu = smp_processor_id();
    if (qinfo->reg == ECTLR_EL1) {
        pr_info("Writing to ECTLR_EL1 to 0x%016llx on CPU %d\n", qinfo->val, cpu);
        asm volatile("msr S3_0_C15_C1_4, %0" :: "r" (qinfo->val));
        qinfo->result = 0;
    } else if (qinfo->reg == ECTLR2_EL1) {
        pr_info("Writing to ECTLR2_EL1 to 0x%016llx on CPU %d\n", qinfo->val, cpu);
        asm volatile("msr S3_0_C15_C1_5, %0" :: "r" (qinfo->val));
        qinfo->result = 0;
    }
    else {
        qinfo->result = -EINVAL;
    }
}

static ssize_t ectlr_load(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int smp_id = ectlr_get_cpu_id(kobj);
    if (smp_id == -1)
        return -EINVAL;
    struct ectlr_load_info info;
    if (strcmp(attr->attr.name, "imp_cpuectlr_el1") == 0) {
        info.reg = ECTLR_EL1;
    } else if (strcmp(attr->attr.name, "imp_cpuectlr2_el1") == 0) {
        info.reg = ECTLR2_EL1;
    } else {
        return -EINVAL;
    }
    info.result = -EINVAL;
    smp_call_function_single(smp_id, _ectlr_load, &info, 1);
    if (info.result != 0) {
        return info.result;
    }
    u64 val = info.val;
    return scnprintf(buf, PAGE_SIZE, "0x%016llx\n", val);
}

static ssize_t ectlr_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    int smp_id = ectlr_get_cpu_id(kobj);
    if (smp_id == -1)
        return -EINVAL;
    struct ectlr_store_info info;
    if (strcmp(attr->attr.name, "imp_cpuectlr_el1") == 0) {
        info.reg = ECTLR_EL1;
    } else if (strcmp(attr->attr.name, "imp_cpuectlr2_el1") == 0) {
        info.reg = ECTLR2_EL1;
    } else {
        return -EINVAL;
    }
    // parse input
    u64 val;
    char buf_copy[32];
    for (size_t i = 0; i < min(count, sizeof(buf_copy) - 1); i++) {
        buf_copy[i] = buf[i];
    }
    buf_copy[min(count, sizeof(buf_copy) - 1)] = '\0';
    if (sscanf(buf_copy, "%llx", &val) != 1) {
        return -EINVAL;
    }
    info.val = val;
    info.result = -EINVAL;
    pr_info("Setting CPU %d %s to 0x%016llx\n", smp_id, attr->attr.name, val);
    ectlr_store_infos[smp_id] = info;
    smp_call_function_single(smp_id, _ectlr_store, &info, 0);
    /*
    if (info.result != 0) {
        return info.result;
    }
     */
    return count;
}

static struct kobj_attribute  ectlr_imp_cpuectlr_el1 = __ATTR(imp_cpuectlr_el1, 0644, ectlr_load, ectlr_store);
static struct kobj_attribute ectlr_imp_cpuectlr2_el1 = __ATTR(imp_cpuectlr2_el1, 0644, ectlr_load, ectlr_store);

static void init_each_cpu_features(void *info)
{
    int cpu = smp_processor_id();
    struct kobject *cpu_kobj = ectlr_cpu_kobjs[cpu];
    if (!cpu_kobj)
        return;
    // read midr
    u64 midr;
    asm volatile("mrs %0, MIDR_EL1" : "=r" (midr));
    // check features
    if (ectlr_has_ectlr_el1_feature(midr)) {
        if (sysfs_create_file(cpu_kobj, &ectlr_imp_cpuectlr_el1.attr))
            pr_err("Failed to create imp_cpuectlr_el1 attribute for CPU %d\n", cpu);
    }
    if (ectlr_has_ectlr2_el1_feature(midr)) {
        if (sysfs_create_file(cpu_kobj, &ectlr_imp_cpuectlr2_el1.attr))
            pr_err("Failed to create imp_cpuectlr2_el1 attribute for CPU %d\n", cpu);
    }
    u64 actlr_el2;
    asm volatile("mrs %0, actlr_el2" : "=r"(actlr_el2));
    pr_info("CPU %d MIDR: 0x%08llx, ACTLR_EL2: 0x%016llx\n", cpu, midr, actlr_el2);
    actlr_el2 |= (1 << 1); // Enable ECTLREN
    asm volatile("msr actlr_el2, %0" :: "r"(actlr_el2));
    return;
}

static int __init ectlr_ctrl_init(void)
{
    ectlr_kobj = kobject_create_and_add("ectlr", kernel_kobj);
    if (!ectlr_kobj)
        return -ENOMEM;
    // create subsysfs directories for each CPU
    int cpu;
    for_each_possible_cpu(cpu) {
        struct kobject *cpu_kobj;
        char cpu_name[8];
        snprintf(cpu_name, sizeof(cpu_name), "cpu%d", cpu);
        cpu_kobj = kobject_create_and_add(cpu_name, ectlr_kobj);
        if (!cpu_kobj) {
            pr_err("Failed to create kobject for CPU %d\n", cpu);
            goto err_put_kobj;
        }
        ectlr_cpu_kobjs[cpu] = cpu_kobj;
        // Assume we have fence in smp_call_function_single
        smp_call_function_single(cpu, init_each_cpu_features, NULL, 0);
    }
err_put_kobj:
    if (cpu < 0) {
        for_each_possible_cpu(cpu) {
            if (ectlr_cpu_kobjs[cpu])
                kobject_put(ectlr_cpu_kobjs[cpu]);
        }
        kobject_put(ectlr_kobj);
        return -ENOMEM;
    }
    return 0;
}

static void __exit ectlr_ctrl_exit(void)
{
    // put subsysfs directories for each CPU
    int cpu;
    for_each_possible_cpu(cpu) {
        if (ectlr_cpu_kobjs[cpu]) {
            sysfs_remove_file(ectlr_cpu_kobjs[cpu], &ectlr_imp_cpuectlr_el1.attr);
            sysfs_remove_file(ectlr_cpu_kobjs[cpu], &ectlr_imp_cpuectlr2_el1.attr);
            kobject_put(ectlr_cpu_kobjs[cpu]);
        }
    }
    kobject_put(ectlr_kobj);
}

module_init(ectlr_ctrl_init);
module_exit(ectlr_ctrl_exit);
