#define pr_fmt(fmt) "pciem_p2p: " fmt

#include "pciem_p2p.h"
#include "pciem_framework.h"
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/string.h>

static int parse_p2p_regions(struct pciem_p2p_manager *mgr,
                              const char *regions_str)
{
    char *str __free(kfree) = NULL, *token, *cur;
    phys_addr_t phys;
    resource_size_t size;
    int count = 0;

    if (!regions_str || strlen(regions_str) == 0) {
        return 0;
    }

    str = kstrdup(regions_str, GFP_KERNEL);
    if (!str) {
        return -ENOMEM;
    }

    cur = str;
    while ((token = strsep(&cur, ",")) != NULL) {
        struct pciem_p2p_region *region;

        if (sscanf(token, "0x%llx:0x%llx", &phys, &size) != 2 &&
            sscanf(token, "%llx:%llx", &phys, &size) != 2) {
            pr_warn("Invalid P2P region format: '%s'\n", token);
            continue;
        }

        if (size == 0 || size > (1ULL << 40)) {
            pr_warn("Invalid P2P region size: 0x%llx\n", size);
            continue;
        }

        phys_addr_t region_end = phys + size;
        struct pciem_p2p_region *existing;
        bool overlap = false;

        list_for_each_entry(existing, &mgr->regions, list) {
            phys_addr_t existing_end = existing->phys_start + existing->size;

            if ((phys < existing_end && region_end > existing->phys_start)) {
                pr_err("P2P region 0x%llx-0x%llx overlaps with existing 0x%llx-0x%llx\n",
                       phys, region_end, existing->phys_start, existing_end);
                overlap = true;
                break;
            }
        }

        if (overlap) {
            continue;
        }

        region = kzalloc(sizeof(*region), GFP_KERNEL);
        if (!region) {
            pr_err("Failed to allocate P2P region struct\n");
            continue;
        }

        region->phys_start = phys;
        region->size = size;

        region->kaddr = ioremap_wc(phys, size);
        if (!region->kaddr) {
            pr_err("Failed to ioremap P2P region 0x%llx (size 0x%llx)\n",
                   phys, size);
            kfree(region);
            continue;
        }

        snprintf(region->name, sizeof(region->name), "p2p_%d", count);

        list_add_tail(&region->list, &mgr->regions);
        count++;

        pr_info("Registered P2P region: 0x%llx-0x%llx (size %llu KB)\n",
                phys, phys + size, size / 1024);
    }

    if (count > 0) {
        mgr->enabled = true;
        pr_info("P2P enabled with %d regions\n", count);
    }

    return 0;
}

int pciem_p2p_init(struct pciem_root_complex *v, const char *regions_str)
{
    struct pciem_p2p_manager *mgr;
    int ret;

    if (!v) {
        return -EINVAL;
    }

    mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
    if (!mgr) {
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&mgr->regions);
    mutex_init(&mgr->lock);
    mgr->max_transfer_size = PCIEM_P2P_MAX_TRANSFER;
    mgr->enabled = false;

    ret = parse_p2p_regions(mgr, regions_str);
    if (ret < 0) {
        pr_err("Failed to parse P2P regions: %d\n", ret);
        mutex_destroy(&mgr->lock);
        kfree(mgr);
        return ret;
    }

    v->p2p_mgr = mgr;
    return 0;
}
EXPORT_SYMBOL(pciem_p2p_init);

void pciem_p2p_cleanup(struct pciem_root_complex *v)
{
    struct pciem_p2p_manager *mgr;
    struct pciem_p2p_region *region, *tmp;

    if (!v || !v->p2p_mgr) {
        return;
    }

    mgr = v->p2p_mgr;

    mutex_lock(&mgr->lock);

    list_for_each_entry_safe(region, tmp, &mgr->regions, list) {
        pr_info("Unregistering P2P region: 0x%llx (size 0x%llx)\n",
                region->phys_start, region->size);

        if (region->kaddr) {
            iounmap(region->kaddr);
        }

        list_del(&region->list);
        kfree(region);
    }

    mutex_unlock(&mgr->lock);

    kfree(mgr);
    v->p2p_mgr = NULL;
}
EXPORT_SYMBOL(pciem_p2p_cleanup);

int pciem_p2p_register_region(struct pciem_root_complex *v,
                               phys_addr_t phys,
                               resource_size_t size,
                               const char *name)
{
    struct pciem_p2p_manager *mgr;
    struct pciem_p2p_region *region;

    if (!v || !v->p2p_mgr) {
        return -EINVAL;
    }

    if (size == 0 || size > PCIEM_P2P_MAX_TRANSFER) {
        return -EINVAL;
    }

    mgr = v->p2p_mgr;

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (!region) {
        return -ENOMEM;
    }

    region->phys_start = phys;
    region->size = size;
    region->kaddr = ioremap_wc(phys, size);

    if (!region->kaddr) {
        kfree(region);
        return -ENOMEM;
    }

    if (name) {
        strncpy(region->name, name, sizeof(region->name) - 1);
    } else {
        snprintf(region->name, sizeof(region->name), "dynamic_0x%llx", phys);
    }

    guard(mutex)(&mgr->lock);
    list_add_tail(&region->list, &mgr->regions);
    mgr->enabled = true;

    pr_info("Dynamically registered P2P region: %s at 0x%llx (size 0x%llx)\n",
            region->name, phys, size);

    return 0;
}
EXPORT_SYMBOL(pciem_p2p_register_region);

int pciem_p2p_unregister_region(struct pciem_root_complex *v,
                                 phys_addr_t phys)
{
    struct pciem_p2p_manager *mgr;
    struct pciem_p2p_region *region, *tmp;

    if (!v || !v->p2p_mgr) {
        return -EINVAL;
    }

    mgr = v->p2p_mgr;

    guard(mutex)(&mgr->lock);

    list_for_each_entry_safe(region, tmp, &mgr->regions, list) {
        if (region->phys_start == phys) {
            pr_info("Unregistering P2P region: %s\n", region->name);

            if (region->kaddr) {
                iounmap(region->kaddr);
            }

            list_del(&region->list);
            kfree(region);
            return 0;
        }
    }

    return -ENOENT;
}
EXPORT_SYMBOL(pciem_p2p_unregister_region);

struct pciem_p2p_region *pciem_p2p_get_region(struct pciem_root_complex *v,
                                               phys_addr_t phys_addr)
{
    struct pciem_p2p_manager *mgr;
    struct pciem_p2p_region *region;

    if (!v || !v->p2p_mgr) {
        return NULL;
    }

    mgr = v->p2p_mgr;

    list_for_each_entry(region, &mgr->regions, list) {
        phys_addr_t region_end = region->phys_start + region->size;

        if (phys_addr >= region->phys_start && phys_addr < region_end) {
            return region;
        }
    }

    return NULL;
}
EXPORT_SYMBOL(pciem_p2p_get_region);

int pciem_p2p_validate_access(struct pciem_root_complex *v,
                               phys_addr_t phys_addr,
                               size_t len)
{
    struct pciem_p2p_manager *mgr;
    struct pciem_p2p_region *region;
    phys_addr_t access_end;
    int ret = -EACCES;

    if (!v || !v->p2p_mgr) {
        return -EINVAL;
    }

    mgr = v->p2p_mgr;

    if (!mgr->enabled) {
        return -EACCES;
    }

    if (len == 0 || len > mgr->max_transfer_size) {
        return -EINVAL;
    }

    access_end = phys_addr + len;

    if (access_end < phys_addr) {
        return -EINVAL;
    }

    guard(mutex)(&mgr->lock);

    list_for_each_entry(region, &mgr->regions, list) {
        phys_addr_t region_end = region->phys_start + region->size;

        if (phys_addr >= region->phys_start && access_end <= region_end) {
            ret = 0;
            break;
        }
    }

    if (ret != 0) {
        pr_warn_ratelimited("P2P access denied: 0x%llx+0x%zx not whitelisted\n",
                           phys_addr, len);
    }

    return ret;
}
EXPORT_SYMBOL(pciem_p2p_validate_access);

int pciem_p2p_read(struct pciem_root_complex *v,
                   phys_addr_t phys_addr,
                   void *dst,
                   size_t len)
{
    struct pciem_p2p_manager *mgr;
    struct pciem_p2p_region *region;
    size_t offset;
    int ret;

    if (!v || !v->p2p_mgr || !dst) {
        return -EINVAL;
    }

    ret = pciem_p2p_validate_access(v, phys_addr, len);
    if (ret < 0) {
        return ret;
    }

    mgr = v->p2p_mgr;

    guard(mutex)(&mgr->lock);

    region = pciem_p2p_get_region(v, phys_addr);
    if (!region)
        return -EFAULT;

    offset = phys_addr - region->phys_start;

    memcpy_fromio(dst, region->kaddr + offset, len);

    pr_debug("P2P read: 0x%llx+0x%zx from region '%s'\n",
             phys_addr, len, region->name);

    return 0;
}
EXPORT_SYMBOL(pciem_p2p_read);

int pciem_p2p_write(struct pciem_root_complex *v,
                    phys_addr_t phys_addr,
                    const void *src,
                    size_t len)
{
    struct pciem_p2p_manager *mgr;
    struct pciem_p2p_region *region;
    size_t offset;
    int ret;

    if (!v || !v->p2p_mgr || !src) {
        return -EINVAL;
    }

    ret = pciem_p2p_validate_access(v, phys_addr, len);
    if (ret < 0) {
        return ret;
    }

    mgr = v->p2p_mgr;

    guard(mutex)(&mgr->lock);

    region = pciem_p2p_get_region(v, phys_addr);
    if (!region)
        return -EFAULT;

    offset = phys_addr - region->phys_start;

    memcpy_toio(region->kaddr + offset, src, len);

    pr_debug("P2P write: 0x%llx+0x%zx to region '%s'\n",
             phys_addr, len, region->name);

    return 0;
}
EXPORT_SYMBOL(pciem_p2p_write);
