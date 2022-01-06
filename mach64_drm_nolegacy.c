/* By Brian Gisseler
** Based on existing mach64 driver and linux kernel sources
** Released under GPL
**
** most of this code is from drivers/gpu/drm/drm_*.c
**
** this whole file assumes that CONFIG_DRM_LEGACY is not set, and therefore the drm_device struct does not contain those legacy elements.
** several data legacy elements from struct drm_device are moved into the dev_private struct
*/

#ifndef __MACH64_DRM_NOLEGACY_C__
#define __MACH64_DRM_NOLEGACY_C__

#if !IS_ENABLED(CONFIG_DRM_LEGACY)

#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <drm/drm_legacy.h>
#include <drm/drm.h>
#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_agpsupport.h>
#include <linux/pci.h>

#include "mach64_drm_nolegacy.h"

drm_dma_handle_t *mach64_drm_pci_alloc(struct drm_device * dev, size_t size, size_t align)
{
	drm_dma_handle_t *dmah;
	/* pci_alloc_consistent only guarantees alignment to the smallest
	 * PAGE_SIZE order which is greater than or equal to the requested size.
	 * Return NULL here for now to make sure nobody tries for larger alignment
	 */
	if (align > size)
		return NULL;
	dmah = kmalloc(sizeof(drm_dma_handle_t), GFP_KERNEL);
	if (!dmah)
		return NULL;
	dmah->size = size;
	dmah->vaddr = dma_alloc_coherent(&dev->pdev->dev, size,
					 &dmah->busaddr,
					 GFP_KERNEL);
	if (dmah->vaddr == NULL) {
		kfree(dmah);
		return NULL;
	}
	return dmah;
}

void mach64_drm_pci_free(struct drm_device * dev, drm_dma_handle_t * dmah)
{
	dma_free_coherent(&dev->pdev->dev, dmah->size, dmah->vaddr,
			  dmah->busaddr);
	kfree(dmah);
}

static void mach64_drm_pci_agp_init(struct drm_device *dev);
void mach64_drm_pci_agp_destroy(struct drm_device *dev);

struct drm_agp_head *mach64_drm_agp_init(struct drm_device *dev)
{
	struct drm_agp_head *head = NULL;

	head = kzalloc(sizeof(*head), GFP_KERNEL);
	if (!head)
		return NULL;
	head->bridge = agp_find_bridge(dev->pdev);
	if (!head->bridge) {
		head->bridge = agp_backend_acquire(dev->pdev);
		if (!head->bridge) {
			kfree(head);
			return NULL;
		}
		agp_copy_info(head->bridge, &head->agp_info);
		agp_backend_release(head->bridge);
	} else {
		agp_copy_info(head->bridge, &head->agp_info);
	}
	if (head->agp_info.chipset == NOT_SUPPORTED) {
		kfree(head);
		return NULL;
	}
	INIT_LIST_HEAD(&head->memory);
	head->cant_use_aperture = head->agp_info.cant_use_aperture;
	head->page_mask = head->agp_info.page_mask;
	head->base = head->agp_info.aper_base;
	return head;
}

static void mach64_drm_pci_agp_init(struct drm_device *dev)
{
	if (drm_core_check_feature(dev, DRIVER_USE_AGP)) {
		if (pci_find_capability(dev->pdev, PCI_CAP_ID_AGP))
			dev->agp = mach64_drm_agp_init(dev);
		if (dev->agp) {
			dev->agp->agp_mtrr = arch_phys_wc_add(
				dev->agp->agp_info.aper_base,
				dev->agp->agp_info.aper_size *
				1024 * 1024);
		}
	}
}

struct mach64_drm_agp_mem {
	unsigned long handle;
	struct agp_memory *memory;
	unsigned long bound;
	int pages;
	struct list_head head;
};

void mach64_drm_free_agp(struct agp_memory *handle, int pages)
{
	agp_free_memory(handle);
}

int mach64_drm_unbind_agp(struct agp_memory *handle)
{
	return agp_unbind_memory(handle);
}

void mach64_drm_legacy_agp_clear(struct drm_device *dev)
{
	struct mach64_drm_agp_mem *entry, *tempe;

	if (!dev->agp)
		return;
	if (!drm_core_check_feature(dev, DRIVER_LEGACY))
		return;

	list_for_each_entry_safe(entry, tempe, &dev->agp->memory, head) {
		if (entry->bound)
			mach64_drm_unbind_agp(entry->memory);
		mach64_drm_free_agp(entry->memory, entry->pages);
		kfree(entry);
	}
	INIT_LIST_HEAD(&dev->agp->memory);

	if (dev->agp->acquired)
		drm_agp_release(dev);

	dev->agp->acquired = 0;
	dev->agp->enabled = 0;
}

void mach64_drm_pci_agp_destroy(struct drm_device *dev)
{
	if (dev->agp) {
		arch_phys_wc_del(dev->agp->agp_mtrr);
		mach64_drm_legacy_agp_clear(dev);
		kfree(dev->agp);
		dev->agp = NULL;
	}
}

static int mach64_drm_get_pci_dev(struct pci_dev *pdev,
			   const struct pci_device_id *ent,
			   struct drm_driver *driver)
{
	struct drm_device *dev;
	int ret;

	DRM_DEBUG("\n");

	dev = drm_dev_alloc(driver, &pdev->dev);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	ret = pci_enable_device(pdev);
	if (ret)
		goto err_free;

	dev->pdev = pdev;
#ifdef __alpha__
	dev->hose = pdev->sysdata;
#endif

	if (drm_core_check_feature(dev, DRIVER_MODESET))
		pci_set_drvdata(pdev, dev);

	mach64_drm_pci_agp_init(dev);

	ret = drm_dev_register(dev, ent->driver_data);
	if (ret)
		goto err_agp;

	/* No locking needed since shadow-attach is single-threaded since it may
	 * only be called from the per-driver module init hook. */
	if (drm_core_check_feature(dev, DRIVER_LEGACY))
		list_add_tail(&dev->legacy_dev_list, &driver->legacy_dev_list);

	return 0;

err_agp:
	mach64_drm_pci_agp_destroy(dev);
	pci_disable_device(pdev);
err_free:
	drm_dev_put(dev);
	return ret;
}

int mach64_drm_legacy_pci_init(struct drm_driver *driver, struct pci_driver *pdriver)
{
	struct pci_dev *pdev = NULL;
	const struct pci_device_id *pid;
	int i;

	DRM_DEBUG("\n");

	if (WARN_ON(!(driver->driver_features & DRIVER_LEGACY)))
		return -EINVAL;

	/* If not using KMS, fall back to stealth mode manual scanning. */
	INIT_LIST_HEAD(&driver->legacy_dev_list);
	for (i = 0; pdriver->id_table[i].vendor != 0; i++) {
		pid = &pdriver->id_table[i];

		/* Loop around setting up a DRM device for each PCI device
		 * matching our ID and device class.  If we had the internal
		 * function that pci_get_subsys and pci_get_class used, we'd
		 * be able to just pass pid in instead of doing a two-stage
		 * thing.
		 */
		pdev = NULL;
		while ((pdev =
			pci_get_subsys(pid->vendor, pid->device, pid->subvendor,
				       pid->subdevice, pdev)) != NULL) {
			if ((pdev->class & pid->class_mask) != pid->class)
				continue;

			/* stealth mode requires a manual probe */
			pci_dev_get(pdev);
			mach64_drm_get_pci_dev(pdev, pid, driver);
		}
	}
	return 0;
}

void mach64_drm_legacy_pci_exit(struct drm_driver *driver, struct pci_driver *pdriver)
{
	struct drm_device *dev, *tmp;
	DRM_DEBUG("\n");

	if (!(driver->driver_features & DRIVER_LEGACY)) {
		WARN_ON(1);
	} else {
		list_for_each_entry_safe(dev, tmp, &driver->legacy_dev_list,
					 legacy_dev_list) {
			list_del(&dev->legacy_dev_list);
			drm_put_dev(dev);
		}
	}
	DRM_INFO("Module unloaded\n");
}

struct drm_local_map *mach64_drm_legacy_findmap(struct drm_device *dev,
					 unsigned int token)
{
	struct drm_map_list *_entry;
	list_for_each_entry(_entry, &MACH64_PRIVATE(dev)->maplist, head)
		if (_entry->user_token == token)
			return _entry->map;
	return NULL;
}

struct drm_local_map *mach64_drm_legacy_getsarea(struct drm_device *dev)
{
	struct drm_map_list *entry;

	list_for_each_entry(entry, &MACH64_PRIVATE(dev)->maplist, head) {
		if (entry->map && entry->map->type == _DRM_SHM &&
		    (entry->map->flags & _DRM_CONTAINS_LOCK)) {
			return entry->map;
		}
	}
	return NULL;
}

/* From v5.8/drivers/gpu/drm/drm_vm.c */
/* if CONFIG_DRM_VM is not defined in kernel config, attempt to embed dependencies into module */

#if !IS_ENABLED(CONFIG_DRM_VM)

struct mach64_drm_vma_entry {
	struct list_head head;
	struct vm_area_struct *vma;
	pid_t pid;
};

static pgprot_t mach64_drm_io_prot(struct drm_local_map *map,
				   struct vm_area_struct *vma)
{
	pgprot_t tmp = vm_get_page_prot(vma->vm_flags);

	/* We don't want graphics memory to be mapped encrypted */
	tmp = pgprot_decrypted(tmp);

#if defined(__i386__) || defined(__x86_64__) || defined(__powerpc__) || \
    defined(__mips__)
	if (map->type == _DRM_REGISTERS && !(map->flags & _DRM_WRITE_COMBINING))
		tmp = pgprot_noncached(tmp);
	else
		tmp = pgprot_writecombine(tmp);
#elif defined(__ia64__)
	if (efi_range_is_wc(vma->vm_start, vma->vm_end -
		vma->vm_start))
		tmp = pgprot_writecombine(tmp);
	else
		tmp = pgprot_noncached(tmp);
#elif defined(__sparc__) || defined(__arm__)
	tmp = pgprot_noncached(tmp);
#endif
	return tmp;
}

static pgprot_t mach64_drm_dma_prot(uint32_t map_type, struct vm_area_struct *vma)
{
	pgprot_t tmp = vm_get_page_prot(vma->vm_flags);

#if defined(__powerpc__) && defined(CONFIG_NOT_COHERENT_CACHE)
	tmp = pgprot_noncached_wc(tmp);
#endif
	return tmp;
}

/*
 * \c fault method for AGP virtual memory.
 *
 * \param vma virtual memory area.
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Find the right map and if it's AGP memory find the real physical page to
 * map, get the page, increment the use count and return it.
 */
#if IS_ENABLED(CONFIG_AGP)
static vm_fault_t mach64_drm_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_local_map *map = NULL;
	struct drm_map_list *r_list;
	struct drm_hash_item *hash;

	/*
	 * Find the right map
	 */
	if (!dev->agp)
		goto vm_fault_error;

	if (!dev->agp || !dev->agp->cant_use_aperture)
		goto vm_fault_error;

	if (drm_ht_find_item(&MACH64_PRIVATE(dev)->map_hash, vma->vm_pgoff, &hash))
		goto vm_fault_error;

	r_list = drm_hash_entry(hash, struct drm_map_list, hash);
	map = r_list->map;

	if (map && map->type == _DRM_AGP) {
		/*
		 * Using vm_pgoff as a selector forces us to use this unusual
		 * addressing scheme.
		 */
		resource_size_t offset = vmf->address - vma->vm_start;
		resource_size_t baddr = map->offset + offset;
		struct mach64_drm_agp_mem *agpmem;
		struct page *page;

#ifdef __alpha__
		/*
		 * Adjust to a bus-relative address
		 */
		baddr -= dev->hose->mem_space->start;
#endif

		/*
		 * It's AGP memory - find the real physical page to map
		 */
		list_for_each_entry(agpmem, &dev->agp->memory, head) {
			if (agpmem->bound <= baddr &&
			    agpmem->bound + agpmem->pages * PAGE_SIZE > baddr)
				break;
		}

		if (&agpmem->head == &dev->agp->memory)
			goto vm_fault_error;

		/*
		 * Get the page, inc the use count, and return it
		 */
		offset = (baddr - agpmem->bound) >> PAGE_SHIFT;
		page = agpmem->memory->pages[offset];
		get_page(page);
		vmf->page = page;

		DRM_DEBUG
		    ("baddr = 0x%llx page = 0x%p, offset = 0x%llx, count=%d\n",
		     (unsigned long long)baddr,
		     agpmem->memory->pages[offset],
		     (unsigned long long)offset,
		     page_count(page));
		return 0;
	}
vm_fault_error:
	return VM_FAULT_SIGBUS;	/* Disallow mremap */
}
#else
static vm_fault_t mach64_drm_vm_fault(struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}
#endif

/*
 * \c nopage method for shared virtual memory.
 *
 * \param vma virtual memory area.
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Get the mapping, find the real physical page to map, get the page, and
 * return it.
 */
static vm_fault_t mach64_drm_vm_shm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct drm_local_map *map = vma->vm_private_data;
	unsigned long offset;
	unsigned long i;
	struct page *page;

	if (!map)
		return VM_FAULT_SIGBUS;	/* Nothing allocated */

	offset = vmf->address - vma->vm_start;
	i = (unsigned long)map->handle + offset;
	page = vmalloc_to_page((void *)i);
	if (!page)
		return VM_FAULT_SIGBUS;
	get_page(page);
	vmf->page = page;

	DRM_DEBUG("shm_fault 0x%lx\n", offset);
	return 0;
}

/*
 * \c close method for shared virtual memory.
 *
 * \param vma virtual memory area.
 *
 * Deletes map information if we are the last
 * person to close a mapping and it's not in the global maplist.
 */
static void mach64_drm_vm_shm_close(struct vm_area_struct *vma)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct mach64_drm_vma_entry *pt, *temp;
	struct drm_local_map *map;
	struct drm_map_list *r_list;
	int found_maps = 0;

	DRM_DEBUG("0x%08lx,0x%08lx\n",
		  vma->vm_start, vma->vm_end - vma->vm_start);

	map = vma->vm_private_data;

	mutex_lock(&dev->struct_mutex);
	list_for_each_entry_safe(pt, temp, &MACH64_PRIVATE(dev)->vmalist, head) {
		if (pt->vma->vm_private_data == map)
			found_maps++;
		if (pt->vma == vma) {
			list_del(&pt->head);
			kfree(pt);
		}
	}

	/* We were the only map that was found */
	if (found_maps == 1 && map->flags & _DRM_REMOVABLE) {
		/* Check to see if we are in the maplist, if we are not, then
		 * we delete this mappings information.
		 */
		found_maps = 0;
		list_for_each_entry(r_list, &MACH64_PRIVATE(dev)->maplist, head) {
			if (r_list->map == map)
				found_maps++;
		}

		if (!found_maps) {
			switch (map->type) {
			case _DRM_REGISTERS:
			case _DRM_FRAME_BUFFER:
				arch_phys_wc_del(map->mtrr);
				iounmap(map->handle);
				break;
			case _DRM_SHM:
				vfree(map->handle);
				break;
			case _DRM_AGP:
			case _DRM_SCATTER_GATHER:
				break;
			case _DRM_CONSISTENT:
				dma_free_coherent(&dev->pdev->dev,
						  map->size,
						  map->handle,
						  map->offset);
				break;
			}
			kfree(map);
		}
	}
	mutex_unlock(&dev->struct_mutex);
}

/*
 * \c fault method for DMA virtual memory.
 *
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Determine the page number from the page offset and get it from drm_device_dma::pagelist.
 */
static vm_fault_t mach64_drm_vm_dma_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_device_dma *dma = MACH64_PRIVATE(dev)->dma;
	unsigned long offset;
	unsigned long page_nr;
	struct page *page;

	if (!dma)
		return VM_FAULT_SIGBUS;	/* Error */
	if (!dma->pagelist)
		return VM_FAULT_SIGBUS;	/* Nothing allocated */

	offset = vmf->address - vma->vm_start;
					/* vm_[pg]off[set] should be 0 */
	page_nr = offset >> PAGE_SHIFT; /* page_nr could just be vmf->pgoff */
	page = virt_to_page((void *)dma->pagelist[page_nr]);

	get_page(page);
	vmf->page = page;

	DRM_DEBUG("dma_fault 0x%lx (page %lu)\n", offset, page_nr);
	return 0;
}

/*
 * \c fault method for scatter-gather virtual memory.
 *
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Determine the map offset from the page offset and get it from drm_sg_mem::pagelist.
 */
static vm_fault_t mach64_drm_vm_sg_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct drm_local_map *map = vma->vm_private_data;
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_sg_mem *entry = MACH64_PRIVATE(dev)->sg;
	unsigned long offset;
	unsigned long map_offset;
	unsigned long page_offset;
	struct page *page;

	if (!entry)
		return VM_FAULT_SIGBUS;	/* Error */
	if (!entry->pagelist)
		return VM_FAULT_SIGBUS;	/* Nothing allocated */

	offset = vmf->address - vma->vm_start;
	map_offset = map->offset - (unsigned long)MACH64_PRIVATE(dev)->sg->virtual;
	page_offset = (offset >> PAGE_SHIFT) + (map_offset >> PAGE_SHIFT);
	page = entry->pagelist[page_offset];
	get_page(page);
	vmf->page = page;

	return 0;
}

/** AGP virtual memory operations */
static const struct vm_operations_struct mach64_drm_vm_ops = {
	.fault = mach64_drm_vm_fault,
	.open = mach64_drm_vm_open,
	.close = mach64_drm_vm_close,
};

/** Shared virtual memory operations */
static const struct vm_operations_struct mach64_drm_vm_shm_ops = {
	.fault = mach64_drm_vm_shm_fault,
	.open = mach64_drm_vm_open,
	.close = mach64_drm_vm_shm_close,
};

/** DMA virtual memory operations */
static const struct vm_operations_struct mach64_drm_vm_dma_ops = {
	.fault = mach64_drm_vm_dma_fault,
	.open = mach64_drm_vm_open,
	.close = mach64_drm_vm_close,
};

/** Scatter-gather virtual memory operations */
static const struct vm_operations_struct mach64_drm_vm_sg_ops = {
	.fault = mach64_drm_vm_sg_fault,
	.open = mach64_drm_vm_open,
	.close = mach64_drm_vm_close,
};

static void mach64_drm_vm_open_locked(struct drm_device *dev,
				      struct vm_area_struct *vma)
{
	struct mach64_drm_vma_entry *vma_entry;

	DRM_DEBUG("0x%08lx,0x%08lx\n",
		  vma->vm_start, vma->vm_end - vma->vm_start);

	vma_entry = kmalloc(sizeof(*vma_entry), GFP_KERNEL);
	if (vma_entry) {
		vma_entry->vma = vma;
		vma_entry->pid = current->pid;
		list_add(&vma_entry->head, &MACH64_PRIVATE(dev)->vmalist);
	}
}

static void mach64_drm_vm_open(struct vm_area_struct *vma)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;

	mutex_lock(&dev->struct_mutex);
	mach64_drm_vm_open_locked(dev, vma);
	mutex_unlock(&dev->struct_mutex);
}

static void mach64_drm_vm_close_locked(struct drm_device *dev,
				       struct vm_area_struct *vma)
{
	struct mach64_drm_vma_entry *pt, *temp;

	DRM_DEBUG("0x%08lx,0x%08lx\n",
		  vma->vm_start, vma->vm_end - vma->vm_start);

	list_for_each_entry_safe(pt, temp, &MACH64_PRIVATE(dev)->vmalist, head) {
		if (pt->vma == vma) {
			list_del(&pt->head);
			kfree(pt);
			break;
		}
	}
}

/*
 * \c close method for all virtual memory types.
 *
 * \param vma virtual memory area.
 *
 * Search the \p vma private data entry in drm_device::vmalist, unlink it, and
 * free it.
 */
static void mach64_drm_vm_close(struct vm_area_struct *vma)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;

	mutex_lock(&dev->struct_mutex);
	mach64_drm_vm_close_locked(dev, vma);
	mutex_unlock(&dev->struct_mutex);
}

/*
 * mmap DMA memory.
 *
 * \param file_priv DRM file private.
 * \param vma virtual memory area.
 * \return zero on success or a negative number on failure.
 *
 * Sets the virtual memory area operations structure to vm_dma_ops, the file
 * pointer, and calls vm_open().
 */
static int mach64_drm_mmap_dma(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev;
	struct drm_device_dma *dma;
	unsigned long length = vma->vm_end - vma->vm_start;

	dev = priv->minor->dev;
	dma = MACH64_PRIVATE(dev)->dma;
	DRM_DEBUG("start = 0x%lx, end = 0x%lx, page offset = 0x%lx\n",
		  vma->vm_start, vma->vm_end, vma->vm_pgoff);

	/* Length must match exact page count */
	if (!dma || (length >> PAGE_SHIFT) != dma->page_count) {
		return -EINVAL;
	}

	if (!capable(CAP_SYS_ADMIN) &&
	    (dma->flags & _DRM_DMA_USE_PCI_RO)) {
		vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE);
#if defined(__i386__) || defined(__x86_64__)
		pgprot_val(vma->vm_page_prot) &= ~_PAGE_RW;
#else
		/* Ye gads this is ugly.  With more thought
		   we could move this up higher and use
		   `protection_map' instead.  */
		vma->vm_page_prot =
		    __pgprot(pte_val
			     (pte_wrprotect
			      (__pte(pgprot_val(vma->vm_page_prot)))));
#endif
	}

	vma->vm_ops = &mach64_drm_vm_dma_ops;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	mach64_drm_vm_open_locked(dev, vma);
	return 0;
}

static resource_size_t mach64_drm_core_get_reg_ofs(struct drm_device *dev)
{
#ifdef __alpha__
	return dev->hose->dense_mem_base;
#else
	return 0;
#endif
}

/*
 * mmap DMA memory.
 *
 * \param file_priv DRM file private.
 * \param vma virtual memory area.
 * \return zero on success or a negative number on failure.
 *
 * If the virtual memory area has no offset associated with it then it's a DMA
 * area, so calls mmap_dma(). Otherwise searches the map in drm_device::maplist,
 * checks that the restricted flag is not set, sets the virtual memory operations
 * according to the mapping type and remaps the pages. Finally sets the file
 * pointer and calls vm_open().
 */
static int mach64_drm_mmap_locked(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_local_map *map = NULL;
	resource_size_t offset = 0;
	struct drm_hash_item *hash;

	DRM_DEBUG("start = 0x%lx, end = 0x%lx, page offset = 0x%lx\n",
			  vma->vm_start, vma->vm_end, vma->vm_pgoff);

	if (!priv->authenticated)
		return -EACCES;

	/* We check for "dma". On Apple's UniNorth, it's valid to have
	 * the AGP mapped at physical address 0
	 * --BenH.
	 */
	if (!vma->vm_pgoff
#if IS_ENABLED(CONFIG_AGP)
		&& (!dev->agp
		|| dev->agp->agp_info.device->vendor != PCI_VENDOR_ID_APPLE)
#endif
	    )
		return mach64_drm_mmap_dma(filp, vma);

	if (drm_ht_find_item(&MACH64_PRIVATE(dev)->map_hash, vma->vm_pgoff, &hash)) {
		DRM_ERROR("Could not find map\n");
		return -EINVAL;
	}

	map = drm_hash_entry(hash, struct drm_map_list, hash)->map;
	if (!map || ((map->flags & _DRM_RESTRICTED) && !capable(CAP_SYS_ADMIN)))
		return -EPERM;

	/* Check for valid size. */
	if (map->size < vma->vm_end - vma->vm_start)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN) && (map->flags & _DRM_READ_ONLY)) {
		vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE);
#if defined(__i386__) || defined(__x86_64__)
		pgprot_val(vma->vm_page_prot) &= ~_PAGE_RW;
#else
		/* Ye gads this is ugly.  With more thought
		   we could move this up higher and use
		   `protection_map' instead.  */
		vma->vm_page_prot =
		    __pgprot(pte_val
			     (pte_wrprotect
			      (__pte(pgprot_val(vma->vm_page_prot)))));
#endif
	}

	switch (map->type) {
#if !defined(__arm__)
	case _DRM_AGP:
		if (dev->agp && dev->agp->cant_use_aperture) {
			/*
			 * On some platforms we can't talk to bus dma address from the CPU, so for
			 * memory of type DRM_AGP, we'll deal with sorting out the real physical
			 * pages and mappings in fault()
			 */
#if defined(__powerpc__)
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif
			vma->vm_ops = &mach64_drm_vm_ops;
			break;
		}
		fallthrough;	/* to _DRM_FRAME_BUFFER... */
#endif
	case _DRM_FRAME_BUFFER:
	case _DRM_REGISTERS:
		offset = mach64_drm_core_get_reg_ofs(dev);
		vma->vm_page_prot = mach64_drm_io_prot(map, vma);
		if (io_remap_pfn_range(vma, vma->vm_start,
				       (map->offset + offset) >> PAGE_SHIFT,
				       vma->vm_end - vma->vm_start,
				       vma->vm_page_prot))
			return -EAGAIN;
		DRM_DEBUG("   Type = %d; start = 0x%lx, end = 0x%lx,"
			  " offset = 0x%llx\n",
			  map->type,
			  vma->vm_start, vma->vm_end, (unsigned long long)(map->offset + offset));

		vma->vm_ops = &mach64_drm_vm_ops;
		break;
	case _DRM_CONSISTENT:
		/* Consistent memory is really like shared memory. But
		 * it's allocated in a different way, so avoid fault */
		if (remap_pfn_range(vma, vma->vm_start,
		    page_to_pfn(virt_to_page(map->handle)),
		    vma->vm_end - vma->vm_start, vma->vm_page_prot))
			return -EAGAIN;
		vma->vm_page_prot = mach64_drm_dma_prot(map->type, vma);
		fallthrough;	/* to _DRM_SHM */
	case _DRM_SHM:
		vma->vm_ops = &mach64_drm_vm_shm_ops;
		vma->vm_private_data = (void *)map;
		break;
	case _DRM_SCATTER_GATHER:
		vma->vm_ops = &mach64_drm_vm_sg_ops;
		vma->vm_private_data = (void *)map;
		vma->vm_page_prot = mach64_drm_dma_prot(map->type, vma);
		break;
	default:
		return -EINVAL;	/* This should never happen. */
	}
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	mach64_drm_vm_open_locked(dev, vma);
	return 0;
}

int mach64_drm_legacy_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev = priv->minor->dev;
	int ret;

	if (drm_dev_is_unplugged(dev))
		return -ENODEV;

	mutex_lock(&dev->struct_mutex);
	ret = mach64_drm_mmap_locked(filp, vma);
	mutex_unlock(&dev->struct_mutex);

	return ret;
}

void mach64_drm_legacy_vma_flush(struct drm_device *dev)
{
	struct mach64_drm_vma_entry *vma, *vma_temp;

	/ * Clear vma list (only needed for legacy drivers) * /
	list_for_each_entry_safe(vma, vma_temp, &dev->vmalist, head) {
		list_del(&vma->head);
		kfree(vma);
	}
}

#endif

#endif

#endif
