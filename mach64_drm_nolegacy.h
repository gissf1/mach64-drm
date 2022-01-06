/* By Brian Gisseler
** Based on existing mach64 driver and linux kernel sources
** Released under GPL
*/

#ifndef __MACH64_DRM_NOLEGACY_H__
#define __MACH64_DRM_NOLEGACY_H__

#if IS_ENABLED(CONFIG_DRM_LEGACY)

#define mach64_drm_pci_alloc drm_pci_alloc
#define mach64_drm_pci_free drm_pci_free
#define mach64_drm_legacy_pci_init drm_legacy_pci_init
#define mach64_drm_legacy_pci_exit drm_legacy_pci_exit
#define mach64_drm_legacy_findmap drm_legacy_findmap
#define mach64_drm_legacy_getsarea drm_legacy_getsarea
#define mach64_drm_legacy_mmap drm_legacy_mmap

#else

#include "mach64_drm.h"
#include "mach64_drv.h"

drm_dma_handle_t *mach64_drm_pci_alloc(struct drm_device * dev, size_t size, size_t align);
void mach64_drm_pci_free(struct drm_device * dev, drm_dma_handle_t * dmah);
int mach64_drm_legacy_pci_init(struct drm_driver *driver, struct pci_driver *pdriver);
void mach64_drm_legacy_pci_exit(struct drm_driver *driver, struct pci_driver *pdriver);

struct drm_local_map *mach64_drm_legacy_findmap(struct drm_device *dev, unsigned int token);
struct drm_local_map *mach64_drm_legacy_getsarea(struct drm_device *dev);
int mach64_drm_legacy_mmap(struct file *filp, struct vm_area_struct *vma);


#if IS_ENABLED(CONFIG_DRM_VM)

#define mach64_drm_vma_entry drm_vma_entry

#define mach64_drm_io_prot drm_io_prot
#define mach64_drm_dma_prot drm_dma_prot
#define mach64_drm_vm_fault drm_vm_fault
#define mach64_drm_vm_shm_fault drm_vm_shm_fault
#define mach64_drm_vm_shm_close drm_vm_shm_close
#define mach64_drm_vm_dma_fault drm_vm_dma_fault
#define mach64_drm_vm_sg_fault drm_vm_sg_fault
#define mach64_drm_vm_open_locked drm_vm_open_locked
#define mach64_drm_vm_open drm_vm_open
#define mach64_drm_vm_close drm_vm_close
#define mach64_drm_core_get_reg_ofs drm_core_get_reg_ofs

#else

struct mach64_drm_vma_entry;

static pgprot_t mach64_drm_io_prot(struct drm_local_map *map, struct vm_area_struct *vma);
static pgprot_t mach64_drm_dma_prot(uint32_t map_type, struct vm_area_struct *vma);
static vm_fault_t mach64_drm_vm_fault(struct vm_fault *vmf);
static vm_fault_t mach64_drm_vm_shm_fault(struct vm_fault *vmf);
static void mach64_drm_vm_shm_close(struct vm_area_struct *vma);
static vm_fault_t mach64_drm_vm_dma_fault(struct vm_fault *vmf);
static vm_fault_t mach64_drm_vm_sg_fault(struct vm_fault *vmf);
static void mach64_drm_vm_open_locked(struct drm_device *dev, struct vm_area_struct *vma);
static void mach64_drm_vm_open(struct vm_area_struct *vma);
static void mach64_drm_vm_close(struct vm_area_struct *vma);
static resource_size_t mach64_drm_core_get_reg_ofs(struct drm_device *dev);

#endif

#endif

#endif
