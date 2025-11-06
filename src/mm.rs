use axerrno::{AxResult, AxError};
use starry_process::Pid;
use starry_core::task::get_process_data;
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr};
use axhal::mem::phys_to_virt;

pub fn read_from_tracee(tracee_pid: Pid, virt_addr: usize, buffer: &mut [u8]) -> AxResult<()> {
    let tracee_proc_data = get_process_data(tracee_pid)?;
    let tracee_aspace = tracee_proc_data.aspace.lock();

    let base_addr = tracee_aspace.base();
    let end_addr = tracee_aspace.end();

    if virt_addr < base_addr.into() || virt_addr + buffer.len() > end_addr.into() {
        return Err(AxError::BadAddress);
    }

    unsafe {
        read_via_tracee_pgtable(&tracee_aspace, virt_addr, buffer)
    }
}

unsafe fn read_via_tracee_pgtable(
    aspace: &axmm::AddrSpace,
    virt_addr: usize,
    buffer: &mut [u8],
) -> AxResult<()> {
    let mut offset = 0;
    let pgtable = aspace.page_table();

    while offset < buffer.len() {
        let va = virt_addr + offset;
        let va_aligned = VirtAddr::from(va).align_down_4k();

        // Query the page table to get the physical address (with offset already included)
        let (pa, _flags, _size) = pgtable.query(va_aligned)
            .map_err(|_| AxError::BadAddress)?;

        // Calculate offset within the page
        let page_offset = va % PAGE_SIZE_4K;
        let to_read = core::cmp::min(buffer.len() - offset, PAGE_SIZE_4K - page_offset);

        // Convert physical address to kernel virtual address that we can access
        let kernel_vaddr = phys_to_virt(pa.add(page_offset));
        let phys_slice = unsafe {
            core::slice::from_raw_parts(
                kernel_vaddr.as_ptr() as *const u8,
                to_read,
            )
        };

        buffer[offset..offset + to_read].copy_from_slice(phys_slice);
        offset += to_read;
    }
    Ok(())
}