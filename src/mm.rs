use axerrno::{AxError, AxResult};
use axhal::mem::phys_to_virt;
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr};
use starry_core::task::get_process_data;
use starry_process::Pid;

/// Read memory from a tracee's address space into the provided buffer.
///
/// # Arguments
/// * `tracee_pid` - The PID of the tracee process to read from.
/// * `virt_addr` - The virtual address in the tracee's address space to read from.
/// * `buffer` - The buffer to fill with the read data.
///
/// # Returns
/// * `AxResult<()>` - Ok on success, Err on failure (e.g., bad address).
pub fn read_from_tracee(tracee_pid: Pid, virt_addr: usize, buffer: &mut [u8]) -> AxResult<()> {
    let tracee_proc_data = get_process_data(tracee_pid)?;
    let tracee_aspace = tracee_proc_data.aspace.lock();

    let base_addr = tracee_aspace.base();
    let end_addr = tracee_aspace.end();

    if virt_addr < base_addr.into() || virt_addr + buffer.len() > end_addr.into() {
        return Err(AxError::BadAddress);
    }

    unsafe { read_via_tracee_pgtable(&tracee_aspace, virt_addr, buffer) }
}

/// Internal helper to read memory from a tracee's address space using its page table.
///
/// This function would:
/// 1. Iterate over the buffer in page-sized chunks.
/// 2. For each chunk, query the tracee's page table to get the physical address.
/// 3. Map the physical address to a kernel virtual address.
/// 4. Copy the data from the kernel virtual address to the provided buffer.
///
/// # Safety
/// This function performs raw pointer dereferencing and assumes the
/// provided address space and virtual address are valid.
///
/// # Arguments
/// * `aspace` - The address space of the tracee process.
/// * `virt_addr` - The starting virtual address to read from.
/// * `buffer` - The buffer to fill with the read data.
///
/// # Returns
/// * `AxResult<()>` - Ok on success, Err on failure (e.g., bad address).
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
        let (pa, _flags, _size) = pgtable.query(va_aligned).map_err(|_| AxError::BadAddress)?;

        // Calculate offset within the page
        let page_offset = va % PAGE_SIZE_4K;
        let to_read = core::cmp::min(buffer.len() - offset, PAGE_SIZE_4K - page_offset);

        // Convert physical address to kernel virtual address that we can access
        let kernel_vaddr = phys_to_virt(pa.add(page_offset));
        let phys_slice =
            unsafe { core::slice::from_raw_parts(kernel_vaddr.as_ptr() as *const u8, to_read) };

        buffer[offset..offset + to_read].copy_from_slice(phys_slice);
        offset += to_read;
    }
    Ok(())
}
