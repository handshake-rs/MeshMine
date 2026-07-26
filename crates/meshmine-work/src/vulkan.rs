use std::{
    ffi::CStr,
    io::Cursor,
    mem::size_of,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ash::{Entry, vk};
use meshmine_hns::MinerHeader;
use thiserror::Error;

use crate::{
    BackendError, BackendKind, DeviceCapabilities, DeviceEvent, MiningBackend, PreparedDeviceJob,
};

const INPUT_WORDS: usize = 53;
const WORKGROUP_SIZE: u32 = 64;
const SHADER: &[u8] = include_bytes!("vulkan_hash.spv");

#[derive(Debug, Error)]
pub enum VulkanHashError {
    #[error("Vulkan loader failed: {0}")]
    Loader(String),
    #[error("Vulkan operation failed: {0:?}")]
    Vulkan(vk::Result),
    #[error("no hardware Vulkan compute device is available")]
    NoDevice,
    #[error("Vulkan compute queue is unavailable")]
    NoQueue,
    #[error("host-visible coherent Vulkan memory is unavailable")]
    NoMemory,
    #[error("Vulkan hash batch is outside configured bounds")]
    BatchBounds,
    #[error("Vulkan hit buffer overflowed; lower the device target or increase capacity")]
    HitOverflow,
    #[error("Vulkan shader result disagrees with the scalar HNS oracle")]
    ScalarMismatch,
}

impl From<vk::Result> for VulkanHashError {
    fn from(value: vk::Result) -> Self {
        Self::Vulkan(value)
    }
}

struct VulkanBuffer {
    buffer: vk::Buffer,
    memory: vk::DeviceMemory,
    bytes: vk::DeviceSize,
}

/// Persistent headless Vulkan compute context for the HNS share-hash kernel.
///
/// The checked-in SPIR-V contains no Int64 capability and therefore runs on
/// V3D as well as ordinary discrete GPUs. Every returned nonce is rechecked by
/// the scalar Rust oracle before it can become a MeshMine device event.
pub struct VulkanHasher {
    _entry: Entry,
    instance: ash::Instance,
    device: ash::Device,
    queue: vk::Queue,
    device_name: String,
    descriptor_set_layout: vk::DescriptorSetLayout,
    pipeline_layout: vk::PipelineLayout,
    pipeline: vk::Pipeline,
    descriptor_pool: vk::DescriptorPool,
    descriptor_set: vk::DescriptorSet,
    command_pool: vk::CommandPool,
    command_buffer: vk::CommandBuffer,
    fence: vk::Fence,
    input: VulkanBuffer,
    output: VulkanBuffer,
    maximum_batch: u32,
    maximum_hits: u32,
}

impl VulkanHasher {
    pub fn new(
        hardware_device_index: usize,
        maximum_batch: u32,
        maximum_hits: u32,
    ) -> Result<Self, VulkanHashError> {
        if maximum_batch == 0 || maximum_hits == 0 {
            return Err(VulkanHashError::BatchBounds);
        }
        // SAFETY: ash loads the process Vulkan loader; the returned entry owns
        // all function pointers for at least as long as the instance.
        let entry =
            unsafe { Entry::load() }.map_err(|error| VulkanHashError::Loader(error.to_string()))?;
        let application_name = c"MeshMine Vulkan worker";
        let application = vk::ApplicationInfo::default()
            .application_name(application_name)
            .application_version(1)
            .engine_name(application_name)
            .engine_version(1)
            .api_version(vk::API_VERSION_1_1);
        let create = vk::InstanceCreateInfo::default().application_info(&application);
        // SAFETY: create contains no dangling extension pointers.
        let instance = unsafe { entry.create_instance(&create, None) }?;
        // SAFETY: instance is live.
        let physical_devices = unsafe { instance.enumerate_physical_devices() }?;
        let hardware = physical_devices
            .into_iter()
            .filter_map(|physical| {
                // SAFETY: physical came from this live instance.
                let properties = unsafe { instance.get_physical_device_properties(physical) };
                matches!(
                    properties.device_type,
                    vk::PhysicalDeviceType::INTEGRATED_GPU
                        | vk::PhysicalDeviceType::DISCRETE_GPU
                        | vk::PhysicalDeviceType::VIRTUAL_GPU
                )
                .then_some((physical, properties))
            })
            .collect::<Vec<_>>();
        let Some((physical, properties)) = hardware.get(hardware_device_index).copied() else {
            // SAFETY: no child objects have been created.
            unsafe { instance.destroy_instance(None) };
            return Err(VulkanHashError::NoDevice);
        };
        // SAFETY: Vulkan guarantees a terminated device_name array.
        let device_name = unsafe { CStr::from_ptr(properties.device_name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: physical came from this instance.
        let queue_families =
            unsafe { instance.get_physical_device_queue_family_properties(physical) };
        let Some(queue_family) = queue_families
            .iter()
            .position(|family| family.queue_flags.contains(vk::QueueFlags::COMPUTE))
        else {
            // SAFETY: no child objects have been created.
            unsafe { instance.destroy_instance(None) };
            return Err(VulkanHashError::NoQueue);
        };
        let queue_family = u32::try_from(queue_family).map_err(|_| VulkanHashError::NoQueue)?;
        let priorities = [1.0f32];
        let queue_create = [vk::DeviceQueueCreateInfo::default()
            .queue_family_index(queue_family)
            .queue_priorities(&priorities)];
        let device_create = vk::DeviceCreateInfo::default().queue_create_infos(&queue_create);
        // SAFETY: queue_create points to live stack storage for this call.
        let device = unsafe { instance.create_device(physical, &device_create, None) }?;
        // SAFETY: the requested queue was created above.
        let queue = unsafe { device.get_device_queue(queue_family, 0) };

        (|| -> Result<Self, VulkanHashError> {
            let input = create_buffer(
                &instance,
                &device,
                physical,
                vk::DeviceSize::try_from(INPUT_WORDS * size_of::<u32>())
                    .map_err(|_| VulkanHashError::BatchBounds)?,
            )?;
            let output_words = usize::try_from(maximum_hits)
                .map_err(|_| VulkanHashError::BatchBounds)?
                .checked_add(2)
                .ok_or(VulkanHashError::BatchBounds)?;
            let output = create_buffer(
                &instance,
                &device,
                physical,
                vk::DeviceSize::try_from(output_words * size_of::<u32>())
                    .map_err(|_| VulkanHashError::BatchBounds)?,
            )?;
            let bindings = [
                vk::DescriptorSetLayoutBinding::default()
                    .binding(0)
                    .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                    .descriptor_count(1)
                    .stage_flags(vk::ShaderStageFlags::COMPUTE),
                vk::DescriptorSetLayoutBinding::default()
                    .binding(1)
                    .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                    .descriptor_count(1)
                    .stage_flags(vk::ShaderStageFlags::COMPUTE),
            ];
            let descriptor_layout_create =
                vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings);
            // SAFETY: descriptor layout bindings are valid for this call.
            let descriptor_set_layout =
                unsafe { device.create_descriptor_set_layout(&descriptor_layout_create, None) }?;
            let set_layouts = [descriptor_set_layout];
            let pipeline_layout_create =
                vk::PipelineLayoutCreateInfo::default().set_layouts(&set_layouts);
            // SAFETY: descriptor_set_layout is live.
            let pipeline_layout =
                unsafe { device.create_pipeline_layout(&pipeline_layout_create, None) }?;
            let mut shader_cursor = Cursor::new(SHADER);
            let shader_words = ash::util::read_spv(&mut shader_cursor)
                .map_err(|error| VulkanHashError::Loader(error.to_string()))?;
            let shader_create = vk::ShaderModuleCreateInfo::default().code(&shader_words);
            // SAFETY: checked-in SPIR-V passed spirv-val and code remains live.
            let shader = unsafe { device.create_shader_module(&shader_create, None) }?;
            let stage = vk::PipelineShaderStageCreateInfo::default()
                .stage(vk::ShaderStageFlags::COMPUTE)
                .module(shader)
                .name(c"main");
            let pipeline_create = [vk::ComputePipelineCreateInfo::default()
                .stage(stage)
                .layout(pipeline_layout)];
            // SAFETY: shader and pipeline layout are live during creation.
            let pipeline = unsafe {
                device.create_compute_pipelines(vk::PipelineCache::null(), &pipeline_create, None)
            }
            .map_err(|(_, error)| VulkanHashError::Vulkan(error))?[0];
            // SAFETY: pipeline retains the compiled shader.
            unsafe { device.destroy_shader_module(shader, None) };
            let pool_sizes = [vk::DescriptorPoolSize {
                ty: vk::DescriptorType::STORAGE_BUFFER,
                descriptor_count: 2,
            }];
            let descriptor_pool_create = vk::DescriptorPoolCreateInfo::default()
                .max_sets(1)
                .pool_sizes(&pool_sizes);
            // SAFETY: pool create info is self-contained.
            let descriptor_pool =
                unsafe { device.create_descriptor_pool(&descriptor_pool_create, None) }?;
            let allocate = vk::DescriptorSetAllocateInfo::default()
                .descriptor_pool(descriptor_pool)
                .set_layouts(&set_layouts);
            // SAFETY: pool and layout are live.
            let descriptor_set = unsafe { device.allocate_descriptor_sets(&allocate) }?[0];
            let input_info = [vk::DescriptorBufferInfo {
                buffer: input.buffer,
                offset: 0,
                range: input.bytes,
            }];
            let output_info = [vk::DescriptorBufferInfo {
                buffer: output.buffer,
                offset: 0,
                range: output.bytes,
            }];
            let writes = [
                vk::WriteDescriptorSet::default()
                    .dst_set(descriptor_set)
                    .dst_binding(0)
                    .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                    .buffer_info(&input_info),
                vk::WriteDescriptorSet::default()
                    .dst_set(descriptor_set)
                    .dst_binding(1)
                    .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                    .buffer_info(&output_info),
            ];
            // SAFETY: descriptor buffers and set are live.
            unsafe { device.update_descriptor_sets(&writes, &[]) };
            let command_pool_create = vk::CommandPoolCreateInfo::default()
                .queue_family_index(queue_family)
                .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER);
            // SAFETY: queue family belongs to this device.
            let command_pool = unsafe { device.create_command_pool(&command_pool_create, None) }?;
            let command_allocate = vk::CommandBufferAllocateInfo::default()
                .command_pool(command_pool)
                .level(vk::CommandBufferLevel::PRIMARY)
                .command_buffer_count(1);
            // SAFETY: command pool is live.
            let command_buffer = unsafe { device.allocate_command_buffers(&command_allocate) }?[0];
            let fence_create = vk::FenceCreateInfo::default();
            // SAFETY: fence create info is self-contained.
            let fence = unsafe { device.create_fence(&fence_create, None) }?;
            Ok(Self {
                _entry: entry,
                instance,
                device,
                queue,
                device_name,
                descriptor_set_layout,
                pipeline_layout,
                pipeline,
                descriptor_pool,
                descriptor_set,
                command_pool,
                command_buffer,
                fence,
                input,
                output,
                maximum_batch,
                maximum_hits,
            })
        })()
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn hash_batch(
        &mut self,
        header: &MinerHeader,
        target: [u8; 32],
        nonce_start: u32,
        nonce_count: u32,
    ) -> Result<Vec<u32>, VulkanHashError> {
        if nonce_count == 0
            || nonce_count > self.maximum_batch
            || nonce_start.checked_add(nonce_count - 1).is_none()
        {
            return Err(VulkanHashError::BatchBounds);
        }
        let mut input = Vec::with_capacity(INPUT_WORDS);
        append_words(&mut input, &header.preheader());
        let padding8 = deterministic_padding(&header.prev_block, &header.tree_root, 8);
        append_words(&mut input, &padding8);
        let padding32 = deterministic_padding(&header.prev_block, &header.tree_root, 32);
        append_words(&mut input, &padding32);
        append_words(&mut input, &target);
        input.extend_from_slice(&[nonce_start, nonce_count, self.maximum_hits]);
        if input.len() != INPUT_WORDS {
            return Err(VulkanHashError::BatchBounds);
        }
        self.write_memory(&self.input, &input)?;
        let output_words = usize::try_from(self.maximum_hits)
            .map_err(|_| VulkanHashError::BatchBounds)?
            .checked_add(2)
            .ok_or(VulkanHashError::BatchBounds)?;
        self.write_memory(&self.output, &vec![0; output_words])?;

        // SAFETY: all command resources and descriptors are live and owned by
        // this context; the fence serializes buffer reuse.
        unsafe {
            self.device.reset_fences(&[self.fence])?;
            self.device
                .reset_command_buffer(self.command_buffer, vk::CommandBufferResetFlags::empty())?;
            self.device.begin_command_buffer(
                self.command_buffer,
                &vk::CommandBufferBeginInfo::default(),
            )?;
            self.device.cmd_bind_pipeline(
                self.command_buffer,
                vk::PipelineBindPoint::COMPUTE,
                self.pipeline,
            );
            self.device.cmd_bind_descriptor_sets(
                self.command_buffer,
                vk::PipelineBindPoint::COMPUTE,
                self.pipeline_layout,
                0,
                &[self.descriptor_set],
                &[],
            );
            self.device.cmd_dispatch(
                self.command_buffer,
                nonce_count.div_ceil(WORKGROUP_SIZE),
                1,
                1,
            );
            self.device.end_command_buffer(self.command_buffer)?;
            let command_buffers = [self.command_buffer];
            let submissions = [vk::SubmitInfo::default().command_buffers(&command_buffers)];
            self.device
                .queue_submit(self.queue, &submissions, self.fence)?;
            self.device.wait_for_fences(&[self.fence], true, u64::MAX)?;
        }
        let output = self.read_memory(&self.output, output_words)?;
        if output[1] != 0 || output[0] > self.maximum_hits {
            return Err(VulkanHashError::HitOverflow);
        }
        let hit_count = usize::try_from(output[0]).map_err(|_| VulkanHashError::HitOverflow)?;
        let hits = output[2..2 + hit_count].to_vec();
        let scalar = header.prepare_hasher();
        if hits.iter().any(|nonce| {
            *nonce < nonce_start
                || *nonce >= nonce_start.saturating_add(nonce_count)
                || scalar.share_hash(*nonce) > target
        }) {
            return Err(VulkanHashError::ScalarMismatch);
        }
        Ok(hits)
    }

    fn write_memory(&self, buffer: &VulkanBuffer, words: &[u32]) -> Result<(), VulkanHashError> {
        let bytes = vk::DeviceSize::try_from(std::mem::size_of_val(words))
            .map_err(|_| VulkanHashError::BatchBounds)?;
        if bytes > buffer.bytes {
            return Err(VulkanHashError::BatchBounds);
        }
        // SAFETY: allocation is HOST_VISIBLE|HOST_COHERENT and the mapped
        // range is bounded by the allocation.
        unsafe {
            let mapped = self.device.map_memory(
                buffer.memory,
                0,
                buffer.bytes,
                vk::MemoryMapFlags::empty(),
            )?;
            ptr::copy_nonoverlapping(words.as_ptr(), mapped.cast::<u32>(), words.len());
            self.device.unmap_memory(buffer.memory);
        }
        Ok(())
    }

    fn read_memory(
        &self,
        buffer: &VulkanBuffer,
        words: usize,
    ) -> Result<Vec<u32>, VulkanHashError> {
        let bytes = vk::DeviceSize::try_from(words * size_of::<u32>())
            .map_err(|_| VulkanHashError::BatchBounds)?;
        if bytes > buffer.bytes {
            return Err(VulkanHashError::BatchBounds);
        }
        let mut output = vec![0u32; words];
        // SAFETY: allocation is HOST_VISIBLE|HOST_COHERENT and both source and
        // destination ranges contain `words` u32 values.
        unsafe {
            let mapped = self.device.map_memory(
                buffer.memory,
                0,
                buffer.bytes,
                vk::MemoryMapFlags::empty(),
            )?;
            ptr::copy_nonoverlapping(mapped.cast::<u32>(), output.as_mut_ptr(), words);
            self.device.unmap_memory(buffer.memory);
        }
        Ok(output)
    }
}

impl Drop for VulkanHasher {
    fn drop(&mut self) {
        // SAFETY: all handles were created by this device and are destroyed in
        // reverse dependency order after waiting for submitted work.
        unsafe {
            let _ = self.device.device_wait_idle();
            self.device.destroy_fence(self.fence, None);
            self.device.destroy_command_pool(self.command_pool, None);
            self.device
                .destroy_descriptor_pool(self.descriptor_pool, None);
            self.device.destroy_pipeline(self.pipeline, None);
            self.device
                .destroy_pipeline_layout(self.pipeline_layout, None);
            self.device
                .destroy_descriptor_set_layout(self.descriptor_set_layout, None);
            self.device.destroy_buffer(self.output.buffer, None);
            self.device.free_memory(self.output.memory, None);
            self.device.destroy_buffer(self.input.buffer, None);
            self.device.free_memory(self.input.memory, None);
            self.device.destroy_device(None);
            self.instance.destroy_instance(None);
        }
    }
}

fn create_buffer(
    instance: &ash::Instance,
    device: &ash::Device,
    physical: vk::PhysicalDevice,
    bytes: vk::DeviceSize,
) -> Result<VulkanBuffer, VulkanHashError> {
    let create = vk::BufferCreateInfo::default()
        .size(bytes)
        .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
        .sharing_mode(vk::SharingMode::EXCLUSIVE);
    // SAFETY: create info is self-contained.
    let buffer = unsafe { device.create_buffer(&create, None) }?;
    // SAFETY: buffer is live.
    let requirements = unsafe { device.get_buffer_memory_requirements(buffer) };
    // SAFETY: physical belongs to instance.
    let properties = unsafe { instance.get_physical_device_memory_properties(physical) };
    let memory_type = (0..properties.memory_type_count)
        .find(|index| {
            requirements.memory_type_bits & (1u32 << index) != 0
                && properties.memory_types[*index as usize]
                    .property_flags
                    .contains(
                        vk::MemoryPropertyFlags::HOST_VISIBLE
                            | vk::MemoryPropertyFlags::HOST_COHERENT,
                    )
        })
        .ok_or(VulkanHashError::NoMemory)?;
    let allocate = vk::MemoryAllocateInfo::default()
        .allocation_size(requirements.size)
        .memory_type_index(memory_type);
    // SAFETY: memory type and size satisfy the queried requirements.
    let memory = unsafe { device.allocate_memory(&allocate, None) }?;
    // SAFETY: allocation satisfies this buffer's requirements.
    unsafe { device.bind_buffer_memory(buffer, memory, 0) }?;
    Ok(VulkanBuffer {
        buffer,
        memory,
        bytes,
    })
}

fn append_words(output: &mut Vec<u32>, bytes: &[u8]) {
    debug_assert_eq!(bytes.len() % 4, 0);
    output.extend(
        bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four-byte chunk"))),
    );
}

fn deterministic_padding(previous_block: &[u8; 32], tree_root: &[u8; 32], size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| previous_block[index % 32] ^ tree_root[index % 32])
        .collect()
}

pub struct VulkanBackend {
    capabilities: DeviceCapabilities,
    prepared: Option<PreparedDeviceJob>,
    active_generation: Option<u64>,
    hardware_device_index: usize,
    maximum_batch: u32,
    maximum_hits: u32,
    event_capacity: usize,
    worker: Option<VulkanWorker>,
}

struct VulkanWorker {
    cancel: Arc<AtomicBool>,
    events: Receiver<DeviceEvent>,
    handle: JoinHandle<()>,
}

impl VulkanBackend {
    pub fn new(
        capabilities: DeviceCapabilities,
        hardware_device_index: usize,
        maximum_batch: u32,
        maximum_hits: u32,
        event_capacity: usize,
    ) -> Result<Self, BackendError> {
        capabilities
            .validate()
            .map_err(|_| BackendError::InvalidCapabilities)?;
        if capabilities.backend_kind != BackendKind::Vulkan
            || !capabilities.supports_nonce_range
            || !capabilities.supports_job_prepare
            || !capabilities.reports_range_completion
            || maximum_batch == 0
            || maximum_hits == 0
            || event_capacity == 0
        {
            return Err(BackendError::InvalidCapabilities);
        }
        Ok(Self {
            capabilities,
            prepared: None,
            active_generation: None,
            hardware_device_index,
            maximum_batch,
            maximum_hits,
            event_capacity,
            worker: None,
        })
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.cancel.store(true, Ordering::Release);
            let _ = worker.handle.join();
        }
    }
}

impl Drop for VulkanBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

impl MiningBackend for VulkanBackend {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }

    fn prepare_job(&mut self, job: &PreparedDeviceJob) -> Result<(), BackendError> {
        if self
            .prepared
            .as_ref()
            .is_some_and(|current| current.generation == job.generation && current != job)
        {
            return Err(BackendError::ConflictingPreparedJob);
        }
        if job.nonce_stride != 1 {
            return Err(BackendError::Operation(
                "Vulkan backend requires a contiguous nonce lease".to_owned(),
            ));
        }
        self.stop_worker();
        self.active_generation = None;
        self.prepared = Some(job.clone());
        Ok(())
    }

    fn activate_job(&mut self, generation: u64) -> Result<(), BackendError> {
        let job = self
            .prepared
            .as_ref()
            .filter(|job| job.generation == generation)
            .cloned()
            .ok_or(BackendError::GenerationNotPrepared)?;
        self.stop_worker();
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, events) = sync_channel(self.event_capacity);
        let worker_cancel = Arc::clone(&cancel);
        let device_index = self.hardware_device_index;
        let maximum_batch = self.maximum_batch;
        let maximum_hits = self.maximum_hits;
        let handle = thread::Builder::new()
            .name(format!(
                "meshmine-vulkan-{}",
                hex::encode(&self.capabilities.device_id[..4])
            ))
            .spawn(move || {
                run_vulkan_worker(
                    &job,
                    device_index,
                    maximum_batch,
                    maximum_hits,
                    &worker_cancel,
                    &sender,
                );
            })
            .map_err(|error| BackendError::Operation(error.to_string()))?;
        self.worker = Some(VulkanWorker {
            cancel,
            events,
            handle,
        });
        self.active_generation = Some(generation);
        Ok(())
    }

    fn cancel_job(&mut self, generation: u64) -> Result<(), BackendError> {
        if self.active_generation == Some(generation) {
            self.stop_worker();
            self.active_generation = None;
        }
        if self.prepared.as_ref().map(|job| job.generation) == Some(generation) {
            self.prepared = None;
        }
        Ok(())
    }

    fn poll_events(&mut self, output: &mut dyn FnMut(DeviceEvent)) -> Result<(), BackendError> {
        let Some(worker) = &self.worker else {
            return Ok(());
        };
        loop {
            match worker.events.try_recv() {
                Ok(event) => output(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

fn run_vulkan_worker(
    job: &PreparedDeviceJob,
    hardware_device_index: usize,
    maximum_batch: u32,
    maximum_hits: u32,
    cancel: &AtomicBool,
    sender: &SyncSender<DeviceEvent>,
) {
    let Ok(mut hasher) = VulkanHasher::new(hardware_device_index, maximum_batch, maximum_hits)
    else {
        let _ = sender.try_send(DeviceEvent::Disconnected);
        return;
    };
    if !send_event(
        sender,
        cancel,
        DeviceEvent::JobAcknowledged {
            generation: job.generation,
            observed_at_ms: unix_time_ms(),
        },
    ) {
        return;
    }
    let mut header = MinerHeader {
        nonce: job.nonce_start,
        time: job.ntime,
        prev_block: job.previous_block,
        tree_root: job.tree_root,
        mask_hash: job.mask_hash,
        extra_nonce: job.extra_nonce_start,
        reserved_root: job.reserved_root,
        witness_root: job.witness_root,
        merkle_root: job.merkle_root,
        version: job.version,
        bits: job.bits,
    };
    let mut extra_nonce = job.extra_nonce_start;
    let mut nonce = job.nonce_start;
    let mut hashes = 0u64;
    let mut report_started = Instant::now();
    loop {
        if cancel.load(Ordering::Acquire) {
            return;
        }
        header.extra_nonce = extra_nonce;
        let remaining = job.nonce_end.saturating_sub(nonce).saturating_add(1);
        let count = remaining.min(maximum_batch);
        let hits = match hasher.hash_batch(&header, job.edge_target.0, nonce, count) {
            Ok(hits) => hits,
            Err(_) => {
                let _ = sender.try_send(DeviceEvent::Disconnected);
                return;
            }
        };
        let received_at_ms = unix_time_ms();
        for hit in hits {
            let raw_share_hash = header.prepare_hasher().share_hash(hit);
            if !send_event(
                sender,
                cancel,
                DeviceEvent::Capture {
                    generation: job.generation,
                    nonce: hit,
                    ntime: job.ntime,
                    extra_nonce,
                    raw_share_hash,
                    received_at_ms,
                },
            ) {
                return;
            }
        }
        hashes = hashes.saturating_add(u64::from(count));
        let elapsed = report_started.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let rate = u128::from(hashes)
                .saturating_mul(1_000_000_000)
                .checked_div(elapsed.as_nanos().max(1))
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(u64::MAX);
            let _ = sender.try_send(DeviceEvent::Telemetry {
                generation: job.generation,
                hashes_reported: Some(rate),
                temperature_millicelsius: None,
                power_millijoules: None,
            });
            hashes = 0;
            report_started = Instant::now();
        }
        if count == remaining {
            if extra_nonce == job.extra_nonce_end {
                let _ = send_event(
                    sender,
                    cancel,
                    DeviceEvent::RangeCompleted {
                        generation: job.generation,
                        lease_id: job.lease_id,
                    },
                );
                return;
            }
            let Some(next) = next_extra_nonce(extra_nonce, job.extra_nonce_end) else {
                let _ = sender.try_send(DeviceEvent::Disconnected);
                return;
            };
            extra_nonce = next;
            nonce = job.nonce_start;
        } else {
            nonce = nonce.saturating_add(count);
        }
    }
}

fn next_extra_nonce(current: [u8; 24], end: [u8; 24]) -> Option<[u8; 24]> {
    if current >= end || current[..4] != end[..4] || current[8..] != [0; 16] || end[8..] != [0; 16]
    {
        return None;
    }
    let value = u32::from_be_bytes(current[4..8].try_into().ok()?);
    let mut next = current;
    next[4..8].copy_from_slice(&value.checked_add(1)?.to_be_bytes());
    (next <= end).then_some(next)
}

fn send_event(
    sender: &SyncSender<DeviceEvent>,
    cancel: &AtomicBool,
    mut event: DeviceEvent,
) -> bool {
    loop {
        match sender.try_send(event) {
            Ok(()) => return true,
            Err(TrySendError::Full(returned)) => {
                if cancel.load(Ordering::Acquire) {
                    return false;
                }
                event = returned;
                thread::yield_now();
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> MinerHeader {
        MinerHeader {
            nonce: 0,
            time: 1_717_171_717,
            prev_block: [1; 32],
            tree_root: [2; 32],
            mask_hash: [3; 32],
            extra_nonce: [4; 24],
            reserved_root: [5; 32],
            witness_root: [6; 32],
            merkle_root: [7; 32],
            version: 8,
            bits: 0x207f_ffff,
        }
    }

    #[test]
    #[ignore = "requires a Vulkan compute device"]
    fn hardware_kernel_matches_scalar_oracle_for_complete_easy_batch() {
        let mut hasher = VulkanHasher::new(0, 128, 128).expect("hardware Vulkan compute device");
        let mut hits = hasher
            .hash_batch(&test_header(), [0xff; 32], 41, 128)
            .expect("Vulkan hash batch");
        hits.sort_unstable();
        assert_eq!(hits, (41..169).collect::<Vec<_>>());
    }

    #[test]
    #[ignore = "hardware throughput measurement"]
    fn measure_hardware_kernel_throughput() {
        const HASHES: u32 = 65_536;
        let mut hasher =
            VulkanHasher::new(0, HASHES, 1_024).expect("hardware Vulkan compute device");
        let started = Instant::now();
        let hits = hasher
            .hash_batch(&test_header(), [0; 32], 0, HASHES)
            .expect("Vulkan hash batch");
        assert!(hits.is_empty());
        let elapsed = started.elapsed();
        let rate = u128::from(HASHES)
            .saturating_mul(1_000_000_000)
            .checked_div(elapsed.as_nanos().max(1))
            .unwrap_or(0);
        println!(
            "device={} hashes={} elapsed_ms={} hashes_per_second={rate}",
            hasher.device_name(),
            HASHES,
            elapsed.as_millis()
        );
    }
}
