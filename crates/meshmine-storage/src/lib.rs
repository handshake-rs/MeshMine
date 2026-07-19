//! Transactional embedded storage used at MeshMine durable-write boundaries.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::fs;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::mem::MaybeUninit;
use std::ops::Bound::{Excluded, Included};
use std::path::Path;
use std::sync::RwLock;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::path::Component;

#[cfg(target_os = "linux")]
use redb::ReadOnlyDatabase;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use thiserror::Error;

const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("meshmine_records_v2");

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("storage operation failed: {0}")]
    Backend(String),
    #[error("durable store is read-only")]
    ReadOnly,
    #[error("storage key component contains a reserved separator")]
    InvalidKey,
    #[error("durable namespace scan exceeded its configured record or byte bound")]
    ScanLimit,
    #[error("durable store does not support paginated namespace scans")]
    PaginationUnsupported,
    #[error("durable store does not support multiple atomic batch conditions")]
    MultipleConditionsUnsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanLimits {
    pub maximum_records: usize,
    pub maximum_value_bytes: u64,
    pub maximum_total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceRecord {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespacePage {
    pub records: Vec<NamespaceRecord>,
    /// `true` means a greater key existed in the same backend view and the
    /// last returned key can be supplied as the next exclusive cursor.
    /// `false` is the terminal page, including an empty namespace.
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchOperation {
    Put {
        namespace: String,
        key: String,
        value: Vec<u8>,
    },
    Delete {
        namespace: String,
        key: String,
    },
}

/// One exact pre-batch condition for an atomic durable mutation.
///
/// `expected = None` requires the key to be absent. Conditions always observe
/// the state before any operation in the associated batch is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchCondition {
    pub namespace: String,
    pub key: String,
    pub expected: Option<Vec<u8>>,
}

impl BatchCondition {
    pub fn new(
        namespace: impl Into<String>,
        key: impl Into<String>,
        expected: Option<Vec<u8>>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
            expected,
        }
    }

    pub fn absent(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self::new(namespace, key, None)
    }

    pub fn equals(namespace: impl Into<String>, key: impl Into<String>, expected: Vec<u8>) -> Self {
        Self::new(namespace, key, Some(expected))
    }
}

impl BatchOperation {
    pub fn put(namespace: impl Into<String>, key: impl Into<String>, value: Vec<u8>) -> Self {
        Self::Put {
            namespace: namespace.into(),
            key: key.into(),
            value,
        }
    }

    pub fn delete(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self::Delete {
            namespace: namespace.into(),
            key: key.into(),
        }
    }
}

pub trait DurableStore: Send + Sync {
    fn put(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), StorageError>;
    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
    fn delete(&self, namespace: &str, key: &str) -> Result<(), StorageError>;

    /// Atomically replace `key` only when its current bytes equal `expected`.
    /// `None` means that the key must not exist. This is the primitive used by
    /// sequence allocators and one-signature guards across process restarts.
    fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        value: &[u8],
    ) -> Result<bool, StorageError>;

    /// Apply ordered puts and deletes in one backend transaction. All key
    /// components are validated before any mutation, and later operations for
    /// the same key observe/replace earlier operations in the batch.
    fn apply_batch(&self, operations: &[BatchOperation]) -> Result<(), StorageError>;

    /// Apply ordered puts and deletes only when the guard key's current bytes
    /// equal `expected`. `None` requires the guard key to be absent. The
    /// comparison observes the pre-batch value, including when the guard key
    /// also appears in `operations`. The comparison and every mutation occur
    /// under one backend transaction or write lock, and every key is validated
    /// before that transaction can mutate storage.
    fn apply_batch_if(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        operations: &[BatchOperation],
    ) -> Result<bool, StorageError>;

    /// Apply one ordered batch only when every exact condition matches the
    /// same pre-batch database view. All condition and operation keys are
    /// validated before mutation. Empty conditions apply the batch
    /// unconditionally.
    ///
    /// The compatibility default safely supports zero or one condition using
    /// existing trait primitives and fails closed for multiple conditions.
    /// Stores must override this method to provide native multi-key atomicity.
    fn apply_batch_if_all(
        &self,
        conditions: &[BatchCondition],
        operations: &[BatchOperation],
    ) -> Result<bool, StorageError> {
        match conditions {
            [] => {
                self.apply_batch(operations)?;
                Ok(true)
            }
            [condition] => self.apply_batch_if(
                &condition.namespace,
                &condition.key,
                condition.expected.as_deref(),
                operations,
            ),
            _ => Err(StorageError::MultipleConditionsUnsupported),
        }
    }

    /// Return one namespace in deterministic key order while enforcing bounds
    /// before recovery code allocates or accepts the complete result.
    fn scan_namespace(
        &self,
        namespace: &str,
        limits: ScanLimits,
    ) -> Result<Vec<NamespaceRecord>, StorageError>;

    /// Return one deterministic page strictly after `exclusive_cursor`.
    ///
    /// Implementations must never return `has_more = true` with an empty
    /// record list: a limit too small to admit even one available record is a
    /// [`StorageError::ScanLimit`]. Separate calls need not share one database
    /// snapshot. Recovery callers must therefore quiesce writes or pin an
    /// external high-water mark; otherwise a newly inserted key at or before a
    /// prior cursor can be missed.
    ///
    /// The default preserves source compatibility for existing store
    /// implementations while failing closed until they provide a native
    /// bounded range scan.
    fn scan_namespace_after(
        &self,
        _namespace: &str,
        _exclusive_cursor: Option<&str>,
        _limits: ScanLimits,
    ) -> Result<NamespacePage, StorageError> {
        Err(StorageError::PaginationUnsupported)
    }

    fn put_if_absent(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
    ) -> Result<bool, StorageError> {
        self.compare_and_swap(namespace, key, None, value)
    }
}

pub struct RedbStore {
    database: Database,
}

/// A descriptor-pinned, existing-only redb view that cannot mutate storage.
///
/// redb does not currently expose a portable `open_read_only_file(File)` API.
/// Linux therefore reopens the already validated descriptor through
/// `/proc/self/fd` and retains the original descriptor for the lifetime of the
/// database. Other platforms fail closed rather than falling back to a
/// pathname reopen that would reintroduce a time-of-check/time-of-use race.
pub struct ReadOnlyRedbStore {
    #[cfg(target_os = "linux")]
    database: ReadOnlyDatabase,
    #[cfg(target_os = "linux")]
    _pinned_file: fs::File,
}

#[derive(Default)]
pub struct MemoryStore {
    records: RwLock<BTreeMap<String, Vec<u8>>>,
}

impl RedbStore {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        #[cfg(unix)]
        let database = {
            let file = open_database_file(path, DatabaseFileMode::Create)?;
            Database::builder().create_file(file).map_err(backend)?
        };
        #[cfg(not(unix))]
        let database = Database::create(path).map_err(backend)?;
        let transaction = database.begin_write().map_err(backend)?;
        transaction.open_table(RECORDS).map_err(backend)?;
        transaction.commit().map_err(backend)?;
        Ok(Self { database })
    }

    /// Open an initialized database without creating the file or its records
    /// table. Existing Unix files must already have exact private mode 0600.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        #[cfg(unix)]
        let database = {
            let file = open_database_file(path, DatabaseFileMode::ExistingReadWrite)?;
            // `create_file` is the only public redb API that consumes an
            // already descriptor-pinned File. Empty existing files were
            // rejected above, and the read-only table check below prevents it
            // from initializing a missing application table.
            Database::builder().create_file(file).map_err(backend)?
        };
        #[cfg(not(unix))]
        let database = Database::open(path).map_err(backend)?;
        verify_records_table(&database)?;
        Ok(Self { database })
    }
}

impl ReadOnlyRedbStore {
    /// Open an initialized database as an offline, immutable view.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        #[cfg(target_os = "linux")]
        {
            let pinned_file =
                open_database_file(path.as_ref(), DatabaseFileMode::ExistingReadOnly)?;
            let descriptor_path = format!("/proc/self/fd/{}", pinned_file.as_raw_fd());
            let mut builder = Database::builder();
            // Status-style reads do not need redb's large default cache.
            builder.set_cache_size(16 * 1024 * 1024);
            let database = builder.open_read_only(descriptor_path).map_err(backend)?;
            verify_records_table(&database)?;
            Ok(Self {
                database,
                _pinned_file: pinned_file,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(backend(
                "secure descriptor-pinned read-only redb open is unsupported on this platform",
            ))
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DatabaseFileMode {
    Create,
    ExistingReadWrite,
    ExistingReadOnly,
}

#[cfg(unix)]
fn open_database_file(path: &Path, mode: DatabaseFileMode) -> Result<fs::File, StorageError> {
    let (absolute, components) = secure_path_components(path)?;
    let (leaf, ancestor_names) = components
        .split_last()
        .ok_or_else(|| backend("durable database path must name a file"))?;
    let base = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let base_descriptor = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base)
        .map_err(|error| backend(format!("failed to descriptor-pin path base: {error}")))?;
    validate_ancestor_descriptor(&base_descriptor, &base.display().to_string())?;

    // Keep every descriptor alive until the leaf has been opened and the
    // complete chain revalidated. Renames therefore cannot redirect a later
    // lookup to a different directory.
    let mut ancestors = vec![base_descriptor];
    for name in ancestor_names {
        let parent = ancestors
            .last()
            .expect("the descriptor-pinned path always retains its base");
        let descriptor = openat_directory(parent, name).map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                backend("refusing a symbolic-link durable database ancestor")
            } else {
                backend(format!(
                    "failed to descriptor-pin durable database ancestor: {error}"
                ))
            }
        })?;
        validate_ancestor_descriptor(&descriptor, &name.to_string_lossy())?;
        ancestors.push(descriptor);
    }

    let parent = ancestors
        .last()
        .expect("the descriptor-pinned path always retains its base");
    let file = openat_database_leaf(parent, leaf, mode).map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            backend("refusing a symbolic link as the durable database")
        } else {
            backend(format!("failed to open durable database leaf: {error}"))
        }
    })?;
    let opened = file.metadata().map_err(backend)?;
    if !opened.is_file() {
        return Err(backend("durable database is not a regular file"));
    }
    if mode != DatabaseFileMode::Create && opened.len() == 0 {
        return Err(backend("existing durable database is empty"));
    }
    if mode == DatabaseFileMode::Create {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(backend)?;
    }
    let hardened = file.metadata().map_err(backend)?;
    if hardened.permissions().mode() & 0o7777 != 0o600 {
        return Err(backend(if mode == DatabaseFileMode::Create {
            "durable database descriptor did not retain private permissions"
        } else {
            "existing durable database must have exact private mode 0600"
        }));
    }

    for (index, name) in ancestor_names.iter().enumerate() {
        verify_directory_entry_identity(&ancestors[index], name, &ancestors[index + 1])?;
    }
    verify_leaf_identity(parent, leaf, &hardened)?;
    Ok(file)
}

#[cfg(unix)]
fn secure_path_components(path: &Path) -> Result<(bool, Vec<CString>), StorageError> {
    let mut absolute = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(backend(
                    "durable database path must not contain a parent-directory component",
                ));
            }
            Component::Normal(name) => names.push(
                CString::new(name.as_bytes())
                    .map_err(|_| backend("durable database path contains a NUL byte"))?,
            ),
            Component::Prefix(_) => {
                return Err(backend(
                    "durable database path uses an unsupported path prefix",
                ));
            }
        }
    }
    Ok((absolute, names))
}

#[cfg(unix)]
fn validate_ancestor_descriptor(directory: &fs::File, component: &str) -> Result<(), StorageError> {
    let metadata = directory.metadata().map_err(backend)?;
    if !metadata.is_dir() {
        return Err(backend("durable database ancestor is not a directory"));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 && mode & libc::S_ISVTX == 0 {
        return Err(backend(format!(
            "durable database ancestor {component:?} is group/world-writable without the sticky bit (mode {:o})",
            mode & 0o7777
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn openat_directory(parent: &fs::File, name: &CStr) -> io::Result<fs::File> {
    openat_owned(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        None,
    )
}

#[cfg(unix)]
fn openat_database_leaf(
    parent: &fs::File,
    name: &CStr,
    mode: DatabaseFileMode,
) -> io::Result<fs::File> {
    let access = match mode {
        DatabaseFileMode::Create | DatabaseFileMode::ExistingReadWrite => libc::O_RDWR,
        DatabaseFileMode::ExistingReadOnly => libc::O_RDONLY,
    };
    let create = if mode == DatabaseFileMode::Create {
        libc::O_CREAT
    } else {
        0
    };
    openat_owned(
        parent,
        name,
        access | create | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
        (mode == DatabaseFileMode::Create).then_some(0o600),
    )
}

#[cfg(unix)]
fn openat_owned(
    parent: &fs::File,
    name: &CStr,
    flags: libc::c_int,
    mode: Option<libc::mode_t>,
) -> io::Result<fs::File> {
    // SAFETY: `parent` and `name` remain live for the call, and `name` is NUL
    // terminated. A successful raw descriptor is immediately transferred to
    // `OwnedFd`, so every return path closes it exactly once.
    let descriptor = unsafe {
        match mode {
            Some(mode) => libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode),
            None => libc::openat(parent.as_raw_fd(), name.as_ptr(), flags),
        }
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new, owned descriptor and ownership has not
    // been transferred anywhere else.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    Ok(fs::File::from(descriptor))
}

#[cfg(unix)]
fn verify_directory_entry_identity(
    parent: &fs::File,
    name: &CStr,
    opened: &fs::File,
) -> Result<(), StorageError> {
    let metadata = opened.metadata().map_err(backend)?;
    verify_entry_identity(
        parent,
        name,
        &metadata,
        libc::S_IFDIR,
        "durable database ancestor changed during descriptor traversal",
    )
}

#[cfg(unix)]
fn verify_leaf_identity(
    parent: &fs::File,
    name: &CStr,
    opened: &fs::Metadata,
) -> Result<(), StorageError> {
    verify_entry_identity(
        parent,
        name,
        opened,
        libc::S_IFREG,
        "durable database leaf changed during descriptor open",
    )
}

#[cfg(unix)]
fn verify_entry_identity(
    parent: &fs::File,
    name: &CStr,
    opened: &fs::Metadata,
    expected_type: libc::mode_t,
    changed_message: &str,
) -> Result<(), StorageError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to writable storage for one `libc::stat`, while the
    // directory descriptor and NUL-terminated component remain live.
    let status = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(backend(format!(
            "{changed_message}: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: a zero `fstatat` result initialized the complete structure.
    let stat = unsafe { stat.assume_init() };
    let entry_dev = identity_to_u64(stat.st_dev)?;
    let entry_ino = identity_to_u64(stat.st_ino)?;
    if stat.st_mode & libc::S_IFMT != expected_type
        || entry_dev != opened.dev()
        || entry_ino != opened.ino()
    {
        return Err(backend(changed_message));
    }
    Ok(())
}

#[cfg(unix)]
fn identity_to_u64<T>(identity: T) -> Result<u64, StorageError>
where
    T: TryInto<u64>,
{
    identity
        .try_into()
        .map_err(|_| backend("durable database entry has an invalid filesystem identity"))
}

fn verify_records_table(database: &dyn ReadableDatabase) -> Result<(), StorageError> {
    let transaction = database.begin_read().map_err(backend)?;
    {
        let _table = transaction.open_table(RECORDS).map_err(backend)?;
    }
    Ok(())
}

fn redb_get(
    database: &dyn ReadableDatabase,
    namespace: &str,
    key: &str,
) -> Result<Option<Vec<u8>>, StorageError> {
    let key = storage_key(namespace, key)?;
    let transaction = database.begin_read().map_err(backend)?;
    let table = transaction.open_table(RECORDS).map_err(backend)?;
    Ok(table
        .get(key.as_str())
        .map_err(backend)?
        .map(|value| value.value().to_vec()))
}

fn redb_scan_namespace(
    database: &dyn ReadableDatabase,
    namespace: &str,
    limits: ScanLimits,
) -> Result<Vec<NamespaceRecord>, StorageError> {
    let prefix = storage_key(namespace, "")?;
    let upper = namespace_upper(namespace)?;
    let transaction = database.begin_read().map_err(backend)?;
    let table = transaction.open_table(RECORDS).map_err(backend)?;
    let mut records = Vec::new();
    let mut total_bytes = 0u64;
    for entry in table
        .range(prefix.as_str()..upper.as_str())
        .map_err(backend)?
    {
        let (key, value) = entry.map_err(backend)?;
        let Some(logical_key) = key.value().strip_prefix(&prefix) else {
            continue;
        };
        append_scanned_record(
            &mut records,
            &mut total_bytes,
            logical_key,
            value.value(),
            limits,
        )?;
    }
    Ok(records)
}

fn redb_scan_namespace_after(
    database: &dyn ReadableDatabase,
    namespace: &str,
    exclusive_cursor: Option<&str>,
    limits: ScanLimits,
) -> Result<NamespacePage, StorageError> {
    let prefix = storage_key(namespace, "")?;
    let lower = match exclusive_cursor {
        Some(cursor) => storage_key(namespace, cursor)?,
        None => prefix.clone(),
    };
    let upper = namespace_upper(namespace)?;
    let lower_bound = if exclusive_cursor.is_some() {
        Excluded(lower.as_str())
    } else {
        Included(lower.as_str())
    };
    let transaction = database.begin_read().map_err(backend)?;
    let table = transaction.open_table(RECORDS).map_err(backend)?;
    let mut records = Vec::new();
    let mut total_bytes = 0u64;
    let mut has_more = false;
    for entry in table
        .range::<&str>((lower_bound, Excluded(upper.as_str())))
        .map_err(backend)?
    {
        let (key, value) = entry.map_err(backend)?;
        let Some(logical_key) = key.value().strip_prefix(&prefix) else {
            continue;
        };
        if !append_page_record(
            &mut records,
            &mut total_bytes,
            logical_key,
            value.value(),
            limits,
        )? {
            if records.is_empty() {
                return Err(StorageError::ScanLimit);
            }
            has_more = true;
            break;
        }
    }
    Ok(NamespacePage { records, has_more })
}

impl DurableStore for RedbStore {
    fn put(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let key = storage_key(namespace, key)?;
        let transaction = self.database.begin_write().map_err(backend)?;
        {
            let mut table = transaction.open_table(RECORDS).map_err(backend)?;
            table.insert(key.as_str(), value).map_err(backend)?;
        }
        transaction.commit().map_err(backend)
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        redb_get(&self.database, namespace, key)
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        let key = storage_key(namespace, key)?;
        let transaction = self.database.begin_write().map_err(backend)?;
        {
            let mut table = transaction.open_table(RECORDS).map_err(backend)?;
            table.remove(key.as_str()).map_err(backend)?;
        }
        transaction.commit().map_err(backend)
    }

    fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        value: &[u8],
    ) -> Result<bool, StorageError> {
        let key = storage_key(namespace, key)?;
        let transaction = self.database.begin_write().map_err(backend)?;
        let matched = {
            let mut table = transaction.open_table(RECORDS).map_err(backend)?;
            let current = table
                .get(key.as_str())
                .map_err(backend)?
                .map(|bytes| bytes.value().to_vec());
            if current.as_deref() != expected {
                false
            } else {
                table.insert(key.as_str(), value).map_err(backend)?;
                true
            }
        };
        if matched {
            transaction.commit().map_err(backend)?;
        }
        Ok(matched)
    }

    fn apply_batch(&self, operations: &[BatchOperation]) -> Result<(), StorageError> {
        let keys = operations
            .iter()
            .map(|operation| match operation {
                BatchOperation::Put { namespace, key, .. }
                | BatchOperation::Delete { namespace, key } => storage_key(namespace, key),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transaction = self.database.begin_write().map_err(backend)?;
        {
            let mut table = transaction.open_table(RECORDS).map_err(backend)?;
            for (operation, key) in operations.iter().zip(keys) {
                match operation {
                    BatchOperation::Put { value, .. } => {
                        table
                            .insert(key.as_str(), value.as_slice())
                            .map_err(backend)?;
                    }
                    BatchOperation::Delete { .. } => {
                        table.remove(key.as_str()).map_err(backend)?;
                    }
                }
            }
        }
        transaction.commit().map_err(backend)
    }

    fn apply_batch_if(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        operations: &[BatchOperation],
    ) -> Result<bool, StorageError> {
        self.apply_batch_if_all(
            &[BatchCondition::new(
                namespace,
                key,
                expected.map(<[u8]>::to_vec),
            )],
            operations,
        )
    }

    fn apply_batch_if_all(
        &self,
        conditions: &[BatchCondition],
        operations: &[BatchOperation],
    ) -> Result<bool, StorageError> {
        let condition_keys = conditions
            .iter()
            .map(|condition| storage_key(&condition.namespace, &condition.key))
            .collect::<Result<Vec<_>, _>>()?;
        let operation_keys = operations
            .iter()
            .map(|operation| match operation {
                BatchOperation::Put { namespace, key, .. }
                | BatchOperation::Delete { namespace, key } => storage_key(namespace, key),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transaction = self.database.begin_write().map_err(backend)?;
        let matched = {
            let mut table = transaction.open_table(RECORDS).map_err(backend)?;
            let mut matched = true;
            for (condition, key) in conditions.iter().zip(condition_keys) {
                let current = table
                    .get(key.as_str())
                    .map_err(backend)?
                    .map(|bytes| bytes.value().to_vec());
                if current.as_deref() != condition.expected.as_deref() {
                    matched = false;
                    break;
                }
            }
            if matched {
                for (operation, key) in operations.iter().zip(operation_keys) {
                    match operation {
                        BatchOperation::Put { value, .. } => {
                            table
                                .insert(key.as_str(), value.as_slice())
                                .map_err(backend)?;
                        }
                        BatchOperation::Delete { .. } => {
                            table.remove(key.as_str()).map_err(backend)?;
                        }
                    }
                }
            }
            matched
        };
        if matched {
            transaction.commit().map_err(backend)?;
        }
        Ok(matched)
    }

    fn scan_namespace(
        &self,
        namespace: &str,
        limits: ScanLimits,
    ) -> Result<Vec<NamespaceRecord>, StorageError> {
        redb_scan_namespace(&self.database, namespace, limits)
    }

    fn scan_namespace_after(
        &self,
        namespace: &str,
        exclusive_cursor: Option<&str>,
        limits: ScanLimits,
    ) -> Result<NamespacePage, StorageError> {
        redb_scan_namespace_after(&self.database, namespace, exclusive_cursor, limits)
    }
}

impl DurableStore for ReadOnlyRedbStore {
    fn put(&self, _namespace: &str, _key: &str, _value: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::ReadOnly)
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        #[cfg(target_os = "linux")]
        {
            redb_get(&self.database, namespace, key)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (namespace, key);
            Err(backend(
                "secure descriptor-pinned read-only redb open is unsupported on this platform",
            ))
        }
    }

    fn delete(&self, _namespace: &str, _key: &str) -> Result<(), StorageError> {
        Err(StorageError::ReadOnly)
    }

    fn compare_and_swap(
        &self,
        _namespace: &str,
        _key: &str,
        _expected: Option<&[u8]>,
        _value: &[u8],
    ) -> Result<bool, StorageError> {
        Err(StorageError::ReadOnly)
    }

    fn apply_batch(&self, _operations: &[BatchOperation]) -> Result<(), StorageError> {
        Err(StorageError::ReadOnly)
    }

    fn apply_batch_if(
        &self,
        _namespace: &str,
        _key: &str,
        _expected: Option<&[u8]>,
        _operations: &[BatchOperation],
    ) -> Result<bool, StorageError> {
        Err(StorageError::ReadOnly)
    }

    fn apply_batch_if_all(
        &self,
        _conditions: &[BatchCondition],
        _operations: &[BatchOperation],
    ) -> Result<bool, StorageError> {
        Err(StorageError::ReadOnly)
    }

    fn scan_namespace(
        &self,
        namespace: &str,
        limits: ScanLimits,
    ) -> Result<Vec<NamespaceRecord>, StorageError> {
        #[cfg(target_os = "linux")]
        {
            redb_scan_namespace(&self.database, namespace, limits)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (namespace, limits);
            Err(backend(
                "secure descriptor-pinned read-only redb open is unsupported on this platform",
            ))
        }
    }

    fn scan_namespace_after(
        &self,
        namespace: &str,
        exclusive_cursor: Option<&str>,
        limits: ScanLimits,
    ) -> Result<NamespacePage, StorageError> {
        #[cfg(target_os = "linux")]
        {
            redb_scan_namespace_after(&self.database, namespace, exclusive_cursor, limits)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (namespace, exclusive_cursor, limits);
            Err(backend(
                "secure descriptor-pinned read-only redb open is unsupported on this platform",
            ))
        }
    }
}

impl DurableStore for MemoryStore {
    fn put(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let key = storage_key(namespace, key)?;
        self.records
            .write()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?
            .insert(key, value.to_vec());
        Ok(())
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let key = storage_key(namespace, key)?;
        Ok(self
            .records
            .read()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?
            .get(&key)
            .cloned())
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        let key = storage_key(namespace, key)?;
        self.records
            .write()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?
            .remove(&key);
        Ok(())
    }

    fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        value: &[u8],
    ) -> Result<bool, StorageError> {
        let key = storage_key(namespace, key)?;
        let mut records = self
            .records
            .write()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?;
        if records.get(&key).map(Vec::as_slice) != expected {
            return Ok(false);
        }
        records.insert(key, value.to_vec());
        Ok(true)
    }

    fn apply_batch(&self, operations: &[BatchOperation]) -> Result<(), StorageError> {
        let keys = operations
            .iter()
            .map(|operation| match operation {
                BatchOperation::Put { namespace, key, .. }
                | BatchOperation::Delete { namespace, key } => storage_key(namespace, key),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut records = self
            .records
            .write()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?;
        for (operation, key) in operations.iter().zip(keys) {
            match operation {
                BatchOperation::Put { value, .. } => {
                    records.insert(key, value.clone());
                }
                BatchOperation::Delete { .. } => {
                    records.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn apply_batch_if(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        operations: &[BatchOperation],
    ) -> Result<bool, StorageError> {
        self.apply_batch_if_all(
            &[BatchCondition::new(
                namespace,
                key,
                expected.map(<[u8]>::to_vec),
            )],
            operations,
        )
    }

    fn apply_batch_if_all(
        &self,
        conditions: &[BatchCondition],
        operations: &[BatchOperation],
    ) -> Result<bool, StorageError> {
        let condition_keys = conditions
            .iter()
            .map(|condition| storage_key(&condition.namespace, &condition.key))
            .collect::<Result<Vec<_>, _>>()?;
        let operation_keys = operations
            .iter()
            .map(|operation| match operation {
                BatchOperation::Put { namespace, key, .. }
                | BatchOperation::Delete { namespace, key } => storage_key(namespace, key),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut records = self
            .records
            .write()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?;
        for (condition, key) in conditions.iter().zip(condition_keys) {
            if records.get(&key).map(Vec::as_slice) != condition.expected.as_deref() {
                return Ok(false);
            }
        }
        for (operation, key) in operations.iter().zip(operation_keys) {
            match operation {
                BatchOperation::Put { value, .. } => {
                    records.insert(key, value.clone());
                }
                BatchOperation::Delete { .. } => {
                    records.remove(&key);
                }
            }
        }
        Ok(true)
    }

    fn scan_namespace(
        &self,
        namespace: &str,
        limits: ScanLimits,
    ) -> Result<Vec<NamespaceRecord>, StorageError> {
        let prefix = storage_key(namespace, "")?;
        let upper = namespace_upper(namespace)?;
        let stored = self
            .records
            .read()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?;
        let mut records = Vec::new();
        let mut total_bytes = 0u64;
        for (key, value) in stored.range(prefix.clone()..upper) {
            let Some(logical_key) = key.strip_prefix(&prefix) else {
                continue;
            };
            append_scanned_record(&mut records, &mut total_bytes, logical_key, value, limits)?;
        }
        Ok(records)
    }

    fn scan_namespace_after(
        &self,
        namespace: &str,
        exclusive_cursor: Option<&str>,
        limits: ScanLimits,
    ) -> Result<NamespacePage, StorageError> {
        let prefix = storage_key(namespace, "")?;
        let lower = match exclusive_cursor {
            Some(cursor) => storage_key(namespace, cursor)?,
            None => prefix.clone(),
        };
        let upper = namespace_upper(namespace)?;
        let lower_bound = if exclusive_cursor.is_some() {
            Excluded(lower)
        } else {
            Included(lower)
        };
        let stored = self
            .records
            .read()
            .map_err(|_| StorageError::Backend("memory store lock poisoned".to_owned()))?;
        let mut records = Vec::new();
        let mut total_bytes = 0u64;
        let mut has_more = false;
        for (key, value) in stored.range((lower_bound, Excluded(upper))) {
            let Some(logical_key) = key.strip_prefix(&prefix) else {
                continue;
            };
            if !append_page_record(&mut records, &mut total_bytes, logical_key, value, limits)? {
                if records.is_empty() {
                    return Err(StorageError::ScanLimit);
                }
                has_more = true;
                break;
            }
        }
        Ok(NamespacePage { records, has_more })
    }
}

/// Every durable MM-0001 record category from section 17.1. Values are
/// immutable under their content/sequence key; canonical-chain rollback is
/// represented by appending a new `CanonicalPlanPayment` record, never by
/// rewriting historical evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolRecordKind {
    OperatorSequence,
    PayoutBucket,
    BodyPackage,
    BodyValidation,
    ErasureDescriptor,
    BodyShard,
    ParentCertificate,
    MaskSession,
    MpcTranscript,
    OpeningShare,
    Assignment,
    GatewayAssignment,
    GatewayContextManifest,
    GatewayCaptureEnvelope,
    GatewayCaptureReceipt,
    GatewayAssignmentTransition,
    GatewayAssignmentDrain,
    CoreAssignmentDrainReceipt,
    AcceptedShare,
    AcceptedWorkKey,
    ReceiptBatch,
    SessionClose,
    PayoutSnapshot,
    PayoutPlan,
    PayoutRecoveryCheckpoint,
    CanonicalPlanPayment,
}

impl ProtocolRecordKind {
    pub const ALL: [Self; 26] = [
        Self::OperatorSequence,
        Self::PayoutBucket,
        Self::BodyPackage,
        Self::BodyValidation,
        Self::ErasureDescriptor,
        Self::BodyShard,
        Self::ParentCertificate,
        Self::MaskSession,
        Self::MpcTranscript,
        Self::OpeningShare,
        Self::Assignment,
        Self::GatewayAssignment,
        Self::GatewayContextManifest,
        Self::GatewayCaptureEnvelope,
        Self::GatewayCaptureReceipt,
        Self::GatewayAssignmentTransition,
        Self::GatewayAssignmentDrain,
        Self::CoreAssignmentDrainReceipt,
        Self::AcceptedShare,
        Self::AcceptedWorkKey,
        Self::ReceiptBatch,
        Self::SessionClose,
        Self::PayoutSnapshot,
        Self::PayoutPlan,
        Self::PayoutRecoveryCheckpoint,
        Self::CanonicalPlanPayment,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::OperatorSequence => "operator-sequence",
            Self::PayoutBucket => "payout-bucket",
            Self::BodyPackage => "body-package",
            Self::BodyValidation => "body-validation",
            Self::ErasureDescriptor => "erasure-descriptor",
            Self::BodyShard => "body-shard",
            Self::ParentCertificate => "parent-certificate",
            Self::MaskSession => "mask-session",
            Self::MpcTranscript => "mpc-transcript",
            Self::OpeningShare => "opening-share",
            Self::Assignment => "assignment",
            Self::GatewayAssignment => "gateway-assignment",
            Self::GatewayContextManifest => "gateway-context-manifest",
            Self::GatewayCaptureEnvelope => "gateway-capture-envelope",
            Self::GatewayCaptureReceipt => "gateway-capture-receipt",
            Self::GatewayAssignmentTransition => "gateway-assignment-transition",
            Self::GatewayAssignmentDrain => "gateway-assignment-drain",
            Self::CoreAssignmentDrainReceipt => "core-assignment-drain-receipt",
            Self::AcceptedShare => "accepted-share",
            Self::AcceptedWorkKey => "accepted-work-key",
            Self::ReceiptBatch => "receipt-batch",
            Self::SessionClose => "session-close",
            Self::PayoutSnapshot => "payout-snapshot",
            Self::PayoutPlan => "payout-plan",
            Self::PayoutRecoveryCheckpoint => "payout-recovery-checkpoint",
            Self::CanonicalPlanPayment => "canonical-plan-payment",
        }
    }

    const fn namespace(self) -> &'static str {
        match self {
            Self::OperatorSequence => "journal/operator-sequence/v2",
            Self::PayoutBucket => "journal/payout-bucket/v2",
            Self::BodyPackage => "journal/body-package/v2",
            Self::BodyValidation => "journal/body-validation/v2",
            Self::ErasureDescriptor => "journal/erasure-descriptor/v2",
            Self::BodyShard => "journal/body-shard/v2",
            Self::ParentCertificate => "journal/parent-certificate/v2",
            Self::MaskSession => "journal/mask-session/v2",
            Self::MpcTranscript => "journal/mpc-transcript/v2",
            Self::OpeningShare => "journal/opening-share/v2",
            Self::Assignment => "journal/assignment/v2",
            Self::GatewayAssignment => "journal/gateway-assignment/v1",
            Self::GatewayContextManifest => "journal/gateway-context-manifest/v1",
            Self::GatewayCaptureEnvelope => "journal/gateway-capture-envelope/v1",
            Self::GatewayCaptureReceipt => "journal/gateway-capture-receipt/v1",
            Self::GatewayAssignmentTransition => "journal/gateway-assignment-transition/v1",
            Self::GatewayAssignmentDrain => "journal/gateway-assignment-drain/v1",
            Self::CoreAssignmentDrainReceipt => "journal/core-assignment-drain-receipt/v1",
            Self::AcceptedShare => "journal/accepted-share/v2",
            Self::AcceptedWorkKey => "journal/accepted-work-key/v2",
            Self::ReceiptBatch => "journal/receipt-batch/v2",
            Self::SessionClose => "journal/session-close/v2",
            Self::PayoutSnapshot => "journal/payout-snapshot/v2",
            Self::PayoutPlan => "journal/payout-plan/v2",
            Self::PayoutRecoveryCheckpoint => "journal/payout-recovery-checkpoint/v1",
            Self::CanonicalPlanPayment => "journal/canonical-plan-payment/v2",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DurableInvariantError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("a durable protocol key was reused with different bytes")]
    ImmutableConflict,
    #[error("a supplemental condition or operation targets the immutable journal record")]
    SupplementalJournalTarget,
    #[error("an immutable journal batch must contain at least one record")]
    EmptyJournalBatch,
    #[error("an immutable journal batch contains the same durable key more than once")]
    DuplicateJournalKey,
    #[error("signer already authorized a different object for this role/scope/sequence")]
    ConflictingSignature,
    #[error("durable protocol recovery encountered a malformed journal key")]
    InvalidRecoveryKey,
    #[error("durable protocol recovery encountered an invalid page boundary")]
    InvalidRecoveryPage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredProtocolRecord {
    pub kind: ProtocolRecordKind,
    pub durable_key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolRecovery {
    pub records: Vec<RecoveredProtocolRecord>,
    /// Value bytes returned to protocol recovery code.
    pub total_value_bytes: u64,
    /// Canonical encoded journal-key bytes plus value bytes. This is the exact
    /// total charged against [`ScanLimits::maximum_total_bytes`].
    pub total_scan_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolRecoveryPage {
    /// Records and byte totals for this page only.
    pub recovery: ProtocolRecovery,
    /// When present, pass these decoded durable-key bytes as the next call's
    /// exclusive cursor. `None` is the terminal page.
    pub next_cursor: Option<Vec<u8>>,
}

/// One owned immutable protocol record in an atomic journal batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalBatchRecord {
    pub kind: ProtocolRecordKind,
    pub durable_key: Vec<u8>,
    pub value: Vec<u8>,
}

impl JournalBatchRecord {
    pub fn new(
        kind: ProtocolRecordKind,
        durable_key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            kind,
            durable_key: durable_key.into(),
            value: value.into(),
        }
    }
}

/// Result of an immutable journal write guarded by caller-supplied conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalBatchOutcome {
    /// The complete journal/derived batch was applied atomically. This also
    /// covers an exact retry whose supplemental operations were reapplied.
    Committed,
    /// Every requested journal record already contains the exact bytes, but
    /// one or more external conditions no longer match, so no supplemental
    /// operation was applied.
    ExactRecord,
    /// External conditions failed while at least one requested journal key
    /// remained absent.
    PreconditionMismatch,
}

pub struct ProtocolJournal<'a> {
    store: &'a dyn DurableStore,
}

impl<'a> ProtocolJournal<'a> {
    pub const fn new(store: &'a dyn DurableStore) -> Self {
        Self { store }
    }

    /// Persist before acknowledging the corresponding externally visible
    /// object. Repeating identical bytes is idempotent; rewriting a key is a
    /// protocol fault.
    pub fn persist(
        &self,
        kind: ProtocolRecordKind,
        durable_key: &[u8],
        value: &[u8],
    ) -> Result<(), DurableInvariantError> {
        self.persist_with_batch(kind, durable_key, value, &[])
    }

    /// Atomically persist one immutable protocol record and update derived
    /// durable indexes before the caller acknowledges the record.
    ///
    /// Supplemental operations must be deterministic and idempotent: an
    /// exact journal retry deliberately reapplies all of them to repair a
    /// missing or stale derived index after a crash. The immutable journal
    /// key itself cannot appear in the supplemental batch. A conflicting
    /// journal value rejects the complete batch, including under concurrent
    /// writers.
    pub fn persist_with_batch(
        &self,
        kind: ProtocolRecordKind,
        durable_key: &[u8],
        value: &[u8],
        supplemental_operations: &[BatchOperation],
    ) -> Result<(), DurableInvariantError> {
        match self.persist_with_conditions_and_batch(
            kind,
            durable_key,
            value,
            &[],
            supplemental_operations,
        )? {
            JournalBatchOutcome::Committed | JournalBatchOutcome::ExactRecord => Ok(()),
            JournalBatchOutcome::PreconditionMismatch => {
                Err(DurableInvariantError::ImmutableConflict)
            }
        }
    }

    /// Atomically persist one immutable journal record and its derived index
    /// mutations only when every caller condition matches the same pre-batch
    /// view. The journal's absent/exact condition is appended internally, so
    /// callers do not need access to its private namespace.
    ///
    /// An exact retry reapplies the supplemental operations when the external
    /// conditions still match. If they no longer match (for example, a
    /// session has since closed), [`JournalBatchOutcome::ExactRecord`] lets a
    /// caller distinguish the prior accepted record from a new attempt that
    /// failed its conditions. Conditions and operations must not target this
    /// journal key themselves.
    pub fn persist_with_conditions_and_batch(
        &self,
        kind: ProtocolRecordKind,
        durable_key: &[u8],
        value: &[u8],
        conditions: &[BatchCondition],
        supplemental_operations: &[BatchOperation],
    ) -> Result<JournalBatchOutcome, DurableInvariantError> {
        self.persist_records_with_conditions_and_batch(
            &[JournalBatchRecord::new(
                kind,
                durable_key.to_vec(),
                value.to_vec(),
            )],
            conditions,
            supplemental_operations,
        )
    }

    /// Atomically persist multiple immutable protocol records, external
    /// conditions, and derived-index operations in one durable transaction.
    ///
    /// Each requested journal key may be absent or already contain its exact
    /// requested bytes. Missing records are installed together; exact records
    /// make the operation an idempotent repair. Any different existing value
    /// rejects the complete transaction as an immutable conflict. Concurrent
    /// absent-to-exact transitions are retried only while they make monotonic
    /// progress, so supplemental operations are never detached from their
    /// journal evidence.
    ///
    /// Supplemental operations may not target any protocol-journal namespace,
    /// and external conditions may not duplicate a requested journal key.
    pub fn persist_records_with_conditions_and_batch(
        &self,
        records: &[JournalBatchRecord],
        conditions: &[BatchCondition],
        supplemental_operations: &[BatchOperation],
    ) -> Result<JournalBatchOutcome, DurableInvariantError> {
        if records.is_empty() {
            return Err(DurableInvariantError::EmptyJournalBatch);
        }

        let mut prepared = Vec::with_capacity(records.len());
        for record in records {
            let namespace = record.kind.namespace();
            let key = hex::encode(&record.durable_key);
            if prepared
                .iter()
                .any(|(existing_namespace, existing_key, _)| {
                    *existing_namespace == namespace && existing_key == &key
                })
            {
                return Err(DurableInvariantError::DuplicateJournalKey);
            }
            prepared.push((namespace, key, record.value.as_slice()));
        }

        let targets_requested_record = |namespace: &str, key: &str| {
            prepared.iter().any(|(record_namespace, record_key, _)| {
                *record_namespace == namespace && record_key == key
            })
        };
        if conditions
            .iter()
            .any(|condition| targets_requested_record(&condition.namespace, &condition.key))
            || supplemental_operations.iter().any(|operation| {
                let namespace = match operation {
                    BatchOperation::Put { namespace, .. }
                    | BatchOperation::Delete { namespace, .. } => namespace,
                };
                ProtocolRecordKind::ALL
                    .into_iter()
                    .any(|kind| kind.namespace() == namespace)
            })
        {
            return Err(DurableInvariantError::SupplementalJournalTarget);
        }

        let mut operations = Vec::new();
        for (namespace, key, record_value) in &prepared {
            operations.push(BatchOperation::put(*namespace, key, record_value.to_vec()));
        }
        operations.extend_from_slice(supplemental_operations);

        let inspect = || -> Result<Vec<bool>, DurableInvariantError> {
            let mut exact = Vec::with_capacity(prepared.len());
            for (namespace, key, expected_value) in &prepared {
                match self.store.get(namespace, key)? {
                    None => exact.push(false),
                    Some(existing) if existing == *expected_value => exact.push(true),
                    Some(_) => return Err(DurableInvariantError::ImmutableConflict),
                }
            }
            Ok(exact)
        };

        // Under immutable journal discipline every failed attempt followed by
        // a changed state adds at least one exact record. There can therefore
        // be at most `records.len()` such transitions before a stable result.
        for _ in 0..=records.len() {
            let observed = inspect()?;
            let mut attempt_conditions = conditions.to_vec();
            for ((namespace, key, expected_value), is_exact) in prepared.iter().zip(&observed) {
                attempt_conditions.push(if *is_exact {
                    BatchCondition::equals(*namespace, key, expected_value.to_vec())
                } else {
                    BatchCondition::absent(*namespace, key)
                });
            }
            if self
                .store
                .apply_batch_if_all(&attempt_conditions, &operations)?
            {
                return Ok(JournalBatchOutcome::Committed);
            }

            let after = inspect()?;
            if after == observed {
                return if after.into_iter().all(|is_exact| is_exact) {
                    Ok(JournalBatchOutcome::ExactRecord)
                } else {
                    Ok(JournalBatchOutcome::PreconditionMismatch)
                };
            }
            if observed
                .iter()
                .zip(&after)
                .any(|(was_exact, is_exact)| *was_exact && !is_exact)
            {
                return Err(DurableInvariantError::ImmutableConflict);
            }
        }

        Err(
            StorageError::Backend("immutable journal conditions did not stabilize".to_owned())
                .into(),
        )
    }

    pub fn load(
        &self,
        kind: ProtocolRecordKind,
        durable_key: &[u8],
    ) -> Result<Option<Vec<u8>>, DurableInvariantError> {
        Ok(self
            .store
            .get(kind.namespace(), &hex::encode(durable_key))?)
    }

    /// Bounded, deterministic replay inventory for one normative §17.1
    /// journal category. Keys are decoded back to their original bytes and a
    /// malformed or noncanonical hex key fails recovery.
    pub fn recover_kind(
        &self,
        kind: ProtocolRecordKind,
        limits: ScanLimits,
    ) -> Result<ProtocolRecovery, DurableInvariantError> {
        let scanned = self.store.scan_namespace(kind.namespace(), limits)?;
        decode_protocol_records(kind, scanned)
    }

    /// Recover one bounded page for a single journal category.
    ///
    /// `exclusive_cursor` and `next_cursor` are decoded durable-key bytes;
    /// journal hex encoding remains internal. A returned `next_cursor` is
    /// always the final record in this nonempty page and indicates that a
    /// greater key existed. `None` is terminal, including for an empty page.
    ///
    /// Pages are deterministic only over a stable backend view. Callers must
    /// quiesce journal writers during recovery or pin an external high-water
    /// mark, because separate calls do not share one database snapshot and an
    /// insertion at or before an earlier cursor would otherwise be missed.
    pub fn recover_kind_page(
        &self,
        kind: ProtocolRecordKind,
        exclusive_cursor: Option<&[u8]>,
        limits: ScanLimits,
    ) -> Result<ProtocolRecoveryPage, DurableInvariantError> {
        let encoded_cursor = exclusive_cursor.map(hex::encode);
        let page =
            self.store
                .scan_namespace_after(kind.namespace(), encoded_cursor.as_deref(), limits)?;
        if page.has_more && page.records.is_empty() {
            return Err(DurableInvariantError::InvalidRecoveryPage);
        }
        if encoded_cursor.as_deref().is_some_and(|cursor| {
            page.records
                .first()
                .is_some_and(|record| record.key.as_str() <= cursor)
        }) {
            return Err(DurableInvariantError::InvalidRecoveryPage);
        }
        let recovery = decode_protocol_records(kind, page.records)?;
        let next_cursor = if page.has_more {
            Some(
                recovery
                    .records
                    .last()
                    .ok_or(DurableInvariantError::InvalidRecoveryPage)?
                    .durable_key
                    .clone(),
            )
        } else {
            None
        };
        Ok(ProtocolRecoveryPage {
            recovery,
            next_cursor,
        })
    }

    /// Bounded, deterministic replay inventory across every normative §17.1
    /// journal category. Keys are decoded back to their original bytes and a
    /// malformed/noncanonical key fails the complete recovery.
    pub fn recover_all(
        &self,
        limits: ScanLimits,
    ) -> Result<ProtocolRecovery, DurableInvariantError> {
        let mut records = Vec::new();
        let mut total_value_bytes = 0u64;
        let mut total_scan_bytes = 0u64;
        for kind in ProtocolRecordKind::ALL {
            let remaining_records = limits
                .maximum_records
                .checked_sub(records.len())
                .ok_or(StorageError::ScanLimit)?;
            let remaining_bytes = limits
                .maximum_total_bytes
                .checked_sub(total_scan_bytes)
                .ok_or(StorageError::ScanLimit)?;
            let recovered = self.recover_kind(
                kind,
                ScanLimits {
                    maximum_records: remaining_records,
                    maximum_value_bytes: limits.maximum_value_bytes,
                    maximum_total_bytes: remaining_bytes,
                },
            )?;
            total_scan_bytes = total_scan_bytes
                .checked_add(recovered.total_scan_bytes)
                .ok_or(StorageError::ScanLimit)?;
            total_value_bytes = total_value_bytes
                .checked_add(recovered.total_value_bytes)
                .ok_or(StorageError::ScanLimit)?;
            records.extend(recovered.records);
        }
        Ok(ProtocolRecovery {
            records,
            total_value_bytes,
            total_scan_bytes,
        })
    }
}

fn decode_protocol_records(
    kind: ProtocolRecordKind,
    scanned: Vec<NamespaceRecord>,
) -> Result<ProtocolRecovery, DurableInvariantError> {
    let mut records = Vec::with_capacity(scanned.len());
    let mut previous_key: Option<String> = None;
    let mut total_value_bytes = 0u64;
    let mut total_scan_bytes = 0u64;
    for record in scanned {
        if previous_key
            .as_deref()
            .is_some_and(|previous| previous >= record.key.as_str())
        {
            return Err(DurableInvariantError::InvalidRecoveryPage);
        }
        let durable_key =
            hex::decode(&record.key).map_err(|_| DurableInvariantError::InvalidRecoveryKey)?;
        if hex::encode(&durable_key) != record.key {
            return Err(DurableInvariantError::InvalidRecoveryKey);
        }
        let key_bytes = u64::try_from(record.key.len()).map_err(|_| StorageError::ScanLimit)?;
        let value_bytes = u64::try_from(record.value.len()).map_err(|_| StorageError::ScanLimit)?;
        total_scan_bytes = total_scan_bytes
            .checked_add(key_bytes)
            .and_then(|total| total.checked_add(value_bytes))
            .ok_or(StorageError::ScanLimit)?;
        total_value_bytes = total_value_bytes
            .checked_add(value_bytes)
            .ok_or(StorageError::ScanLimit)?;
        previous_key = Some(record.key);
        records.push(RecoveredProtocolRecord {
            kind,
            durable_key,
            value: record.value,
        });
    }
    Ok(ProtocolRecovery {
        records,
        total_value_bytes,
        total_scan_bytes,
    })
}

pub struct DurableSignGuard<'a> {
    store: &'a dyn DurableStore,
}

impl<'a> DurableSignGuard<'a> {
    pub const fn new(store: &'a dyn DurableStore) -> Self {
        Self { store }
    }

    /// Reserve exactly one object ID for a signer role, context, and sequence.
    /// The same reservation is idempotent after a crash; a different object is
    /// rejected before signature bytes are created.
    pub fn authorize(
        &self,
        role: &str,
        scope: &[u8],
        sequence: u64,
        object_id: &[u8; 32],
    ) -> Result<(), DurableInvariantError> {
        if role.contains('\0') {
            return Err(StorageError::InvalidKey.into());
        }
        let key = format!("{role}/{}/{sequence}", hex::encode(scope));
        if self.store.put_if_absent("sign-guard/v2", &key, object_id)? {
            return Ok(());
        }
        match self.store.get("sign-guard/v2", &key)? {
            Some(existing) if existing.as_slice() == object_id => Ok(()),
            _ => Err(DurableInvariantError::ConflictingSignature),
        }
    }
}

fn storage_key(namespace: &str, key: &str) -> Result<String, StorageError> {
    if namespace.contains('\0') || key.contains('\0') {
        return Err(StorageError::InvalidKey);
    }
    Ok(format!("{namespace}\0{key}"))
}

fn namespace_upper(namespace: &str) -> Result<String, StorageError> {
    if namespace.contains('\0') {
        return Err(StorageError::InvalidKey);
    }
    Ok(format!("{namespace}\u{1}"))
}

fn append_scanned_record(
    records: &mut Vec<NamespaceRecord>,
    total_bytes: &mut u64,
    key: &str,
    value: &[u8],
    limits: ScanLimits,
) -> Result<(), StorageError> {
    let value_bytes = u64::try_from(value.len()).map_err(|_| StorageError::ScanLimit)?;
    let record_bytes = u64::try_from(key.len())
        .ok()
        .and_then(|key_bytes| key_bytes.checked_add(value_bytes))
        .ok_or(StorageError::ScanLimit)?;
    let next_total = total_bytes
        .checked_add(record_bytes)
        .ok_or(StorageError::ScanLimit)?;
    if records.len() >= limits.maximum_records
        || value_bytes > limits.maximum_value_bytes
        || next_total > limits.maximum_total_bytes
    {
        return Err(StorageError::ScanLimit);
    }
    records.push(NamespaceRecord {
        key: key.to_owned(),
        value: value.to_vec(),
    });
    *total_bytes = next_total;
    Ok(())
}

/// Append one page record, returning `false` when the record fits an empty
/// page but not the remaining record/aggregate budget. An individually
/// inadmissible record is an error so a caller cannot loop forever at one
/// cursor.
fn append_page_record(
    records: &mut Vec<NamespaceRecord>,
    total_bytes: &mut u64,
    key: &str,
    value: &[u8],
    limits: ScanLimits,
) -> Result<bool, StorageError> {
    let value_bytes = u64::try_from(value.len()).map_err(|_| StorageError::ScanLimit)?;
    let record_bytes = u64::try_from(key.len())
        .ok()
        .and_then(|key_bytes| key_bytes.checked_add(value_bytes))
        .ok_or(StorageError::ScanLimit)?;
    if value_bytes > limits.maximum_value_bytes || record_bytes > limits.maximum_total_bytes {
        return Err(StorageError::ScanLimit);
    }
    let next_total = total_bytes
        .checked_add(record_bytes)
        .ok_or(StorageError::ScanLimit)?;
    if records.len() >= limits.maximum_records || next_total > limits.maximum_total_bytes {
        return Ok(false);
    }
    records.push(NamespaceRecord {
        key: key.to_owned(),
        value: value.to_vec(),
    });
    *total_bytes = next_total;
    Ok(true)
}

fn backend(error: impl std::fmt::Display) -> StorageError {
    StorageError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[derive(Default)]
    struct NonPaginatedStore {
        inner: MemoryStore,
    }

    impl DurableStore for NonPaginatedStore {
        fn put(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), StorageError> {
            self.inner.put(namespace, key, value)
        }

        fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(namespace, key)
        }

        fn delete(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
            self.inner.delete(namespace, key)
        }

        fn compare_and_swap(
            &self,
            namespace: &str,
            key: &str,
            expected: Option<&[u8]>,
            value: &[u8],
        ) -> Result<bool, StorageError> {
            self.inner.compare_and_swap(namespace, key, expected, value)
        }

        fn apply_batch(&self, operations: &[BatchOperation]) -> Result<(), StorageError> {
            self.inner.apply_batch(operations)
        }

        fn apply_batch_if(
            &self,
            namespace: &str,
            key: &str,
            expected: Option<&[u8]>,
            operations: &[BatchOperation],
        ) -> Result<bool, StorageError> {
            self.inner
                .apply_batch_if(namespace, key, expected, operations)
        }

        fn scan_namespace(
            &self,
            namespace: &str,
            limits: ScanLimits,
        ) -> Result<Vec<NamespaceRecord>, StorageError> {
            self.inner.scan_namespace(namespace, limits)
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn for_each_shared_backend(mut exercise: impl FnMut(Arc<dyn DurableStore>)) {
        exercise(Arc::new(MemoryStore::default()));
        let directory = private_tempdir();
        exercise(Arc::new(
            RedbStore::create(directory.path().join("shared.redb")).unwrap(),
        ));
    }

    #[test]
    fn committed_records_survive_reopen_and_delete() {
        let directory = private_tempdir();
        let path = directory.path().join("state.redb");
        {
            let store = RedbStore::create(&path).unwrap();
            store
                .put("mask", "session/member", b"opening-share")
                .unwrap();
        }
        {
            let store = RedbStore::create(&path).unwrap();
            assert_eq!(
                store.get("mask", "session/member").unwrap(),
                Some(b"opening-share".to_vec())
            );
            store.delete("mask", "session/member").unwrap();
            assert_eq!(store.get("mask", "session/member").unwrap(), None);
        }
    }

    #[test]
    fn open_existing_never_creates_or_initializes_storage() {
        let directory = private_tempdir();
        let missing = directory.path().join("missing.redb");
        assert!(RedbStore::open_existing(&missing).is_err());
        assert!(!missing.exists());
        #[cfg(target_os = "linux")]
        {
            assert!(ReadOnlyRedbStore::open_existing(&missing).is_err());
            assert!(!missing.exists());
        }

        let empty = directory.path().join("empty.redb");
        fs::write(&empty, []).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(RedbStore::open_existing(&empty).is_err());
        #[cfg(target_os = "linux")]
        assert!(ReadOnlyRedbStore::open_existing(&empty).is_err());
        assert_eq!(fs::metadata(&empty).unwrap().len(), 0);

        let unrelated = directory.path().join("unrelated.redb");
        {
            const UNRELATED: TableDefinition<&str, &[u8]> = TableDefinition::new("unrelated_table");
            let database = Database::create(&unrelated).unwrap();
            let transaction = database.begin_write().unwrap();
            transaction.open_table(UNRELATED).unwrap();
            transaction.commit().unwrap();
        }
        #[cfg(unix)]
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(RedbStore::open_existing(&unrelated).is_err());
        #[cfg(target_os = "linux")]
        assert!(ReadOnlyRedbStore::open_existing(&unrelated).is_err());
    }

    #[test]
    fn writable_existing_open_preserves_and_can_update_initialized_state() {
        let directory = private_tempdir();
        let path = directory.path().join("existing.redb");
        {
            let store = RedbStore::create(&path).unwrap();
            store.put("state", "one", b"first").unwrap();
        }
        let store = RedbStore::open_existing(&path).unwrap();
        assert_eq!(store.get("state", "one").unwrap(), Some(b"first".to_vec()));
        store.put("state", "two", b"second").unwrap();
        drop(store);
        let reopened = RedbStore::open_existing(&path).unwrap();
        assert_eq!(
            reopened.get("state", "two").unwrap(),
            Some(b"second".to_vec())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_only_store_reads_and_pages_but_every_mutator_fails() {
        let directory = private_tempdir();
        let path = directory.path().join("readonly.redb");
        {
            let store = RedbStore::create(&path).unwrap();
            for (key, value) in [("a", b"one".as_slice()), ("b", b"two"), ("c", b"three")] {
                store.put("items", key, value).unwrap();
            }
        }
        let bytes_before = fs::read(&path).unwrap();
        let store = ReadOnlyRedbStore::open_existing(&path).unwrap();
        assert_eq!(store.get("items", "b").unwrap(), Some(b"two".to_vec()));
        let records = store
            .scan_namespace(
                "items",
                ScanLimits {
                    maximum_records: 3,
                    maximum_value_bytes: 5,
                    maximum_total_bytes: 32,
                },
            )
            .unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.key.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        let first = store
            .scan_namespace_after(
                "items",
                None,
                ScanLimits {
                    maximum_records: 2,
                    maximum_value_bytes: 5,
                    maximum_total_bytes: 32,
                },
            )
            .unwrap();
        assert!(first.has_more);
        assert_eq!(first.records.len(), 2);
        let second = store
            .scan_namespace_after(
                "items",
                Some(&first.records[1].key),
                ScanLimits {
                    maximum_records: 2,
                    maximum_value_bytes: 5,
                    maximum_total_bytes: 32,
                },
            )
            .unwrap();
        assert!(!second.has_more);
        assert_eq!(second.records[0].key, "c");

        let operation = BatchOperation::put("items", "d", b"four".to_vec());
        let condition = BatchCondition::absent("items", "d");
        assert_eq!(
            store.put("items", "d", b"four"),
            Err(StorageError::ReadOnly)
        );
        assert_eq!(store.delete("items", "a"), Err(StorageError::ReadOnly));
        assert_eq!(
            store.compare_and_swap("items", "a", Some(b"one"), b"changed"),
            Err(StorageError::ReadOnly)
        );
        assert_eq!(
            store.apply_batch(std::slice::from_ref(&operation)),
            Err(StorageError::ReadOnly)
        );
        assert_eq!(
            store.apply_batch_if("items", "d", None, std::slice::from_ref(&operation)),
            Err(StorageError::ReadOnly)
        );
        assert_eq!(
            store.apply_batch_if_all(&[condition], &[operation]),
            Err(StorageError::ReadOnly)
        );
        assert_eq!(
            store.put_if_absent("items", "d", b"four"),
            Err(StorageError::ReadOnly)
        );
        drop(store);
        assert_eq!(fs::read(&path).unwrap(), bytes_before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_only_open_is_shared_offline_and_conflicts_with_a_live_writer() {
        let directory = private_tempdir();
        let path = directory.path().join("locking.redb");
        {
            let store = RedbStore::create(&path).unwrap();
            store.put("state", "key", b"value").unwrap();
        }

        let first = ReadOnlyRedbStore::open_existing(&path).unwrap();
        let second = ReadOnlyRedbStore::open_existing(&path).unwrap();
        assert_eq!(first.get("state", "key").unwrap(), Some(b"value".to_vec()));
        assert_eq!(second.get("state", "key").unwrap(), Some(b"value".to_vec()));
        assert!(RedbStore::open_existing(&path).is_err());
        drop(first);
        drop(second);

        let writer = RedbStore::open_existing(&path).unwrap();
        assert!(ReadOnlyRedbStore::open_existing(&path).is_err());
        drop(writer);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_only_store_remains_bound_to_renamed_inode() {
        let directory = private_tempdir();
        let path = directory.path().join("state.redb");
        let moved = directory.path().join("moved.redb");
        {
            let store = RedbStore::create(&path).unwrap();
            store.put("state", "identity", b"original").unwrap();
        }
        let store = ReadOnlyRedbStore::open_existing(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        {
            let replacement = RedbStore::create(&path).unwrap();
            replacement
                .put("state", "identity", b"replacement")
                .unwrap();
        }
        assert_eq!(
            store.get("state", "identity").unwrap(),
            Some(b"original".to_vec())
        );
        drop(store);
        let replacement = RedbStore::open_existing(&path).unwrap();
        assert_eq!(
            replacement.get("state", "identity").unwrap(),
            Some(b"replacement".to_vec())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_opens_reject_insecure_modes_symlinks_and_ancestors_without_repair() {
        use std::os::unix::fs::symlink;

        let directory = private_tempdir();
        let path = directory.path().join("private.redb");
        drop(RedbStore::create(&path).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(RedbStore::open_existing(&path).is_err());
        assert!(ReadOnlyRedbStore::open_existing(&path).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let link = directory.path().join("state-link.redb");
        symlink(&path, &link).unwrap();
        assert!(RedbStore::open_existing(&link).is_err());
        assert!(ReadOnlyRedbStore::open_existing(&link).is_err());

        let insecure = directory.path().join("insecure");
        fs::create_dir(&insecure).unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o700)).unwrap();
        let nested = insecure.join("state.redb");
        drop(RedbStore::create(&nested).unwrap());
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(RedbStore::open_existing(&nested).is_err());
        assert!(ReadOnlyRedbStore::open_existing(&nested).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn durable_database_permissions_are_private_and_symlinks_fail_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = private_tempdir();
        let path = directory.path().join("private.redb");
        drop(RedbStore::create(&path).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        drop(RedbStore::create(&path).unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let link = directory.path().join("state-link.redb");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            RedbStore::create(link),
            Err(StorageError::Backend(message)) if message.contains("symbolic link")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn durable_database_rejects_symlink_and_parent_directory_ancestors() {
        use std::os::unix::fs::symlink;

        let directory = private_tempdir();
        let real = directory.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = directory.path().join("linked");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            RedbStore::create(link.join("state.redb")),
            Err(StorageError::Backend(_))
        ));

        let parent_relative = real.join("child").join("..").join("state.redb");
        assert!(matches!(
            RedbStore::create(parent_relative),
            Err(StorageError::Backend(message)) if message.contains("parent-directory")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn durable_database_rejects_insecure_ancestors_but_permits_sticky_ones() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_tempdir();
        let insecure = directory.path().join("insecure");
        fs::create_dir(&insecure).unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            RedbStore::create(insecure.join("state.redb")),
            Err(StorageError::Backend(message)) if message.contains("group/world-writable")
        ));

        let sticky = directory.path().join("sticky");
        fs::create_dir(&sticky).unwrap();
        fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777)).unwrap();
        drop(RedbStore::create(sticky.join("state.redb")).unwrap());
    }

    #[test]
    fn memory_store_obeys_the_same_namespace_and_copy_contract() {
        let store = MemoryStore::default();
        let mut value = vec![1, 2, 3];
        store.put("test", "key", &value).unwrap();
        value[0] = 9;
        assert_eq!(store.get("test", "key").unwrap(), Some(vec![1, 2, 3]));
        store.delete("test", "key").unwrap();
        assert_eq!(store.get("test", "key").unwrap(), None);
    }

    #[test]
    fn compare_and_swap_is_atomic_and_checks_expected_bytes() {
        let store = MemoryStore::default();
        assert!(store.put_if_absent("sequence", "one", b"1").unwrap());
        assert!(!store.put_if_absent("sequence", "one", b"2").unwrap());
        assert!(
            !store
                .compare_and_swap("sequence", "one", Some(b"0"), b"2")
                .unwrap()
        );
        assert!(
            store
                .compare_and_swap("sequence", "one", Some(b"1"), b"2")
                .unwrap()
        );
        assert_eq!(store.get("sequence", "one").unwrap(), Some(b"2".to_vec()));
    }

    #[test]
    fn ordered_batches_are_atomic_across_namespaces_and_prevalidate_every_key() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            store.put("first", "key", b"old").unwrap();
            store.put("second", "retire", b"remove").unwrap();
            store
                .apply_batch(&[
                    BatchOperation::delete("first", "key"),
                    BatchOperation::put("first", "key", b"new".to_vec()),
                    BatchOperation::delete("second", "retire"),
                    BatchOperation::put("third", "created", b"value".to_vec()),
                ])
                .unwrap();
            assert_eq!(store.get("first", "key").unwrap(), Some(b"new".to_vec()));
            assert_eq!(store.get("second", "retire").unwrap(), None);
            assert_eq!(
                store.get("third", "created").unwrap(),
                Some(b"value".to_vec())
            );

            assert_eq!(
                store.apply_batch(&[
                    BatchOperation::put("first", "key", b"not-committed".to_vec()),
                    BatchOperation::delete("invalid\0namespace", "key"),
                ]),
                Err(StorageError::InvalidKey)
            );
            assert_eq!(store.get("first", "key").unwrap(), Some(b"new".to_vec()));
        }
    }

    #[test]
    fn conditional_batch_mismatch_leaves_every_record_unchanged() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            store.put("state", "active", b"old").unwrap();
            store.put("state", "retire", b"keep").unwrap();

            assert!(
                !store
                    .apply_batch_if(
                        "state",
                        "active",
                        Some(b"wrong"),
                        &[
                            BatchOperation::put("state", "active", b"new".to_vec()),
                            BatchOperation::delete("state", "retire"),
                            BatchOperation::put("other", "created", b"value".to_vec()),
                        ],
                    )
                    .unwrap()
            );

            assert_eq!(store.get("state", "active").unwrap(), Some(b"old".to_vec()));
            assert_eq!(
                store.get("state", "retire").unwrap(),
                Some(b"keep".to_vec())
            );
            assert_eq!(store.get("other", "created").unwrap(), None);
        }
    }

    #[test]
    fn conditional_batch_match_applies_every_ordered_mutation() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            store.put("state", "active", b"old").unwrap();
            store.put("state", "retire", b"remove").unwrap();

            assert!(
                store
                    .apply_batch_if(
                        "state",
                        "active",
                        Some(b"old"),
                        &[
                            BatchOperation::put("state", "active", b"new".to_vec()),
                            BatchOperation::delete("state", "retire"),
                            BatchOperation::put("other", "created", b"value".to_vec()),
                        ],
                    )
                    .unwrap()
            );

            assert_eq!(store.get("state", "active").unwrap(), Some(b"new".to_vec()));
            assert_eq!(store.get("state", "retire").unwrap(), None);
            assert_eq!(
                store.get("other", "created").unwrap(),
                Some(b"value".to_vec())
            );
        }
    }

    #[test]
    fn conditional_batch_compares_guard_before_operations_that_replace_it() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            store.put("state", "active", b"old").unwrap();

            assert!(
                store
                    .apply_batch_if(
                        "state",
                        "active",
                        Some(b"old"),
                        &[
                            BatchOperation::delete("state", "active"),
                            BatchOperation::put("state", "active", b"intermediate".to_vec()),
                            BatchOperation::put("state", "active", b"final".to_vec()),
                        ],
                    )
                    .unwrap()
            );
            assert_eq!(
                store.get("state", "active").unwrap(),
                Some(b"final".to_vec())
            );

            assert!(
                !store
                    .apply_batch_if(
                        "state",
                        "active",
                        Some(b"old"),
                        &[BatchOperation::put("state", "active", b"old".to_vec(),)],
                    )
                    .unwrap()
            );
            assert_eq!(
                store.get("state", "active").unwrap(),
                Some(b"final".to_vec())
            );
        }
    }

    #[test]
    fn conditional_batch_rejects_any_invalid_key_before_writing() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            store.put("state", "active", b"old").unwrap();
            assert_eq!(
                store.apply_batch_if(
                    "state",
                    "active",
                    Some(b"old"),
                    &[
                        BatchOperation::put("state", "active", b"not-committed".to_vec()),
                        BatchOperation::put("state", "created", b"not-committed".to_vec()),
                        BatchOperation::delete("invalid\0namespace", "late"),
                    ],
                ),
                Err(StorageError::InvalidKey)
            );
            assert_eq!(store.get("state", "active").unwrap(), Some(b"old".to_vec()));
            assert_eq!(store.get("state", "created").unwrap(), None);

            assert_eq!(
                store.apply_batch_if(
                    "invalid\0namespace",
                    "guard",
                    None,
                    &[BatchOperation::put("state", "created", b"value".to_vec())],
                ),
                Err(StorageError::InvalidKey)
            );
            assert_eq!(store.get("state", "created").unwrap(), None);
        }
    }

    #[test]
    fn multi_condition_batches_use_one_pre_batch_view_and_never_partially_write() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            store.put("guard", "first", b"one").unwrap();
            store.put("guard", "second", b"two").unwrap();
            store.put("state", "retire", b"keep").unwrap();

            assert!(
                !store
                    .apply_batch_if_all(
                        &[
                            BatchCondition::equals("guard", "first", b"one".to_vec()),
                            BatchCondition::equals("guard", "second", b"wrong".to_vec()),
                            BatchCondition::absent("guard", "third"),
                        ],
                        &[
                            BatchOperation::put("state", "created", b"no".to_vec()),
                            BatchOperation::delete("state", "retire"),
                        ],
                    )
                    .unwrap()
            );
            assert_eq!(store.get("state", "created").unwrap(), None);
            assert_eq!(
                store.get("state", "retire").unwrap(),
                Some(b"keep".to_vec())
            );

            assert!(
                store
                    .apply_batch_if_all(
                        &[
                            BatchCondition::equals("guard", "first", b"one".to_vec()),
                            BatchCondition::equals("guard", "second", b"two".to_vec()),
                            BatchCondition::absent("guard", "third"),
                        ],
                        &[
                            BatchOperation::put("guard", "first", b"changed".to_vec()),
                            BatchOperation::put("guard", "third", b"now-present".to_vec()),
                            BatchOperation::delete("state", "retire"),
                        ],
                    )
                    .unwrap()
            );
            assert_eq!(
                store.get("guard", "first").unwrap(),
                Some(b"changed".to_vec())
            );
            assert_eq!(
                store.get("guard", "third").unwrap(),
                Some(b"now-present".to_vec())
            );
            assert_eq!(store.get("state", "retire").unwrap(), None);

            assert_eq!(
                store.apply_batch_if_all(
                    &[
                        BatchCondition::equals("guard", "first", b"changed".to_vec()),
                        BatchCondition::equals("invalid\0guard", "late", b"x".to_vec()),
                    ],
                    &[BatchOperation::put(
                        "state",
                        "invalid-attempt",
                        b"no".to_vec(),
                    )],
                ),
                Err(StorageError::InvalidKey)
            );
            assert_eq!(store.get("state", "invalid-attempt").unwrap(), None);
        }
    }

    #[test]
    fn compatibility_multi_condition_default_fails_closed() {
        let store = NonPaginatedStore::default();
        assert_eq!(
            store.apply_batch_if_all(
                &[
                    BatchCondition::absent("guard", "one"),
                    BatchCondition::absent("guard", "two"),
                ],
                &[BatchOperation::put("state", "created", b"no".to_vec())],
            ),
            Err(StorageError::MultipleConditionsUnsupported)
        );
        assert_eq!(store.get("state", "created").unwrap(), None);
    }

    #[test]
    fn namespace_recovery_scan_is_ordered_isolated_and_bounded() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            store.put("recover", "b", b"22").unwrap();
            store.put("other", "hidden", b"x").unwrap();
            store.put("recover", "a", b"1").unwrap();
            let limits = ScanLimits {
                maximum_records: 2,
                maximum_value_bytes: 2,
                maximum_total_bytes: 5,
            };
            assert_eq!(
                store.scan_namespace("recover", limits).unwrap(),
                vec![
                    NamespaceRecord {
                        key: "a".to_owned(),
                        value: b"1".to_vec(),
                    },
                    NamespaceRecord {
                        key: "b".to_owned(),
                        value: b"22".to_vec(),
                    },
                ]
            );
            assert_eq!(
                store.scan_namespace(
                    "recover",
                    ScanLimits {
                        maximum_records: 1,
                        ..limits
                    }
                ),
                Err(StorageError::ScanLimit)
            );
        }
    }

    #[test]
    fn paginated_namespace_scan_is_exclusive_bounded_and_backend_equivalent() {
        for store in [
            Box::new(MemoryStore::default()) as Box<dyn DurableStore>,
            Box::new(RedbStore::create(tempfile::NamedTempFile::new().unwrap().path()).unwrap())
                as Box<dyn DurableStore>,
        ] {
            for (key, value) in [
                ("d", b"4444".as_slice()),
                ("b", b"22".as_slice()),
                ("a", b"1".as_slice()),
                ("c", b"333".as_slice()),
            ] {
                store.put("paged", key, value).unwrap();
            }
            store.put("other", "b", b"hidden").unwrap();

            let complete_limits = ScanLimits {
                maximum_records: 4,
                maximum_value_bytes: 4,
                maximum_total_bytes: 14,
            };
            let complete = store.scan_namespace("paged", complete_limits).unwrap();

            let first = store
                .scan_namespace_after(
                    "paged",
                    None,
                    ScanLimits {
                        maximum_records: 2,
                        ..complete_limits
                    },
                )
                .unwrap();
            assert_eq!(
                first
                    .records
                    .iter()
                    .map(|record| record.key.as_str())
                    .collect::<Vec<_>>(),
                vec!["a", "b"]
            );
            assert!(first.has_more);

            let second = store
                .scan_namespace_after(
                    "paged",
                    Some(&first.records.last().unwrap().key),
                    ScanLimits {
                        maximum_records: 2,
                        ..complete_limits
                    },
                )
                .unwrap();
            assert_eq!(
                second
                    .records
                    .iter()
                    .map(|record| record.key.as_str())
                    .collect::<Vec<_>>(),
                vec!["c", "d"]
            );
            assert!(!second.has_more);

            let mut joined = first.records;
            joined.extend(second.records);
            assert_eq!(joined, complete);

            let terminal = store
                .scan_namespace_after("paged", Some("d"), complete_limits)
                .unwrap();
            assert!(terminal.records.is_empty());
            assert!(!terminal.has_more);

            let byte_limited = ScanLimits {
                maximum_records: 4,
                maximum_value_bytes: 4,
                maximum_total_bytes: 5,
            };
            let first = store
                .scan_namespace_after("paged", None, byte_limited)
                .unwrap();
            assert_eq!(
                first
                    .records
                    .iter()
                    .map(|record| record.key.as_str())
                    .collect::<Vec<_>>(),
                vec!["a", "b"]
            );
            assert!(first.has_more);
            let second = store
                .scan_namespace_after("paged", Some("b"), byte_limited)
                .unwrap();
            assert_eq!(second.records.len(), 1);
            assert_eq!(second.records[0].key, "c");
            assert!(second.has_more);
            let third = store
                .scan_namespace_after("paged", Some("c"), byte_limited)
                .unwrap();
            assert_eq!(third.records.len(), 1);
            assert_eq!(third.records[0].key, "d");
            assert!(!third.has_more);

            assert_eq!(
                store.scan_namespace_after(
                    "paged",
                    None,
                    ScanLimits {
                        maximum_records: 0,
                        ..complete_limits
                    },
                ),
                Err(StorageError::ScanLimit)
            );
            assert_eq!(
                store.scan_namespace_after(
                    "paged",
                    None,
                    ScanLimits {
                        maximum_value_bytes: 0,
                        ..complete_limits
                    },
                ),
                Err(StorageError::ScanLimit)
            );
            assert_eq!(
                store.scan_namespace_after(
                    "paged",
                    None,
                    ScanLimits {
                        maximum_total_bytes: 1,
                        ..complete_limits
                    },
                ),
                Err(StorageError::ScanLimit)
            );
            assert_eq!(
                store.scan_namespace_after("paged", Some("bad\0cursor"), complete_limits),
                Err(StorageError::InvalidKey)
            );
        }
    }

    #[test]
    fn paginated_scan_default_fails_closed_for_existing_store_implementations() {
        let store = NonPaginatedStore::default();
        assert_eq!(
            store.scan_namespace_after(
                "records",
                None,
                ScanLimits {
                    maximum_records: 1,
                    maximum_value_bytes: 1,
                    maximum_total_bytes: 2,
                },
            ),
            Err(StorageError::PaginationUnsupported)
        );
    }

    #[test]
    fn immutable_journal_covers_protocol_records_and_survives_restart() {
        let directory = private_tempdir();
        let path = directory.path().join("journal.redb");
        let key = [7; 32];
        {
            let store = RedbStore::create(&path).unwrap();
            let journal = ProtocolJournal::new(&store);
            journal
                .persist(ProtocolRecordKind::AcceptedShare, &key, b"share-v1")
                .unwrap();
            journal
                .persist(ProtocolRecordKind::AcceptedShare, &key, b"share-v1")
                .unwrap();
        }
        let store = RedbStore::create(&path).unwrap();
        let journal = ProtocolJournal::new(&store);
        assert_eq!(
            journal
                .load(ProtocolRecordKind::AcceptedShare, &key)
                .unwrap(),
            Some(b"share-v1".to_vec())
        );
        assert_eq!(
            journal.persist(ProtocolRecordKind::AcceptedShare, &key, b"share-v2"),
            Err(DurableInvariantError::ImmutableConflict)
        );
    }

    #[test]
    fn journal_and_derived_batch_is_atomic_repairable_and_immutable() {
        for_each_shared_backend(|store| {
            let journal = ProtocolJournal::new(store.as_ref());
            let key = [0x31; 32];
            store.put("derived", "active", b"old").unwrap();
            store.put("derived", "retire", b"present").unwrap();

            assert_eq!(
                journal.persist_with_batch(
                    ProtocolRecordKind::AcceptedShare,
                    &key,
                    b"share-v1",
                    &[
                        BatchOperation::put("derived", "active", b"not-written".to_vec()),
                        BatchOperation::put("invalid\0namespace", "late", b"x".to_vec()),
                    ],
                ),
                Err(DurableInvariantError::Storage(StorageError::InvalidKey))
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, &key)
                    .unwrap(),
                None
            );
            assert_eq!(
                store.get("derived", "active").unwrap(),
                Some(b"old".to_vec())
            );

            let derived_operations = [
                BatchOperation::put("derived", "active", b"share-v1".to_vec()),
                BatchOperation::delete("derived", "retire"),
            ];
            journal
                .persist_with_batch(
                    ProtocolRecordKind::AcceptedShare,
                    &key,
                    b"share-v1",
                    &derived_operations,
                )
                .unwrap();
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, &key)
                    .unwrap(),
                Some(b"share-v1".to_vec())
            );
            assert_eq!(
                store.get("derived", "active").unwrap(),
                Some(b"share-v1".to_vec())
            );
            assert_eq!(store.get("derived", "retire").unwrap(), None);

            store.put("derived", "active", b"stale").unwrap();
            store.put("derived", "retire", b"returned").unwrap();
            journal
                .persist_with_batch(
                    ProtocolRecordKind::AcceptedShare,
                    &key,
                    b"share-v1",
                    &derived_operations,
                )
                .unwrap();
            assert_eq!(
                store.get("derived", "active").unwrap(),
                Some(b"share-v1".to_vec())
            );
            assert_eq!(store.get("derived", "retire").unwrap(), None);

            assert_eq!(
                journal.persist_with_batch(
                    ProtocolRecordKind::AcceptedShare,
                    &key,
                    b"share-v2",
                    &[BatchOperation::put(
                        "derived",
                        "conflict-leak",
                        b"no".to_vec(),
                    )],
                ),
                Err(DurableInvariantError::ImmutableConflict)
            );
            assert_eq!(store.get("derived", "conflict-leak").unwrap(), None);

            let encoded_key = hex::encode(key);
            for forbidden in [
                BatchOperation::put(
                    ProtocolRecordKind::AcceptedShare.namespace(),
                    &encoded_key,
                    b"replacement".to_vec(),
                ),
                BatchOperation::delete(ProtocolRecordKind::AcceptedShare.namespace(), &encoded_key),
            ] {
                assert_eq!(
                    journal.persist_with_batch(
                        ProtocolRecordKind::AcceptedShare,
                        &key,
                        b"share-v1",
                        &[forbidden],
                    ),
                    Err(DurableInvariantError::SupplementalJournalTarget)
                );
            }
        });
    }

    #[test]
    fn conditional_journal_batch_distinguishes_new_rejection_and_late_exact_retry() {
        for_each_shared_backend(|store| {
            let journal = ProtocolJournal::new(store.as_ref());
            let key = [0x42; 32];
            let closure_absent = [BatchCondition::absent("session", "closed")];
            let derived = [BatchOperation::put(
                "active-share",
                "share",
                b"session".to_vec(),
            )];

            store.put("session", "closed", b"closed").unwrap();
            assert_eq!(
                journal
                    .persist_with_conditions_and_batch(
                        ProtocolRecordKind::AcceptedShare,
                        &key,
                        b"share",
                        &closure_absent,
                        &derived,
                    )
                    .unwrap(),
                JournalBatchOutcome::PreconditionMismatch
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, &key)
                    .unwrap(),
                None
            );
            assert_eq!(store.get("active-share", "share").unwrap(), None);

            store.delete("session", "closed").unwrap();
            assert_eq!(
                journal
                    .persist_with_conditions_and_batch(
                        ProtocolRecordKind::AcceptedShare,
                        &key,
                        b"share",
                        &closure_absent,
                        &derived,
                    )
                    .unwrap(),
                JournalBatchOutcome::Committed
            );

            store.delete("active-share", "share").unwrap();
            assert_eq!(
                journal
                    .persist_with_conditions_and_batch(
                        ProtocolRecordKind::AcceptedShare,
                        &key,
                        b"share",
                        &closure_absent,
                        &derived,
                    )
                    .unwrap(),
                JournalBatchOutcome::Committed
            );
            assert_eq!(
                store.get("active-share", "share").unwrap(),
                Some(b"session".to_vec())
            );

            store.put("session", "closed", b"closed").unwrap();
            store.delete("active-share", "share").unwrap();
            assert_eq!(
                journal
                    .persist_with_conditions_and_batch(
                        ProtocolRecordKind::AcceptedShare,
                        &key,
                        b"share",
                        &closure_absent,
                        &derived,
                    )
                    .unwrap(),
                JournalBatchOutcome::ExactRecord
            );
            assert_eq!(store.get("active-share", "share").unwrap(), None);
            assert_eq!(
                journal.persist_with_conditions_and_batch(
                    ProtocolRecordKind::AcceptedShare,
                    &key,
                    b"different",
                    &closure_absent,
                    &derived,
                ),
                Err(DurableInvariantError::ImmutableConflict)
            );
        });
    }

    #[test]
    fn multi_record_journal_batch_is_atomic_repairable_and_conditioned() {
        for_each_shared_backend(|store| {
            let journal = ProtocolJournal::new(store.as_ref());
            let records = [
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedWorkKey,
                    b"work-key".to_vec(),
                    b"work-value".to_vec(),
                ),
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedShare,
                    b"share-key".to_vec(),
                    b"share-value".to_vec(),
                ),
            ];
            let session_open = [BatchCondition::absent("session", "closed")];
            let derived = [BatchOperation::put(
                "active-share",
                "share-key",
                b"session-id".to_vec(),
            )];

            assert_eq!(
                journal.persist_records_with_conditions_and_batch(
                    &records,
                    &session_open,
                    &[
                        derived[0].clone(),
                        BatchOperation::put("invalid\0namespace", "late", b"x".to_vec()),
                    ],
                ),
                Err(DurableInvariantError::Storage(StorageError::InvalidKey))
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedWorkKey, b"work-key")
                    .unwrap(),
                None
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, b"share-key")
                    .unwrap(),
                None
            );
            assert_eq!(store.get("active-share", "share-key").unwrap(), None);

            assert_eq!(
                journal
                    .persist_records_with_conditions_and_batch(&records, &session_open, &derived,)
                    .unwrap(),
                JournalBatchOutcome::Committed
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedWorkKey, b"work-key")
                    .unwrap(),
                Some(b"work-value".to_vec())
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, b"share-key")
                    .unwrap(),
                Some(b"share-value".to_vec())
            );
            assert_eq!(
                store.get("active-share", "share-key").unwrap(),
                Some(b"session-id".to_vec())
            );

            // Exact retry repairs derived state while the external condition
            // remains true.
            store.delete("active-share", "share-key").unwrap();
            assert_eq!(
                journal
                    .persist_records_with_conditions_and_batch(&records, &session_open, &derived,)
                    .unwrap(),
                JournalBatchOutcome::Committed
            );
            assert_eq!(
                store.get("active-share", "share-key").unwrap(),
                Some(b"session-id".to_vec())
            );

            // A retry after closure recognizes complete exact evidence but
            // does not recreate the derived active index.
            store.put("session", "closed", b"yes").unwrap();
            store.delete("active-share", "share-key").unwrap();
            assert_eq!(
                journal
                    .persist_records_with_conditions_and_batch(&records, &session_open, &derived,)
                    .unwrap(),
                JournalBatchOutcome::ExactRecord
            );
            assert_eq!(store.get("active-share", "share-key").unwrap(), None);

            let rejected = [
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedWorkKey,
                    b"rejected-work".to_vec(),
                    b"work".to_vec(),
                ),
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedShare,
                    b"rejected-share".to_vec(),
                    b"share".to_vec(),
                ),
            ];
            assert_eq!(
                journal
                    .persist_records_with_conditions_and_batch(&rejected, &session_open, &derived,)
                    .unwrap(),
                JournalBatchOutcome::PreconditionMismatch
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedWorkKey, b"rejected-work")
                    .unwrap(),
                None
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, b"rejected-share")
                    .unwrap(),
                None
            );
        });
    }

    #[test]
    fn multi_record_journal_batch_fills_missing_exact_set_and_rejects_any_conflict() {
        for_each_shared_backend(|store| {
            let journal = ProtocolJournal::new(store.as_ref());
            journal
                .persist(
                    ProtocolRecordKind::AcceptedWorkKey,
                    b"existing-work",
                    b"exact-work",
                )
                .unwrap();
            let mixed = [
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedWorkKey,
                    b"existing-work".to_vec(),
                    b"exact-work".to_vec(),
                ),
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedShare,
                    b"missing-share".to_vec(),
                    b"new-share".to_vec(),
                ),
            ];
            assert_eq!(
                journal
                    .persist_records_with_conditions_and_batch(
                        &mixed,
                        &[],
                        &[BatchOperation::put(
                            "derived",
                            "mixed",
                            b"complete".to_vec(),
                        )],
                    )
                    .unwrap(),
                JournalBatchOutcome::Committed
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, b"missing-share")
                    .unwrap(),
                Some(b"new-share".to_vec())
            );

            journal
                .persist(
                    ProtocolRecordKind::AcceptedWorkKey,
                    b"conflicting-work",
                    b"other-value",
                )
                .unwrap();
            let conflicting = [
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedWorkKey,
                    b"conflicting-work".to_vec(),
                    b"requested-value".to_vec(),
                ),
                JournalBatchRecord::new(
                    ProtocolRecordKind::AcceptedShare,
                    b"must-stay-missing".to_vec(),
                    b"share".to_vec(),
                ),
            ];
            assert_eq!(
                journal.persist_records_with_conditions_and_batch(
                    &conflicting,
                    &[],
                    &[BatchOperation::put(
                        "derived",
                        "conflict-leak",
                        b"no".to_vec(),
                    )],
                ),
                Err(DurableInvariantError::ImmutableConflict)
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, b"must-stay-missing")
                    .unwrap(),
                None
            );
            assert_eq!(store.get("derived", "conflict-leak").unwrap(), None);

            assert_eq!(
                journal.persist_records_with_conditions_and_batch(&[], &[], &[]),
                Err(DurableInvariantError::EmptyJournalBatch)
            );
            assert_eq!(
                journal.persist_records_with_conditions_and_batch(
                    &[mixed[0].clone(), mixed[0].clone()],
                    &[],
                    &[],
                ),
                Err(DurableInvariantError::DuplicateJournalKey)
            );
            assert_eq!(
                journal.persist_records_with_conditions_and_batch(
                    &mixed,
                    &[],
                    &[BatchOperation::put(
                        ProtocolRecordKind::PayoutPlan.namespace(),
                        "unrelated-journal-key",
                        b"forbidden".to_vec(),
                    )],
                ),
                Err(DurableInvariantError::SupplementalJournalTarget)
            );
        });
    }

    #[test]
    fn racing_conflicting_multi_record_batches_are_all_or_nothing() {
        for_each_shared_backend(|store| {
            let barrier = Arc::new(Barrier::new(3));
            let mut handles = Vec::new();
            for (label, share_value) in [
                ("left-multi", b"left-share".to_vec()),
                ("right-multi", b"right-share".to_vec()),
            ] {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                handles.push(thread::spawn(move || {
                    let records = [
                        JournalBatchRecord::new(
                            ProtocolRecordKind::AcceptedWorkKey,
                            b"racing-work".to_vec(),
                            b"common-work".to_vec(),
                        ),
                        JournalBatchRecord::new(
                            ProtocolRecordKind::AcceptedShare,
                            b"racing-share".to_vec(),
                            share_value.clone(),
                        ),
                    ];
                    barrier.wait();
                    ProtocolJournal::new(store.as_ref()).persist_records_with_conditions_and_batch(
                        &records,
                        &[],
                        &[
                            BatchOperation::put("multi-race", "winner", share_value.clone()),
                            BatchOperation::put("multi-race", label, b"applied".to_vec()),
                        ],
                    )
                }));
            }
            barrier.wait();
            let results = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                results
                    .iter()
                    .filter(|result| { matches!(result, Ok(JournalBatchOutcome::Committed)) })
                    .count(),
                1
            );
            assert_eq!(
                results
                    .iter()
                    .filter(|result| {
                        matches!(result, Err(DurableInvariantError::ImmutableConflict))
                    })
                    .count(),
                1
            );

            let journal = ProtocolJournal::new(store.as_ref());
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedWorkKey, b"racing-work")
                    .unwrap(),
                Some(b"common-work".to_vec())
            );
            let share = journal
                .load(ProtocolRecordKind::AcceptedShare, b"racing-share")
                .unwrap()
                .unwrap();
            assert_eq!(
                store.get("multi-race", "winner").unwrap(),
                Some(share.clone())
            );
            let left_won = share == b"left-share";
            assert_eq!(
                store.get("multi-race", "left-multi").unwrap().is_some(),
                left_won
            );
            assert_eq!(
                store.get("multi-race", "right-multi").unwrap().is_some(),
                !left_won
            );
        });
    }

    #[test]
    fn multi_record_journal_commit_survives_redb_restart_and_exact_retry() {
        let directory = private_tempdir();
        let path = directory.path().join("multi-journal.redb");
        let records = [
            JournalBatchRecord::new(
                ProtocolRecordKind::AcceptedWorkKey,
                b"restart-work".to_vec(),
                b"work".to_vec(),
            ),
            JournalBatchRecord::new(
                ProtocolRecordKind::AcceptedShare,
                b"restart-share".to_vec(),
                b"share".to_vec(),
            ),
        ];
        let derived = [BatchOperation::put(
            "active-share",
            "restart-share",
            b"session".to_vec(),
        )];
        {
            let store = RedbStore::create(&path).unwrap();
            assert_eq!(
                ProtocolJournal::new(&store)
                    .persist_records_with_conditions_and_batch(&records, &[], &derived)
                    .unwrap(),
                JournalBatchOutcome::Committed
            );
        }
        {
            let store = RedbStore::create(&path).unwrap();
            let journal = ProtocolJournal::new(&store);
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedWorkKey, b"restart-work")
                    .unwrap(),
                Some(b"work".to_vec())
            );
            assert_eq!(
                journal
                    .load(ProtocolRecordKind::AcceptedShare, b"restart-share")
                    .unwrap(),
                Some(b"share".to_vec())
            );
            store.delete("active-share", "restart-share").unwrap();
            assert_eq!(
                journal
                    .persist_records_with_conditions_and_batch(&records, &[], &derived)
                    .unwrap(),
                JournalBatchOutcome::Committed
            );
        }
        let store = RedbStore::create(&path).unwrap();
        assert_eq!(
            store.get("active-share", "restart-share").unwrap(),
            Some(b"session".to_vec())
        );
    }

    #[test]
    fn racing_conflicting_journal_batches_expose_only_the_winner_derivation() {
        for_each_shared_backend(|store| {
            let barrier = Arc::new(Barrier::new(3));
            let mut handles = Vec::new();
            for (label, value) in [("left", b"left".to_vec()), ("right", b"right".to_vec())] {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                handles.push(thread::spawn(move || {
                    barrier.wait();
                    ProtocolJournal::new(store.as_ref()).persist_with_batch(
                        ProtocolRecordKind::AcceptedShare,
                        &[0x53; 32],
                        &value,
                        &[
                            BatchOperation::put("race", "winner", value.clone()),
                            BatchOperation::put("race", label, b"applied".to_vec()),
                        ],
                    )
                }));
            }
            barrier.wait();
            let results = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
            assert_eq!(
                results
                    .iter()
                    .filter(|result| {
                        matches!(result, Err(DurableInvariantError::ImmutableConflict))
                    })
                    .count(),
                1
            );

            let journal_value = ProtocolJournal::new(store.as_ref())
                .load(ProtocolRecordKind::AcceptedShare, &[0x53; 32])
                .unwrap()
                .unwrap();
            assert_eq!(
                store.get("race", "winner").unwrap(),
                Some(journal_value.clone())
            );
            let left_won = journal_value == b"left";
            assert_eq!(store.get("race", "left").unwrap().is_some(), left_won);
            assert_eq!(store.get("race", "right").unwrap().is_some(), !left_won);
        });
    }

    #[test]
    fn protocol_recovery_kind_is_isolated_bounded_and_exactly_accounted() {
        let store = MemoryStore::default();
        let journal = ProtocolJournal::new(&store);
        journal
            .persist(ProtocolRecordKind::AcceptedShare, &[0x0a], b"abc")
            .unwrap();
        journal
            .persist(ProtocolRecordKind::AcceptedShare, &[0x0b, 0x0c], b"de")
            .unwrap();
        journal
            .persist(ProtocolRecordKind::PayoutPlan, &[0xff], b"hidden")
            .unwrap();

        let limits = ScanLimits {
            maximum_records: 2,
            maximum_value_bytes: 3,
            maximum_total_bytes: 11,
        };
        let recovered = journal
            .recover_kind(ProtocolRecordKind::AcceptedShare, limits)
            .unwrap();
        assert_eq!(recovered.records.len(), 2);
        assert!(
            recovered
                .records
                .iter()
                .all(|record| record.kind == ProtocolRecordKind::AcceptedShare)
        );
        assert_eq!(recovered.records[0].durable_key, vec![0x0a]);
        assert_eq!(recovered.records[1].durable_key, vec![0x0b, 0x0c]);
        assert_eq!(recovered.total_value_bytes, 5);
        // Encoded keys "0a" and "0b0c" occupy 2 + 4 bytes; values occupy 3 + 2.
        assert_eq!(recovered.total_scan_bytes, 11);

        let other = journal
            .recover_kind(
                ProtocolRecordKind::PayoutPlan,
                ScanLimits {
                    maximum_records: 1,
                    maximum_value_bytes: 6,
                    maximum_total_bytes: 8,
                },
            )
            .unwrap();
        assert_eq!(other.records.len(), 1);
        assert_eq!(other.records[0].durable_key, vec![0xff]);
        assert_eq!(other.total_value_bytes, 6);
        assert_eq!(other.total_scan_bytes, 8);

        for too_small in [
            ScanLimits {
                maximum_records: 1,
                ..limits
            },
            ScanLimits {
                maximum_value_bytes: 2,
                ..limits
            },
            ScanLimits {
                maximum_total_bytes: 10,
                ..limits
            },
        ] {
            assert_eq!(
                journal.recover_kind(ProtocolRecordKind::AcceptedShare, too_small),
                Err(DurableInvariantError::Storage(StorageError::ScanLimit))
            );
        }
    }

    #[test]
    fn protocol_recovery_pages_equal_complete_kind_recovery() {
        let store = MemoryStore::default();
        let journal = ProtocolJournal::new(&store);
        for index in [4u8, 1, 3, 0, 2] {
            journal
                .persist(
                    ProtocolRecordKind::AcceptedShare,
                    &[index],
                    &vec![index; usize::from(index) + 1],
                )
                .unwrap();
        }
        journal
            .persist(ProtocolRecordKind::PayoutPlan, &[0], b"isolated")
            .unwrap();

        let complete = journal
            .recover_kind(
                ProtocolRecordKind::AcceptedShare,
                ScanLimits {
                    maximum_records: 5,
                    maximum_value_bytes: 5,
                    maximum_total_bytes: 25,
                },
            )
            .unwrap();
        let page_limits = ScanLimits {
            maximum_records: 2,
            maximum_value_bytes: 5,
            maximum_total_bytes: 14,
        };
        let mut cursor: Option<Vec<u8>> = None;
        let mut records = Vec::new();
        let mut total_value_bytes = 0u64;
        let mut total_scan_bytes = 0u64;
        let mut page_count = 0usize;
        loop {
            let page = journal
                .recover_kind_page(
                    ProtocolRecordKind::AcceptedShare,
                    cursor.as_deref(),
                    page_limits,
                )
                .unwrap();
            page_count += 1;
            assert!(!page.recovery.records.is_empty());
            total_value_bytes += page.recovery.total_value_bytes;
            total_scan_bytes += page.recovery.total_scan_bytes;
            records.extend(page.recovery.records.iter().cloned());
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            assert_eq!(
                page.recovery.records.last().unwrap().durable_key,
                next_cursor
            );
            if let Some(previous_cursor) = &cursor {
                assert!(previous_cursor < &next_cursor);
            }
            cursor = Some(next_cursor);
            assert!(page_count < 5, "page continuation failed to make progress");
        }

        assert_eq!(page_count, 3);
        assert_eq!(records, complete.records);
        assert_eq!(total_value_bytes, complete.total_value_bytes);
        assert_eq!(total_scan_bytes, complete.total_scan_bytes);

        let terminal = journal
            .recover_kind_page(ProtocolRecordKind::AcceptedShare, Some(&[4]), page_limits)
            .unwrap();
        assert!(terminal.recovery.records.is_empty());
        assert_eq!(terminal.recovery.total_value_bytes, 0);
        assert_eq!(terminal.recovery.total_scan_bytes, 0);
        assert_eq!(terminal.next_cursor, None);

        let after_one = journal
            .recover_kind_page(ProtocolRecordKind::AcceptedShare, Some(&[1]), page_limits)
            .unwrap();
        assert_eq!(after_one.recovery.records[0].durable_key, vec![2]);
    }

    #[test]
    fn protocol_recovery_page_rejects_late_malformed_key_and_zero_progress_limit() {
        let store = MemoryStore::default();
        let journal = ProtocolJournal::new(&store);
        journal
            .persist(ProtocolRecordKind::AcceptedShare, &[0], b"valid")
            .unwrap();
        store
            .put(
                ProtocolRecordKind::AcceptedShare.namespace(),
                "zz",
                b"invalid",
            )
            .unwrap();
        let limits = ScanLimits {
            maximum_records: 1,
            maximum_value_bytes: 7,
            maximum_total_bytes: 16,
        };
        let first = journal
            .recover_kind_page(ProtocolRecordKind::AcceptedShare, None, limits)
            .unwrap();
        assert_eq!(first.recovery.records.len(), 1);
        assert_eq!(first.next_cursor, Some(vec![0]));
        assert_eq!(
            journal.recover_kind_page(
                ProtocolRecordKind::AcceptedShare,
                first.next_cursor.as_deref(),
                limits,
            ),
            Err(DurableInvariantError::InvalidRecoveryKey)
        );
        assert_eq!(
            journal.recover_kind_page(
                ProtocolRecordKind::AcceptedShare,
                None,
                ScanLimits {
                    maximum_records: 0,
                    ..limits
                },
            ),
            Err(DurableInvariantError::Storage(StorageError::ScanLimit))
        );
    }

    #[test]
    fn protocol_recovery_kind_rejects_malformed_and_noncanonical_keys() {
        for invalid_key in ["not-hex", "0A"] {
            let store = MemoryStore::default();
            store
                .put(
                    ProtocolRecordKind::AcceptedShare.namespace(),
                    invalid_key,
                    b"x",
                )
                .unwrap();
            let journal = ProtocolJournal::new(&store);
            assert_eq!(
                journal.recover_kind(
                    ProtocolRecordKind::AcceptedShare,
                    ScanLimits {
                        maximum_records: 1,
                        maximum_value_bytes: 1,
                        maximum_total_bytes: 32,
                    },
                ),
                Err(DurableInvariantError::InvalidRecoveryKey)
            );
        }
    }

    #[test]
    fn protocol_recovery_inventory_covers_every_category_and_rejects_bad_keys() {
        let store = MemoryStore::default();
        let journal = ProtocolJournal::new(&store);
        for (index, kind) in ProtocolRecordKind::ALL.into_iter().enumerate() {
            journal
                .persist(kind, &[index as u8], &[index as u8, 1])
                .unwrap();
        }
        let limits = ScanLimits {
            maximum_records: ProtocolRecordKind::ALL.len(),
            maximum_value_bytes: 2,
            maximum_total_bytes: 1_024,
        };
        let recovered = journal.recover_all(limits).unwrap();
        assert_eq!(recovered.records.len(), ProtocolRecordKind::ALL.len());
        assert_eq!(
            recovered.total_value_bytes,
            ProtocolRecordKind::ALL.len() as u64 * 2
        );
        assert_eq!(
            recovered.total_scan_bytes,
            ProtocolRecordKind::ALL.len() as u64 * 4
        );
        for (index, record) in recovered.records.iter().enumerate() {
            assert_eq!(record.kind, ProtocolRecordKind::ALL[index]);
            assert_eq!(record.durable_key, vec![index as u8]);
        }
        assert_eq!(
            journal.recover_all(ScanLimits {
                maximum_records: limits.maximum_records - 1,
                ..limits
            }),
            Err(DurableInvariantError::Storage(StorageError::ScanLimit))
        );
        assert_eq!(
            journal.recover_all(ScanLimits {
                maximum_total_bytes: recovered.total_scan_bytes - 1,
                ..limits
            }),
            Err(DurableInvariantError::Storage(StorageError::ScanLimit))
        );

        store
            .put(
                ProtocolRecordKind::AcceptedShare.namespace(),
                "NOT-HEX",
                b"x",
            )
            .unwrap();
        assert_eq!(
            journal.recover_all(ScanLimits {
                maximum_records: limits.maximum_records + 1,
                ..limits
            }),
            Err(DurableInvariantError::InvalidRecoveryKey)
        );
    }

    #[test]
    fn one_signature_per_role_scope_and_sequence_is_crash_safe() {
        let directory = private_tempdir();
        let path = directory.path().join("signing.redb");
        {
            let store = RedbStore::create(&path).unwrap();
            DurableSignGuard::new(&store)
                .authorize("receipt", &[3; 32], 9, &[4; 32])
                .unwrap();
        }
        let store = RedbStore::create(&path).unwrap();
        let guard = DurableSignGuard::new(&store);
        guard.authorize("receipt", &[3; 32], 9, &[4; 32]).unwrap();
        assert_eq!(
            guard.authorize("receipt", &[3; 32], 9, &[5; 32]),
            Err(DurableInvariantError::ConflictingSignature)
        );
        // Independent roles and sequences do not collide.
        guard.authorize("snapshot", &[3; 32], 9, &[5; 32]).unwrap();
        guard.authorize("receipt", &[3; 32], 10, &[5; 32]).unwrap();
    }
}
