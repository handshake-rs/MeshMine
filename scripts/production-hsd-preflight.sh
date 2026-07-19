#!/usr/bin/env bash
set -uo pipefail

# This is a Linux/systemd deployment check. Do not inherit an operator-provided
# command search path when examining production state.
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export GIT_OPTIONAL_LOCKS=0
export GIT_PAGER=cat
umask 077

usage() {
  echo "usage: $0 --service-scope user|system --service NAME.service --state-dir ABSOLUTE --hsd-cli ABSOLUTE --hsd-source ABSOLUTE --node-runtime ABSOLUTE --expected-commit HEX [--minimum-free-kib N] [--minimum-free-inodes N] [--minimum-restart-delay-sec N] [--minimum-start-limit-interval-sec N] [--maximum-start-limit-burst N]" >&2
  exit 2
}

service_scope=
service_name=
state_dir=
hsd_cli=
hsd_source=
node_runtime=
expected_commit=
minimum_free_kib=10485760
minimum_free_inodes=100000
minimum_restart_delay_sec=60
minimum_start_limit_interval_sec=600
maximum_start_limit_burst=5
declare -A seen_options=()

while (($#)); do
  case "$1" in
    --service-scope|--service|--state-dir|--hsd-cli|--hsd-source|--node-runtime|--expected-commit|--minimum-free-kib|--minimum-free-inodes|--minimum-restart-delay-sec|--minimum-start-limit-interval-sec|--maximum-start-limit-burst)
      (($# >= 2)) || usage
      [[ ! ${seen_options[$1]+present} ]] || usage
      seen_options[$1]=true
      value=$2
      [[ $value != --* ]] || usage
      case "$1" in
        --service-scope) service_scope=$value ;;
        --service) service_name=$value ;;
        --state-dir) state_dir=$value ;;
        --hsd-cli) hsd_cli=$value ;;
        --hsd-source) hsd_source=$value ;;
        --node-runtime) node_runtime=$value ;;
        --expected-commit) expected_commit=$value ;;
        --minimum-free-kib) minimum_free_kib=$value ;;
        --minimum-free-inodes) minimum_free_inodes=$value ;;
        --minimum-restart-delay-sec) minimum_restart_delay_sec=$value ;;
        --minimum-start-limit-interval-sec) minimum_start_limit_interval_sec=$value ;;
        --maximum-start-limit-burst) maximum_start_limit_burst=$value ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done

is_safe_scalar() {
  [[ -n $1 && ! $1 =~ [[:cntrl:]] ]]
}

normalize_decimal() {
  local value=$1
  while [[ ${#value} -gt 1 && $value == 0* ]]; do
    value=${value#0}
  done
  printf '%s' "$value"
}

decimal_ge() {
  local left right
  left=$(normalize_decimal "$1")
  right=$(normalize_decimal "$2")
  if ((${#left} != ${#right})); then
    ((${#left} > ${#right}))
  else
    [[ $left == "$right" || $left > "$right" ]]
  fi
}

[[ $service_scope == user || $service_scope == system ]] || usage
[[ $service_name =~ ^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service$ ]] || usage
for input_value in "$state_dir" "$hsd_cli" "$hsd_source" "$node_runtime"; do
  is_safe_scalar "$input_value" || usage
done
[[ $expected_commit =~ ^[0-9a-f]{40}$ ]] || usage
[[ $minimum_free_kib =~ ^[0-9]+$ && $minimum_free_inodes =~ ^[0-9]+$ ]] || usage
[[ $minimum_restart_delay_sec =~ ^[0-9]+$ && $minimum_start_limit_interval_sec =~ ^[0-9]+$ ]] || usage
[[ $maximum_start_limit_burst =~ ^[0-9]+$ ]] || usage
minimum_free_kib=$(normalize_decimal "$minimum_free_kib")
minimum_free_inodes=$(normalize_decimal "$minimum_free_inodes")
minimum_restart_delay_sec=$(normalize_decimal "$minimum_restart_delay_sec")
minimum_start_limit_interval_sec=$(normalize_decimal "$minimum_start_limit_interval_sec")
maximum_start_limit_burst=$(normalize_decimal "$maximum_start_limit_burst")
decimal_ge "$minimum_restart_delay_sec" 1 || usage
decimal_ge "$minimum_start_limit_interval_sec" 1 || usage
decimal_ge "$maximum_start_limit_burst" 1 || usage

failures=0
warnings=0

pass() {
  echo "PASS $1"
}

fail() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

warn() {
  echo "WARN $1"
  warnings=$((warnings + 1))
}

require_command() {
  if command -v "$1" >/dev/null 2>&1; then
    pass "command.$1=available"
  else
    fail "command.$1=missing"
  fi
}

for command_name in awk b2sum df dirname find git grep id realpath sort stat systemctl systemd-analyze wc; do
  require_command "$command_name"
done
if ((failures)); then
  echo "SUMMARY failures=$failures warnings=$warnings"
  exit 1
fi

systemctl_command=(systemctl)
if [[ $service_scope == user ]]; then
  systemctl_command+=(--user)
fi

if "${systemctl_command[@]}" is-active --quiet -- "$service_name"; then
  pass "service.active=true"
else
  fail "service.active=false"
fi
if "${systemctl_command[@]}" is-enabled --quiet -- "$service_name"; then
  pass "service.enabled=true"
else
  fail "service.enabled=false"
fi

service_properties=
if ! service_properties=$("${systemctl_command[@]}" show \
  --property=ActiveState,MainPID,NoNewPrivileges,UMask,Restart,RestartUSec,NRestarts,StartLimitBurst,StartLimitIntervalUSec,User,DynamicUser,ExecStart,WorkingDirectory \
  --no-pager -- "$service_name" 2>/dev/null); then
  fail "service.properties=unavailable"
fi

property_value() {
  local key=$1
  awk -F= -v key="$key" '
    $1 == key {
      if (seen++) exit 2
      sub(/^[^=]*=/, "")
      value = $0
    }
    END {
      if (seen != 1) exit 1
      print value
    }
  ' <<<"$service_properties"
}

get_property() {
  local key=$1
  local value
  if value=$(property_value "$key") && is_safe_scalar "$value"; then
    printf '%s' "$value"
  else
    return 1
  fi
}

main_pid=
if ! main_pid=$(get_property MainPID) || [[ ! $main_pid =~ ^[1-9][0-9]*$ ]]; then
  fail "service.main_pid=unknown"
  main_pid=
fi

proc_start_time() {
  local pid=$1
  local line tail
  IFS= read -r line <"/proc/$pid/stat" || return 1
  [[ $line == *') '* ]] || return 1
  tail=${line##*) }
  awk '{ print $20 }' <<<"$tail"
}

initial_start_time=
if [[ -n $main_pid ]]; then
  initial_start_time=$(proc_start_time "$main_pid" 2>/dev/null || true)
  [[ $initial_start_time =~ ^[0-9]+$ ]] || fail "service.process_start_time=unknown"
fi

service_uid=
service_gid=
service_group_list=
if [[ -n $main_pid ]]; then
  service_uid=$(awk '$1 == "Uid:" { print $3; exit }' "/proc/$main_pid/status" 2>/dev/null || true)
  service_gid=$(awk '$1 == "Gid:" { print $3; exit }' "/proc/$main_pid/status" 2>/dev/null || true)
  service_group_list=$(awk '$1 == "Groups:" { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }' "/proc/$main_pid/status" 2>/dev/null || true)
fi
if [[ $service_uid =~ ^[0-9]+$ ]]; then
  pass "service.effective_uid=$service_uid"
else
  fail "service.effective_uid=unknown"
  service_uid=$(id -u)
fi
service_groups=()
if [[ $service_gid =~ ^[0-9]+$ ]]; then
  service_groups+=("$service_gid")
fi
read -r -a supplemental_groups <<<"$service_group_list"
for supplemental_group in "${supplemental_groups[@]}"; do
  [[ $supplemental_group =~ ^[0-9]+$ ]] && service_groups+=("$supplemental_group")
done

configured_user=$(get_property User 2>/dev/null || true)
dynamic_user=$(get_property DynamicUser 2>/dev/null || true)
if [[ $service_scope == user ]]; then
  effective_uid=$(id -u)
  if [[ $service_uid == "$effective_uid" ]]; then
    pass "service.scope_uid_matches=true"
  else
    fail "service.scope_uid=$service_uid expected=$effective_uid"
  fi
elif [[ $dynamic_user == yes ]]; then
  pass "service.dynamic_user=true"
elif [[ -z $configured_user ]]; then
  if [[ $service_uid == 0 ]]; then
    pass "service.configured_uid=0"
  else
    fail "service.configured_uid=0 live=$service_uid"
  fi
elif configured_uid=$(id -u "$configured_user" 2>/dev/null); then
  if [[ $service_uid == "$configured_uid" ]]; then
    pass "service.configured_uid=$configured_uid"
  else
    fail "service.configured_uid=$configured_uid live=$service_uid"
  fi
else
  fail "service.configured_user_resolves=false"
fi

canonical_path() {
  local label=$1
  local path=$2
  local expected_type=$3
  if [[ $path != /* || $path == / ]]; then
    fail "$label.absolute_nonroot=false"
    return 1
  fi
  local resolved
  if ! resolved=$(realpath -e -- "$path" 2>/dev/null); then
    fail "$label.exists=false"
    return 1
  fi
  if [[ $resolved != "$path" ]]; then
    fail "$label.canonical=false"
    return 1
  fi
  if [[ $expected_type == file && ! -f $path ]] || [[ $expected_type == directory && ! -d $path ]]; then
    fail "$label.type=$expected_type-required"
    return 1
  fi
  pass "$label.canonical=true"
}

state_dir_valid=false
hsd_cli_valid=false
hsd_source_valid=false
node_runtime_valid=false
if canonical_path state_dir "$state_dir" directory; then state_dir_valid=true; fi
if canonical_path hsd_cli "$hsd_cli" file; then hsd_cli_valid=true; fi
if canonical_path hsd_source "$hsd_source" directory; then hsd_source_valid=true; fi
if canonical_path node_runtime "$node_runtime" file; then node_runtime_valid=true; fi

check_leaf() {
  local label=$1
  local path=$2
  local private=$3
  local executable=$4
  local owner_policy=$5
  local mode owner group mode_value access_bits
  if ! read -r mode owner group < <(stat -Lc '%a %u %g' -- "$path" 2>/dev/null); then
    fail "$label.stat=unavailable"
    return 1
  fi
  if [[ ! $mode =~ ^[0-7]{3,4}$ || ! $owner =~ ^[0-9]+$ || ! $group =~ ^[0-9]+$ ]]; then
    fail "$label.stat=invalid"
    return 1
  fi
  mode_value=$((8#$mode))
  if [[ $owner_policy == exact-service ]]; then
    if [[ $owner == "$service_uid" ]]; then
      pass "$label.owner_uid=$owner"
    else
      fail "$label.owner_uid=$owner expected=$service_uid"
    fi
  elif [[ $owner == 0 || $owner == "$service_uid" ]]; then
    pass "$label.owner_uid=$owner"
  else
    fail "$label.owner_uid=$owner expected=0-or-$service_uid"
  fi
  if [[ $owner == "$service_uid" ]]; then
    access_bits=$(((mode_value >> 6) & 7))
  elif group_matches_service "$group"; then
    access_bits=$(((mode_value >> 3) & 7))
  else
    access_bits=$((mode_value & 7))
  fi
  if ((mode_value & 0022)); then
    fail "$label.mode=$mode group_or_other_writable=true"
  elif [[ $private == true ]] && ((mode_value & 0077)); then
    fail "$label.mode=$mode private=false"
  elif [[ $private == true ]] && (( (mode_value & 0700) != 0700 )); then
    fail "$label.mode=$mode owner_rwx=false"
  elif [[ $executable == true ]] && (( (access_bits & 5) != 5 )); then
    fail "$label.mode=$mode service_read_execute=false"
  else
    pass "$label.mode=$mode"
  fi
}

group_matches_service() {
  local candidate=$1
  local service_group
  for service_group in "${service_groups[@]}"; do
    [[ $candidate == "$service_group" ]] && return 0
  done
  return 1
}

check_safe_ancestors() {
  local label=$1
  local path=$2
  local current
  current=$(dirname -- "$path")
  while :; do
    local mode owner group mode_value access_bits
    if ! read -r mode owner group < <(stat -Lc '%a %u %g' -- "$current" 2>/dev/null); then
      fail "$label.ancestor_stat=unavailable"
      return 1
    fi
    if [[ ! $mode =~ ^[0-7]{3,4}$ || ! $owner =~ ^[0-9]+$ || ! $group =~ ^[0-9]+$ ]]; then
      fail "$label.ancestor_mode=invalid"
      return 1
    fi
    mode_value=$((8#$mode))
    if [[ $owner == "$service_uid" ]]; then
      access_bits=$(((mode_value >> 6) & 7))
    elif group_matches_service "$group"; then
      access_bits=$(((mode_value >> 3) & 7))
    else
      access_bits=$((mode_value & 7))
    fi
    if (( (access_bits & 1) == 0 )); then
      fail "$label.unsearchable_ancestor=$current mode=$mode"
      return 1
    fi
    if ((mode_value & 0022)) && ! ((mode_value & 01000)); then
      fail "$label.unsafe_ancestor=$current mode=$mode"
      return 1
    fi
    [[ $current == / ]] && break
    current=$(dirname -- "$current")
  done
  pass "$label.ancestors_nonwritable_or_sticky=true"
}

file_digest() {
  local path=$1
  local output digest before after
  if ! before=$(stat -Lc '%d:%i:%s:%Y:%Z' -- "$path" 2>/dev/null); then
    return 1
  fi
  if ! output=$(b2sum -- "$path" 2>/dev/null); then
    return 1
  fi
  digest=${output%% *}
  if [[ ! $digest =~ ^[0-9a-f]{128}$ ]]; then
    return 1
  fi
  if ! after=$(stat -Lc '%d:%i:%s:%Y:%Z' -- "$path" 2>/dev/null) || [[ $after != "$before" ]]; then
    return 1
  fi
  printf '%s' "$digest"
}

hsd_cli_digest=
if [[ $hsd_cli_valid == true ]]; then
  check_leaf hsd_cli "$hsd_cli" false true root-or-service
  check_safe_ancestors hsd_cli "$hsd_cli"
  if hsd_cli_digest=$(file_digest "$hsd_cli"); then
    echo "INFO hsd_cli.blake2b512=$hsd_cli_digest"
  else
    fail "hsd_cli.digest=unavailable_or_changed"
  fi
fi
if [[ $hsd_source_valid == true ]]; then
  check_leaf hsd_source "$hsd_source" false true root-or-service
  check_safe_ancestors hsd_source "$hsd_source"
fi
node_runtime_digest=
if [[ $node_runtime_valid == true ]]; then
  check_leaf node_runtime "$node_runtime" false true root-or-service
  check_safe_ancestors node_runtime "$node_runtime"
  if node_runtime_digest=$(file_digest "$node_runtime"); then
    echo "INFO node.blake2b512=$node_runtime_digest"
  else
    fail "node.digest=unavailable_or_changed"
  fi
fi

if [[ $state_dir_valid == true ]]; then
  check_leaf state_dir "$state_dir" true true exact-service
  check_safe_ancestors state_dir "$state_dir"

  available_kib=
  available_inodes=
  if df_output=$(df -Pk -- "$state_dir" 2>/dev/null); then
    available_kib=$(awk 'NR == 2 { print $4 }' <<<"$df_output")
  fi
  if inode_output=$(df -Pi -- "$state_dir" 2>/dev/null); then
    available_inodes=$(awk 'NR == 2 { print $4 }' <<<"$inode_output")
  fi
  if [[ $available_kib =~ ^[0-9]+$ ]] && decimal_ge "$available_kib" "$minimum_free_kib"; then
    pass "disk.available_kib=$available_kib minimum=$minimum_free_kib"
  else
    fail "disk.available_kib=${available_kib:-unknown} minimum=$minimum_free_kib"
  fi
  if [[ $available_inodes =~ ^[0-9]+$ ]] && decimal_ge "$available_inodes" "$minimum_free_inodes"; then
    pass "disk.available_inodes=$available_inodes minimum=$minimum_free_inodes"
  else
    fail "disk.available_inodes=${available_inodes:-unknown} minimum=$minimum_free_inodes"
  fi

  state_device_count=
  if state_device_count=$(find "$state_dir" -type d -printf '%D\n' 2>/dev/null | sort -u | wc -l) &&
    [[ $state_device_count =~ ^[0-9]+$ ]]; then
    if [[ $state_device_count == 1 ]]; then
      pass "state.filesystem_count=1"
    else
      fail "state.filesystem_count=$state_device_count expected=1"
    fi
  else
    fail "state.filesystem_scan=unavailable"
  fi

  state_symlink_count=
  if state_symlink_count=$(find "$state_dir" -type l -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $state_symlink_count =~ ^[0-9]+$ ]]; then
    if [[ $state_symlink_count == 0 ]]; then
      pass "state.symlinks=0"
    else
      fail "state.symlinks=$state_symlink_count"
    fi
  else
    fail "state.symlink_scan=unavailable"
  fi

  state_foreign_owner_count=
  if state_foreign_owner_count=$(find "$state_dir" ! -uid "$service_uid" -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $state_foreign_owner_count =~ ^[0-9]+$ ]]; then
    if [[ $state_foreign_owner_count == 0 ]]; then
      pass "state.foreign_owner_entries=0"
    else
      fail "state.foreign_owner_entries=$state_foreign_owner_count expected_uid=$service_uid"
    fi
  else
    fail "state.owner_scan=unavailable"
  fi

  state_nonprivate_mode_count=
  if state_nonprivate_mode_count=$(find "$state_dir" \( -type f -o -type d \) -perm /077 -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $state_nonprivate_mode_count =~ ^[0-9]+$ ]]; then
    if [[ $state_nonprivate_mode_count == 0 ]]; then
      pass "state.nonprivate_entries=0"
    else
      fail "state.nonprivate_entries=$state_nonprivate_mode_count"
    fi
  else
    fail "state.mode_scan=unavailable"
  fi

  state_special_type_count=
  if state_special_type_count=$(find "$state_dir" ! -type f ! -type d ! -type l -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $state_special_type_count =~ ^[0-9]+$ ]]; then
    if [[ $state_special_type_count == 0 ]]; then
      pass "state.special_entries=0"
    else
      fail "state.special_entries=$state_special_type_count"
    fi
  else
    fail "state.type_scan=unavailable"
  fi

  insecure_secret_count=
  if insecure_secret_count=$(find "$state_dir" \
    \( -name '*.conf' -o -name '*.key' -o -name '*.json' -o -name 'wallet*' \) \
    \( -type l -o \( -type f -perm /077 \) \) -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $insecure_secret_count =~ ^[0-9]+$ ]]; then
    if [[ $insecure_secret_count == 0 ]]; then
      pass "state.sensitive_files_insecure=0"
    else
      fail "state.sensitive_files_insecure=$insecure_secret_count"
    fi
  else
    fail "state.sensitive_file_scan=unavailable"
  fi
fi

git_command=(git --no-optional-locks -c core.fsmonitor=false -c core.untrackedCache=false -c "safe.directory=$hsd_source")
if [[ $hsd_source_valid == true ]]; then
  source_device_count=
  if source_device_count=$(find "$hsd_source" -type d -printf '%D\n' 2>/dev/null | sort -u | wc -l) &&
    [[ $source_device_count =~ ^[0-9]+$ ]]; then
    if [[ $source_device_count == 1 ]]; then
      pass "source.filesystem_count=1"
    else
      fail "source.filesystem_count=$source_device_count expected=1"
    fi
  else
    fail "source.filesystem_scan=unavailable"
  fi

  source_unsafe_mode_count=
  if source_unsafe_mode_count=$(find "$hsd_source" \( -type f -o -type d \) -perm /022 -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $source_unsafe_mode_count =~ ^[0-9]+$ ]]; then
    if [[ $source_unsafe_mode_count == 0 ]]; then
      pass "source.group_or_other_writable_entries=0"
    else
      fail "source.group_or_other_writable_entries=$source_unsafe_mode_count"
    fi
  else
    fail "source.mode_scan=unavailable"
  fi

  source_foreign_owner_count=
  if source_foreign_owner_count=$(find "$hsd_source" ! -uid 0 ! -uid "$service_uid" -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $source_foreign_owner_count =~ ^[0-9]+$ ]]; then
    if [[ $source_foreign_owner_count == 0 ]]; then
      pass "source.foreign_owner_entries=0"
    else
      fail "source.foreign_owner_entries=$source_foreign_owner_count expected_uid=0-or-$service_uid"
    fi
  else
    fail "source.owner_scan=unavailable"
  fi

  source_special_type_count=
  if source_special_type_count=$(find "$hsd_source" ! -type f ! -type d ! -type l -printf '.\n' 2>/dev/null | wc -l) &&
    [[ $source_special_type_count =~ ^[0-9]+$ ]]; then
    if [[ $source_special_type_count == 0 ]]; then
      pass "source.special_entries=0"
    else
      fail "source.special_entries=$source_special_type_count"
    fi
  else
    fail "source.type_scan=unavailable"
  fi

  source_top=
  if source_top=$("${git_command[@]}" -C "$hsd_source" rev-parse --show-toplevel 2>/dev/null) &&
    [[ $source_top == "$hsd_source" ]]; then
    pass "source.repository_root=true"
  else
    fail "source.repository_root=false"
  fi

  actual_commit=
  if actual_commit=$("${git_command[@]}" -C "$hsd_source" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) &&
    [[ $actual_commit == "$expected_commit" ]]; then
    pass "source.commit=$actual_commit"
  else
    fail "source.commit=${actual_commit:-unknown} expected=$expected_commit"
  fi

  worktree_status=
  if worktree_status=$("${git_command[@]}" -C "$hsd_source" status --porcelain=v1 --untracked-files=all 2>/dev/null); then
    if [[ -z $worktree_status ]]; then
      pass "source.worktree_clean=true"
    else
      fail "source.worktree_clean=false"
    fi
  else
    fail "source.worktree_status=unavailable"
  fi

  tree_id=
  if tree_id=$("${git_command[@]}" -C "$hsd_source" rev-parse --verify 'HEAD^{tree}' 2>/dev/null) &&
    [[ $tree_id =~ ^[0-9a-f]{40,64}$ ]]; then
    echo "INFO source.tree_id=$tree_id"
  else
    fail "source.tree_id=unavailable"
  fi
fi

if [[ -n $main_pid && $node_runtime_valid == true ]]; then
  expected_runtime_identity=$(stat -Lc '%d:%i' -- "$node_runtime" 2>/dev/null || true)
  live_runtime_identity=$(stat -Lc '%d:%i' -- "/proc/$main_pid/exe" 2>/dev/null || true)
  if [[ -n $expected_runtime_identity && $live_runtime_identity == "$expected_runtime_identity" ]]; then
    pass "service.node_runtime_identity_matches=true"
  else
    fail "service.node_runtime_identity_matches=false"
  fi
  live_runtime_digest=$(file_digest "/proc/$main_pid/exe" 2>/dev/null || true)
  if [[ -n $node_runtime_digest && $live_runtime_digest == "$node_runtime_digest" ]]; then
    pass "service.node_runtime_digest_matches=true"
  else
    fail "service.node_runtime_digest_matches=false"
  fi
fi

if [[ -n $main_pid && $hsd_source_valid == true && $state_dir_valid == true ]]; then
  expected_launcher=$hsd_source/bin/hsd
  launcher_canonical=$(realpath -e -- "$expected_launcher" 2>/dev/null || true)
  if [[ -f $expected_launcher && $launcher_canonical == "$expected_launcher" ]]; then
    pass "source.hsd_launcher_canonical=true"
  else
    fail "source.hsd_launcher_canonical=false"
  fi

  # hsd overwrites its process title, including the original argv area. Bind
  # the live PID to systemd's retained ExecStart execution record instead of
  # printing or trusting /proc/PID/cmdline. ExecStart is held only in memory so
  # API keys or other command-line values can never reach this report.
  exec_start=$(get_property ExecStart 2>/dev/null || true)
  if [[ $exec_start == "{ path=$expected_launcher ; "* && $exec_start == *" pid=$main_pid ;"* ]]; then
    pass "service.hsd_launcher_binding=systemd_pid_match"
  else
    fail "service.hsd_launcher_binding=false"
  fi
  exec_argv=
  if [[ $exec_start == *' argv[]='*' ; ignore_errors='* ]]; then
    exec_argv=${exec_start#* argv[]=}
    exec_argv=${exec_argv%% ; ignore_errors=*}
  fi
  exec_tokens=()
  read -r -a exec_tokens <<<"$exec_argv"
  prefix_values=()
  for ((argument_index = 0; argument_index < ${#exec_tokens[@]}; argument_index++)); do
    argument=${exec_tokens[$argument_index]}
    case "$argument" in
      --prefix=*) prefix_values+=("${argument#--prefix=}") ;;
      --prefix)
        if ((argument_index + 1 < ${#exec_tokens[@]})); then
          argument_index=$((argument_index + 1))
          prefix_values+=("${exec_tokens[$argument_index]}")
        else
          prefix_values+=("")
        fi
        ;;
    esac
  done
  if [[ $state_dir =~ [[:space:]\\\;] ]]; then
    fail "service.state_dir_binding=unsupported_escaped_path"
  elif ((${#prefix_values[@]} == 1)) && [[ ${prefix_values[0]} == "$state_dir" ]]; then
    pass "service.state_dir_binding=explicit_systemd_match"
  elif ((${#prefix_values[@]} == 0)); then
    fail "service.state_dir_binding=missing_explicit_prefix"
  else
    fail "service.state_dir_binding=ambiguous_or_mismatched"
  fi

  configured_working_directory=$(get_property WorkingDirectory 2>/dev/null || true)
  live_working_directory=$(realpath -e -- "/proc/$main_pid/cwd" 2>/dev/null || true)
  if [[ $configured_working_directory == "$hsd_source" || $configured_working_directory == "$hsd_source/bin" ]] &&
    [[ $live_working_directory == "$configured_working_directory" ]]; then
    pass "service.working_directory_binding=true"
  else
    fail "service.working_directory_binding=false"
  fi
fi

no_new_privileges=$(get_property NoNewPrivileges 2>/dev/null || true)
if [[ $no_new_privileges == yes ]]; then
  pass "service.no_new_privileges=true"
else
  fail "service.no_new_privileges=false"
fi

service_umask=$(get_property UMask 2>/dev/null || true)
if [[ $service_umask =~ ^00?77$ ]]; then
  pass "service.umask=0077"
else
  fail "service.umask_not_0077=true"
fi

restart_policy=$(get_property Restart 2>/dev/null || true)
if [[ -z $restart_policy ]]; then
  fail "service.restart_policy=unknown"
elif [[ $restart_policy == always ]]; then
  fail "service.restart_always=true"
else
  pass "service.restart_policy=$restart_policy"
fi

restart_delay=$(get_property RestartUSec 2>/dev/null || true)
duration_microseconds() {
  local rendered
  rendered=$(systemd-analyze timespan -- "$1" 2>/dev/null) || return 1
  awk '$2 ~ /^[0-9]+$/ { print $2; exit }' <<<"$rendered"
}

restart_delay_usec=$(duration_microseconds "$restart_delay" 2>/dev/null || true)
minimum_restart_delay_usec=${minimum_restart_delay_sec}000000
if [[ $restart_delay_usec =~ ^[0-9]+$ ]] && decimal_ge "$restart_delay_usec" "$minimum_restart_delay_usec"; then
  pass "service.restart_delay=$restart_delay minimum_sec=$minimum_restart_delay_sec"
else
  fail "service.restart_delay=${restart_delay:-unknown} minimum_sec=$minimum_restart_delay_sec"
fi

start_limit_burst=$(get_property StartLimitBurst 2>/dev/null || true)
if [[ $start_limit_burst =~ ^[0-9]+$ ]] && decimal_ge "$start_limit_burst" 1 &&
  decimal_ge "$maximum_start_limit_burst" "$start_limit_burst"; then
  pass "service.start_limit_burst=$start_limit_burst maximum=$maximum_start_limit_burst"
else
  fail "service.start_limit_burst=${start_limit_burst:-unknown} maximum=$maximum_start_limit_burst"
fi

start_limit_interval=$(get_property StartLimitIntervalUSec 2>/dev/null || true)
start_limit_interval_usec=$(duration_microseconds "$start_limit_interval" 2>/dev/null || true)
minimum_start_limit_interval_usec=${minimum_start_limit_interval_sec}000000
if [[ $start_limit_interval_usec =~ ^[0-9]+$ ]] &&
  decimal_ge "$start_limit_interval_usec" "$minimum_start_limit_interval_usec"; then
  pass "service.start_limit_interval=$start_limit_interval minimum_sec=$minimum_start_limit_interval_sec"
else
  fail "service.start_limit_interval=${start_limit_interval:-unknown} minimum_sec=$minimum_start_limit_interval_sec"
fi

restart_count=$(get_property NRestarts 2>/dev/null || true)
if [[ $restart_count =~ ^[0-9]+$ ]]; then
  if [[ $restart_count == 0 ]]; then
    pass "service.current_restart_count=0"
  else
    warn "service.current_restart_count=$restart_count"
  fi
else
  fail "service.current_restart_count=unknown"
fi

if [[ -n $main_pid ]]; then
  final_properties=$("${systemctl_command[@]}" show --property=ActiveState,MainPID --no-pager -- "$service_name" 2>/dev/null || true)
  final_pid=$(awk -F= '$1 == "MainPID" { print $2 }' <<<"$final_properties")
  final_active=$(awk -F= '$1 == "ActiveState" { print $2 }' <<<"$final_properties")
  final_start_time=$(proc_start_time "$main_pid" 2>/dev/null || true)
  if [[ $final_pid == "$main_pid" && $final_active == active && -n $initial_start_time && $final_start_time == "$initial_start_time" ]]; then
    pass "service.live_identity_stable=true"
  else
    fail "service.live_identity_stable=false"
  fi
fi

echo "SUMMARY failures=$failures warnings=$warnings"
((failures == 0))
