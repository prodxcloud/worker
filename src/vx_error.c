#include "vx_error.h"

#include <errno.h>

const char *vx_status_name(int status) {
    switch (status) {
    case VX_OK:
        return "VX_OK";
    case VX_ERR_INVALID_ARG:
        return "VX_ERR_INVALID_ARG";
    case VX_ERR_BAD_MAGIC:
        return "VX_ERR_BAD_MAGIC";
    case VX_ERR_PAYLOAD_TOO_LARGE:
        return "VX_ERR_PAYLOAD_TOO_LARGE";
    case VX_ERR_NO_MEMORY:
        return "VX_ERR_NO_MEMORY";
    case VX_ERR_SHM:
        return "VX_ERR_SHM";
    case VX_ERR_RING_FULL:
        return "VX_ERR_RING_FULL";
    case VX_ERR_RING_EMPTY:
        return "VX_ERR_RING_EMPTY";
    case VX_ERR_NAMESPACE:
        return "VX_ERR_NAMESPACE";
    case VX_ERR_CGROUP:
        return "VX_ERR_CGROUP";
    case VX_ERR_UIDMAP:
        return "VX_ERR_UIDMAP";
    case VX_ERR_SPAWN:
        return "VX_ERR_SPAWN";
    case VX_ERR_TIMEOUT:
        return "VX_ERR_TIMEOUT";
    case VX_ERR_UNSUPPORTED:
        return "VX_ERR_UNSUPPORTED";
    default:
        return "VX_ERR_UNKNOWN";
    }
}

const char *vx_status_str(int status) {
    switch (status) {
    case VX_OK:
        return "ok";
    case VX_ERR_INVALID_ARG:
        return "invalid argument";
    case VX_ERR_BAD_MAGIC:
        return "bad ABI magic (incompatible host runtime)";
    case VX_ERR_PAYLOAD_TOO_LARGE:
        return "payload exceeds 16 MiB ABI limit";
    case VX_ERR_NO_MEMORY:
        return "out of memory";
    case VX_ERR_SHM:
        return "shared memory operation failed";
    case VX_ERR_RING_FULL:
        return "ring buffer full";
    case VX_ERR_RING_EMPTY:
        return "ring buffer empty";
    case VX_ERR_NAMESPACE:
        return "namespace creation denied by kernel";
    case VX_ERR_CGROUP:
        return "cgroup v2 operation failed";
    case VX_ERR_UIDMAP:
        return "uid_map/gid_map write denied";
    case VX_ERR_SPAWN:
        return "clone/exec failed";
    case VX_ERR_TIMEOUT:
        return "deadline exceeded";
    case VX_ERR_UNSUPPORTED:
        return "kernel lacks a required facility";
    default:
        return "unknown error";
    }
}

vx_status_t vx_status_from_errno(int err) {
    switch (err) {
    case 0:
        return VX_OK;
    case ENOMEM:
        return VX_ERR_NO_MEMORY;
    case EINVAL:
        return VX_ERR_INVALID_ARG;
    case ETIMEDOUT:
        return VX_ERR_TIMEOUT;
    case ENOSYS:
        return VX_ERR_UNSUPPORTED;
    case EPERM:
    case EACCES:
        return VX_ERR_NAMESPACE;
    default:
        return VX_ERR_SPAWN;
    }
}

const char *vx_state_str(int state) {
    switch (state) {
    case VX_STATE_PENDING:
        return "PENDING";
    case VX_STATE_RUNNING:
        return "RUNNING";
    case VX_STATE_COMPLETED:
        return "COMPLETED";
    case VX_STATE_FAILED:
        return "FAILED";
    case VX_STATE_KILLED_OOM:
        return "KILLED_OOM";
    case VX_STATE_KILLED_TIMEOUT:
        return "KILLED_TIMEOUT";
    case VX_STATE_KILLED_SIGNAL:
        return "KILLED_SIGNAL";
    default:
        return "UNKNOWN";
    }
}

const char *vx_engine_str(int engine) {
    switch (engine) {
    case ENGINE_ION:
        return "ion";
    case ENGINE_IRON:
        return "iron";
    default:
        return "unknown";
    }
}
