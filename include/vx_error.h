/* vx_error.h — status-code helpers for the VxCloud worker ABI. */
#ifndef VX_ERROR_H
#define VX_ERROR_H

#include "worker_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Stable, human-readable name for a vx_status_t ("VX_ERR_CGROUP"). */
const char *vx_status_name(int status);

/* One-line explanation suitable for an operator log line. */
const char *vx_status_str(int status);

/* Map an errno value onto the closest vx_status_t.  Used at every syscall
 * boundary so callers never have to look at errno themselves. */
vx_status_t vx_status_from_errno(int err);

/* Name of a vx_task_state_t, e.g. "COMPLETED". */
const char *vx_state_str(int state);

/* Name of a vx_engine_type_t, e.g. "ion". */
const char *vx_engine_str(int engine);

#ifdef __cplusplus
}
#endif

#endif /* VX_ERROR_H */
