export type GuestErrorCode =
    | "VM_NOT_FOUND"
    | "VM_NOT_RUNNING"
    | "AUTH_FAILED"
    | "GUEST_ADDITIONS_NOT_READY"
    | "GUEST_CONTROL_UNAVAILABLE"
    | "PERMISSION_DENIED"
    | "WORKDIR_NOT_FOUND"
    | "PATH_SYNTAX_ERROR"
    | "ARG_QUOTING_ERROR"
    | "UNC_PATH_ERROR"
    | "TIMEOUT"
    | "INTERNAL_ERROR";

export function mapGuestError(error: any): GuestErrorCode {
    const msg = `${error?.message || ""} ${error?.stderr || ""}`.toLowerCase();
    if (error?.timedOut || msg.includes("timed out")) return "TIMEOUT";
    if (msg.includes("working directory not found") || msg.includes("workdir_not_found")) return "WORKDIR_NOT_FOUND";
    if (msg.includes("unc") && msg.includes("path")) return "UNC_PATH_ERROR";
    if (msg.includes("filename, directory name, or volume label syntax is incorrect")) return "PATH_SYNTAX_ERROR";
    if (msg.includes("invalid argument") && msg.includes("quote")) return "ARG_QUOTING_ERROR";
    if (msg.includes("not found")) return "VM_NOT_FOUND";
    if (msg.includes("must be 'running'") || msg.includes("not running")) return "VM_NOT_RUNNING";
    if (msg.includes("access denied") || msg.includes("permission denied")) return "PERMISSION_DENIED";
    if (msg.includes("logon failure") || msg.includes("invalid username") || msg.includes("invalid password") || msg.includes("authentication")) {
        return "AUTH_FAILED";
    }
    if (msg.includes("guest additions") || msg.includes("vbox_e_iprt_error")) return "GUEST_ADDITIONS_NOT_READY";
    if (msg.includes("guest control") || msg.includes("vbox_e_vm_error")) return "GUEST_CONTROL_UNAVAILABLE";
    return "INTERNAL_ERROR";
}
