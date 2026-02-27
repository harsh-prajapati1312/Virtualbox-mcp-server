import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from 'fs';
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { logger, setLogLevel, GitHubAssetResolver } from "@virtualbox-mcp/shared-utils";
import { VagrantClient } from "@virtualbox-mcp/vagrant-client";
import { SyncManager, BackgroundTaskManager, OperationTracker, GuardrailsManager } from "@virtualbox-mcp/sync-engine";
import { handleToolError } from "./error-handler.js";
import { SequentialThinkingManager } from "./sequential-thinking.js";
import { TOOLS, CreateVMSchema, GetVMStatusSchema, ResizeVMResourcesSchema } from "./tools.js";
import { UrlGuard } from "./utils/UrlGuard.js";
import { GuestExecutionEngine } from "./guest-execution-engine.js";
import { mapGuestError } from "./error-mapper.js";
import { stableStringify, utcNow } from "./json-utils.js";
import { normalizeVmState } from "./vm-state.js";
import { VmStateCache } from "./vm-state-cache.js";
import { ExecGuestResponseSchema, VmStatusResponseSchema, validateResponse } from "./response-schemas.js";

// Main Server Class
export class McpServer {
    private server: Server;
    private vagrant?: VagrantClient;
    private syncManager?: SyncManager;
    private taskManager?: BackgroundTaskManager;
    private operationTracker?: OperationTracker;
    private guardrails?: GuardrailsManager;
    private thinkingManager?: SequentialThinkingManager;
    private execEngine?: GuestExecutionEngine;
    private vmStateCache = new VmStateCache(3000);
    private initializationPromise: Promise<void> | null = null;

    constructor() {
        this.server = new Server(
            {
                name: "virtualbox-mcp-server",
                version: "1.0.2",
            },
            {
                capabilities: {
                    tools: {},
                },
            }
        );
        this.setupHandlers();
    }

    private async ensureInitialized() {
        if (this.initializationPromise) return this.initializationPromise;

        this.initializationPromise = (async () => {
            logger.info("[BOOTSTRAP] Initializing managers...");
            this.vagrant = new VagrantClient();
            this.syncManager = new SyncManager(this.vagrant);
            this.taskManager = new BackgroundTaskManager(this.vagrant);
            this.operationTracker = new OperationTracker(this.vagrant);
            this.guardrails = new GuardrailsManager(this.vagrant);
            this.thinkingManager = new SequentialThinkingManager();
            this.execEngine = new GuestExecutionEngine(this.vagrant);
            logger.info("[BOOTSTRAP] Managers ready.");
        })();

        return this.initializationPromise;
    }

    private setupHandlers() {
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            return { tools: TOOLS };
        });

        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;

            // Zero-Trust URL Validation
            try {
                await UrlGuard.validate(args);
            } catch (error: any) {
                return {
                    content: [{ type: "text", text: `⛔ SAFETY INTERVENTION: ${error.message}` }],
                    isError: true,
                };
            }

            await this.ensureInitialized();
            const result = await this.executeTool(name, args);

            // Global Interceptor for Screenshot (if applicable)
            const vmName = (args as any)?.vm_name;
            if (vmName && typeof vmName === 'string' && this.vagrant) {
                try {
                    const status = await this.vagrant.getVMStatus(vmName);
                    if (status === 'running') {
                        // takeScreenshot implementation should be in VagrantClient
                        // For now we'll check if it exists or skip to avoid crash
                        if ((this.vagrant as any).takeScreenshot) {
                            const screenshotPath = await (this.vagrant as any).takeScreenshot(vmName);
                            if (fs.existsSync(screenshotPath)) {
                                const imageBuffer = fs.readFileSync(screenshotPath);
                                result.content = result.content || [];
                                result.content.push({
                                    type: "image",
                                    data: imageBuffer.toString('base64'),
                                    mimeType: "image/png"
                                } as any);
                                fs.unlinkSync(screenshotPath);
                            }
                        }
                    }
                } catch (err) { }
            }
            return result;
        });
    }

    private jsonResponse(payload: Record<string, any>) {
        const withTimestamp = payload.timestamp_utc ? payload : { ...payload, timestamp_utc: utcNow() };
        return { content: [{ type: "text", text: stableStringify(withTimestamp) }] };
    }

    private quoteForShell(value: string): string {
        return value.replace(/'/g, "'\\''");
    }

    private async executeTool(name: string, args: any) {
        try {
            if (name === "create_vm" || name === "create_dev_vm") {
                const { name: vmName, box, gui_mode } = CreateVMSchema.parse(args);
                await this.vagrant!.createVM(vmName, box, gui_mode);
                return { content: [{ type: "text", text: `VM ${vmName} creation initiated.` }] };
            }

            if (name === "get_vm_status") {
                const { name: vmName } = GetVMStatusSchema.parse(args);
                const snapshot = this.vmStateCache.getSnapshot();
                const cached = this.vmStateCache.getCachedState(vmName);
                const status = cached ?? this.vmStateCache.setState(vmName, await this.vagrant!.getVMStatus(vmName));
                const payload = validateResponse(VmStatusResponseSchema, {
                    name: vmName,
                    state: status,
                    observed_at_utc: snapshot?.observed_at_utc ?? utcNow()
                });
                return this.jsonResponse(payload as any);
            }

            if (name === "list_vms") {
                const vms = await this.vagrant!.listVMs();
                const snapshot = this.vmStateCache.setSnapshot(vms.map(v => ({ ...v, state: v.state })));
                return this.jsonResponse(snapshot as any);
            }

            if (name === "destroy_vm") {
                const { name: vmName } = z.object({ name: z.string() }).parse(args);
                await this.vagrant!.destroyVM(vmName);
                return { content: [{ type: "text", text: `VM ${vmName} destroyed.` }] };
            }

            if (name === "exec_command") {
                const schema = z.object({
                    vm_name: z.string(),
                    command: z.string(),
                    timeout: z.number().optional(),
                    username: z.string().optional(),
                    password: z.string().optional(),
                    use_console_injection: z.boolean().optional()
                });
                const { vm_name, command, timeout, username, password, use_console_injection } = schema.parse(args);
                const osFamily = await this.vagrant!.getGuestOSFamily(vm_name);
                const strictExecV2 = process.env.MCP_STRICT_EXEC_V2 !== "0";
                if (strictExecV2) {
                    const result = await this.execEngine!.execute({
                        vm_name,
                        username,
                        password,
                        timeout_ms: timeout,
                        capture_output: true,
                        allow_fallback: !!use_console_injection,
                        shell_mode: osFamily === "windows" ? "windows" : "linux",
                        command
                    });
                    const validated = validateResponse(ExecGuestResponseSchema, result);
                    return this.jsonResponse(validated as any);
                }

                const legacy = await this.vagrant!.executeCommand(vm_name, command, { timeout, username, password });
                return this.jsonResponse({
                    ok: legacy.exitCode === 0,
                    exit_code: legacy.exitCode,
                    stdout: legacy.stdout || "",
                    stderr: legacy.stderr || "",
                    vm_state: normalizeVmState(await this.vagrant!.getVMStatus(vm_name)),
                    guest_os_family: osFamily
                });
            }

            if (name === "exec_guest_command") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional(),
                    program: z.string().optional(),
                    args: z.array(z.string()).optional(),
                    working_dir: z.string().optional(),
                    env: z.record(z.string()).optional(),
                    timeout_ms: z.number().optional(),
                    run_as_admin: z.boolean().optional(),
                    capture_output: z.boolean().optional(),
                    strict_paths: z.boolean().optional(),
                    allow_workdir_fallback: z.boolean().optional(),
                    shell_mode: z.enum(["windows", "linux", "none", "auto"]).optional()
                });
                const input = schema.parse(args);
                const strictExecV2 = process.env.MCP_STRICT_EXEC_V2 !== "0";
                if (!strictExecV2) {
                    const legacy = await this.execEngine!.execute({ ...input, strict_paths: false, allow_workdir_fallback: true } as any);
                    const validatedLegacy = validateResponse(ExecGuestResponseSchema, legacy);
                    return this.jsonResponse(validatedLegacy as any);
                }
                const result = await this.execEngine!.execute({ ...input, strict_paths: input.strict_paths ?? true, allow_workdir_fallback: input.allow_workdir_fallback ?? false } as any);
                const validated = validateResponse(ExecGuestResponseSchema, result);
                return this.jsonResponse(validated as any);
            }

            if (name === "exec_guest_command_v2") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional(),
                    program: z.string().optional(),
                    args: z.array(z.string()).optional(),
                    working_dir: z.string().optional(),
                    env: z.record(z.string()).optional(),
                    timeout_ms: z.number().optional(),
                    run_as_admin: z.boolean().optional(),
                    capture_output: z.boolean().optional(),
                    strict_paths: z.boolean().default(true),
                    allow_workdir_fallback: z.boolean().default(false),
                    shell_mode: z.enum(["windows", "linux", "none", "auto"]).optional()
                });
                const input = schema.parse(args);
                const result = await this.execEngine!.execute(input as any);
                const validated = validateResponse(ExecGuestResponseSchema, result);
                return this.jsonResponse(validated as any);
            }

            if (name === "resolve_guest_path") {
                const schema = z.object({
                    vm_name: z.string(),
                    path: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const input = schema.parse(args);
                const result = await this.execEngine!.resolveGuestPath(input);
                return this.jsonResponse(result as any);
            }

            if (name === "test_guest_auth") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string(),
                    password: z.string(),
                    timeout_ms: z.number().default(30000)
                });
                const { vm_name, username, password, timeout_ms } = schema.parse(args);
                const phaseTimings: Record<string, number> = {};
                let phaseStart = Date.now();
                const vmState = normalizeVmState(await this.vagrant!.getVMStatus(vm_name));
                phaseTimings.vm_state_ms = Date.now() - phaseStart;

                if (vmState === "powered_off" || vmState === "saved" || vmState === "paused" || vmState === "unknown") {
                    return this.jsonResponse({
                        ok: false,
                        error_code: "VM_NOT_RUNNING",
                        message: `VM '${vm_name}' is not running.`,
                        details: {
                            vm_state: vmState,
                            guest_additions: "unknown",
                            guest_control: "not_ready",
                            auth: "unknown"
                        },
                        phase_timings_ms: phaseTimings
                    });
                }

                try {
                    phaseStart = Date.now();
                    const health = await this.vagrant!.getGuestToolsHealth(vm_name);
                    phaseTimings.guest_tools_ms = Date.now() - phaseStart;
                    if (!health.guestControlReady) {
                        return this.jsonResponse({
                            ok: false,
                            error_code: "GUEST_CONTROL_UNAVAILABLE",
                            message: "Guest control is not ready.",
                            details: {
                                vm_state: vmState,
                                guest_additions: health.guestAdditionsVersion === "unknown" ? "unknown" : "installed",
                                guest_control: "not_ready",
                                auth: "unknown"
                            },
                            phase_timings_ms: phaseTimings
                        });
                    }

                    const osFamily = await this.vagrant!.getGuestOSFamily(vm_name);
                    phaseStart = Date.now();
                    const probe = await this.vagrant!.executeGuestProgram(
                        vm_name,
                        osFamily === "windows" ? "cmd.exe" : "/bin/sh",
                        osFamily === "windows" ? ["/c", "echo", "AUTH_OK"] : ["-lc", "echo AUTH_OK"],
                        {
                        username,
                        password,
                        timeout: timeout_ms,
                        captureOutput: true
                    });
                    phaseTimings.auth_probe_ms = Date.now() - phaseStart;
                    if (probe.exitCode === 0) {
                        return this.jsonResponse({
                            ok: true,
                            error_code: null,
                            message: "Authentication and guest control are ready.",
                            details: {
                                vm_state: vmState,
                                guest_additions: health.guestAdditionsVersion === "unknown" ? "unknown" : "installed",
                                guest_control: health.guestControlReady ? "ready" : "not_ready",
                                auth: "success"
                            },
                            phase_timings_ms: phaseTimings
                        });
                    }

                    const code = mapGuestError(probe);
                    return this.jsonResponse({
                        ok: false,
                        error_code: code,
                        message: probe.stderr || "Guest auth probe failed.",
                        details: {
                            vm_state: vmState,
                            guest_additions: health.guestAdditionsVersion === "unknown" ? "unknown" : "installed",
                            guest_control: health.guestControlReady ? "ready" : "not_ready",
                            auth: code === "AUTH_FAILED" ? "failed" : "unknown"
                        },
                        phase_timings_ms: phaseTimings
                    });
                } catch (error: any) {
                    const code = mapGuestError(error);
                    return this.jsonResponse({
                        ok: false,
                        error_code: code,
                        message: error.message || "Guest auth test failed.",
                        details: {
                            vm_state: vmState,
                            guest_additions: "unknown",
                            guest_control: "not_ready",
                            auth: code === "AUTH_FAILED" ? "failed" : "unknown"
                        },
                        phase_timings_ms: phaseTimings
                    });
                }
            }

            if (name === "ensure_vm_running") {
                const schema = z.object({
                    vm_name: z.string(),
                    display_mode: z.enum(["headless", "gui", "unchanged"]).default("unchanged"),
                    timeout_ms: z.number().default(180000)
                });
                const { vm_name, display_mode, timeout_ms } = schema.parse(args);
                const startedMs = Date.now();
                const previousState = this.vmStateCache.setState(vm_name, await this.vagrant!.getVMStatus(vm_name));

                if (display_mode !== "unchanged") {
                    await this.vagrant!.setDisplayMode(vm_name, display_mode);
                }

                if (previousState !== "running") {
                    await this.vagrant!.startVM(vm_name);
                }

                let currentState = this.vmStateCache.setState(vm_name, await this.vagrant!.getVMStatus(vm_name));
                while (currentState !== "running" && Date.now() - startedMs < timeout_ms) {
                    await new Promise(r => setTimeout(r, 2000));
                    currentState = this.vmStateCache.setState(vm_name, await this.vagrant!.getVMStatus(vm_name));
                }

                return this.jsonResponse({
                    ok: currentState === "running",
                    previous_state: previousState,
                    current_state: currentState,
                    elapsed_ms: Date.now() - startedMs
                });
            }

            if (name === "upload_file") {
                const schema = z.object({
                    vm_name: z.string(),
                    source: z.string(),
                    destination: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, source, destination, username, password } = schema.parse(args);
                await this.vagrant!.uploadFile(vm_name, source, destination, { username, password });
                return { content: [{ type: "text", text: `File uploaded to ${destination} on ${vm_name}` }] };
            }

            if (name === "search_files") {
                const schema = z.object({ vm_name: z.string(), query: z.string(), path: z.string().optional() });
                const { vm_name, query, path } = schema.parse(args);
                const result = await this.vagrant!.executeCommand(vm_name, `grep -rnI "${query}" "${path || "/vagrant"}"`);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "tail_vm_log") {
                const schema = z.object({
                    vm_name: z.string(),
                    path: z.string(),
                    lines: z.number().default(50),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, path: logPath, lines, username, password } = schema.parse(args);
                const result = await this.vagrant!.tailFile(vm_name, logPath, lines, { username, password });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "list_processes") {
                const schema = z.object({
                    vm_name: z.string(),
                    filter: z.string().optional(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, filter, username, password } = schema.parse(args);
                const result = await this.vagrant!.listProcesses(vm_name, filter, { username, password });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "check_vm_port") {
                const schema = z.object({
                    vm_name: z.string(),
                    guest_port: z.number(),
                    host_port: z.number().optional(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, guest_port, host_port, username, password } = schema.parse(args);
                const vmResult = await this.vagrant!.checkPortInVM(vm_name, guest_port, { username, password });
                let hostResult = null;
                if (host_port) hostResult = await this.vagrant!.checkHostPort(host_port);
                return this.jsonResponse({ vm_port: vmResult, host_port: hostResult });
            }

            if (name === "guest_file_exists") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string(),
                    password: z.string(),
                    path: z.string()
                });
                const { vm_name, username, password, path } = schema.parse(args);
                const os = await this.vagrant!.getGuestOSFamily(vm_name);
                const cmd = os === "windows"
                    ? { program: "cmd.exe", args: ["/c", `if exist "${path}" (echo 1) else (echo 0)`] }
                    : { program: "/bin/sh", args: ["-lc", `[ -e '${this.quoteForShell(path)}' ] && echo 1 || echo 0`] };
                const out = await this.execEngine!.execute({ vm_name, username, password, program: cmd.program, args: cmd.args, shell_mode: "none", capture_output: true });
                return this.jsonResponse({ ok: out.ok, exists: (out.stdout || "").trim() === "1" });
            }

            if (name === "guest_list_dir") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string(),
                    password: z.string(),
                    path: z.string()
                });
                const { vm_name, username, password, path } = schema.parse(args);
                const os = await this.vagrant!.getGuestOSFamily(vm_name);
                const cmd = os === "windows"
                    ? { program: "cmd.exe", args: ["/c", `dir /b "${path}"`] }
                    : { program: "/bin/sh", args: ["-lc", `ls -1 '${this.quoteForShell(path)}'`] };
                const out = await this.execEngine!.execute({ vm_name, username, password, program: cmd.program, args: cmd.args, shell_mode: "none", capture_output: true });
                if (!out.ok) return this.jsonResponse({ ok: false, error_code: mapGuestError(out), message: out.stderr });
                return this.jsonResponse({ ok: true, entries: out.stdout.split(/\r?\n/).filter(Boolean) });
            }

            if (name === "guest_read_file") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string(),
                    password: z.string(),
                    path: z.string()
                });
                const { vm_name, username, password, path } = schema.parse(args);
                const os = await this.vagrant!.getGuestOSFamily(vm_name);
                const cmd = os === "windows"
                    ? { program: "cmd.exe", args: ["/c", `type "${path}"`] }
                    : { program: "/bin/sh", args: ["-lc", `cat '${this.quoteForShell(path)}'`] };
                const out = await this.execEngine!.execute({ vm_name, username, password, program: cmd.program, args: cmd.args, shell_mode: "none", capture_output: true });
                if (!out.ok) return this.jsonResponse({ ok: false, error_code: mapGuestError(out), message: out.stderr });
                return this.jsonResponse({ ok: true, content: out.stdout });
            }

            if (name === "guest_write_file") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string(),
                    password: z.string(),
                    path: z.string(),
                    content: z.string()
                });
                const { vm_name, username, password, path, content } = schema.parse(args);
                const os = await this.vagrant!.getGuestOSFamily(vm_name);
                const cmd = os === "windows"
                    ? { program: "powershell.exe", args: ["-NoProfile", "-Command", `[IO.File]::WriteAllText('${path.replace(/'/g, "''")}', @'\n${content}\n'@)`] }
                    : { program: "/bin/sh", args: ["-lc", `cat > '${this.quoteForShell(path)}' <<'EOF'\n${content}\nEOF`] };
                const out = await this.execEngine!.execute({ vm_name, username, password, program: cmd.program, args: cmd.args, shell_mode: "none", capture_output: true });
                if (!out.ok) return this.jsonResponse({ ok: false, error_code: mapGuestError(out), message: out.stderr });
                return this.jsonResponse({ ok: true, bytes_written: Buffer.byteLength(content, "utf8") });
            }

            if (name === "guest_hash_file") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string(),
                    password: z.string(),
                    path: z.string()
                });
                const { vm_name, username, password, path } = schema.parse(args);
                const os = await this.vagrant!.getGuestOSFamily(vm_name);
                const cmd = os === "windows"
                    ? { program: "powershell.exe", args: ["-NoProfile", "-Command", `$f='${path.replace(/'/g, "''")}'; if(Test-Path $f){ $h=(Get-FileHash -Algorithm SHA256 $f).Hash.ToLower(); $s=(Get-Item $f).Length; Write-Output \"$h $s\" } else { exit 2 }`] }
                    : { program: "/bin/sh", args: ["-lc", `h=$(sha256sum '${this.quoteForShell(path)}' | awk '{print $1}'); s=$(stat -c %s '${this.quoteForShell(path)}'); echo \"$h $s\"`] };
                const out = await this.execEngine!.execute({ vm_name, username, password, program: cmd.program, args: cmd.args, shell_mode: "none", capture_output: true });
                if (!out.ok) return this.jsonResponse({ ok: false, error_code: mapGuestError(out), message: out.stderr });
                const parts = out.stdout.trim().split(/\s+/);
                const sha256 = parts[0] || "";
                const sizeBytes = parseInt(parts[1] || "0", 10) || 0;
                return this.jsonResponse({ ok: true, sha256, size_bytes: sizeBytes });
            }

            if (name === "get_vm_network_info") {
                const { vm_name } = z.object({ vm_name: z.string() }).parse(args);
                const info = await this.vagrant!.getVMNetworkInfo(vm_name);
                return this.jsonResponse({
                    ok: true,
                    vm_name: info.vmName,
                    guest_ips: info.guestIps,
                    adapters: info.adapters,
                    forwarded_ports: info.forwardedPorts
                });
            }

            if (name === "get_guest_tools_health") {
                const { vm_name } = z.object({ vm_name: z.string() }).parse(args);
                const health = await this.vagrant!.getGuestToolsHealth(vm_name);
                return this.jsonResponse({
                    ok: true,
                    vm_name: health.vmName,
                    guest_additions_version: health.guestAdditionsVersion,
                    vboxservice_status: health.vboxserviceStatus,
                    guest_control_ready: health.guestControlReady
                });
            }

            if (name === "sync_status") {
                const schema = z.object({ vm_name: z.string() });
                const { vm_name } = schema.parse(args);
                const status = await this.syncManager!.getSyncStatus(vm_name);
                return { content: [{ type: "text", text: JSON.stringify(status || { status: 'idle' }, null, 2) }] };
            }

            if (name === "resolve_conflict") {
                const schema = z.object({
                    vm_name: z.string(),
                    file_path: z.string(),
                    resolution: z.enum(["use_host", "use_vm"])
                });
                const { vm_name, file_path, resolution } = schema.parse(args);
                await this.syncManager!.resolveConflict(vm_name, file_path, resolution);
                return { content: [{ type: "text", text: `Conflict for ${file_path} resolved using ${resolution}` }] };
            }

            if (name === "ensure_dev_vm") {
                const schema = z.object({ name: z.string(), project_path: z.string() });
                const { name: vmName, project_path } = schema.parse(args);
                const status = await this.vagrant!.getVMStatus(vmName);
                if (status === 'not_created') {
                    await this.vagrant!.createVMAdvanced(vmName, project_path, {});
                } else if (status !== 'running') {
                    await this.vagrant!.startVM(vmName);
                }
                return { content: [{ type: "text", text: `VM ${vmName} is ready.` }] };
            }

            if (name === "exec_with_sync") {
                const schema = z.object({
                    vm_name: z.string(),
                    command: z.string(),
                    sync_before: z.boolean().default(true),
                    sync_after: z.boolean().default(true),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, command, sync_before, sync_after, username, password } = schema.parse(args);
                if (sync_before) await this.syncManager!.syncToVMFull(vm_name);
                const result = await this.vagrant!.executeCommand(vm_name, command, { username, password });
                if (sync_after) await this.syncManager!.syncFromVMFull(vm_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "run_background_task") {
                const schema = z.object({
                    vm_name: z.string(),
                    command: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, command, username, password } = schema.parse(args);
                const taskResult = await this.taskManager!.startTask(vm_name, command, undefined, { username, password });
                return { content: [{ type: "text", text: JSON.stringify(taskResult, null, 2) }] };
            }

            if (name === "get_task_output") {
                const schema = z.object({
                    vm_name: z.string(),
                    task_id: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, task_id, username, password } = schema.parse(args);
                const output = await this.taskManager!.getTaskOutput(task_id);
                return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }] };
            }

            if (name === "sync_to_vm") {
                const schema = z.object({ vm_name: z.string() });
                const { vm_name } = schema.parse(args);
                const result = await this.syncManager!.syncToVMFull(vm_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "sync_from_vm") {
                const schema = z.object({ vm_name: z.string() });
                const { vm_name } = schema.parse(args);
                const result = await this.syncManager!.syncFromVMFull(vm_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "setup_dev_environment") {
                const schema = z.object({ vm_name: z.string(), runtimes: z.array(z.string()) });
                const { vm_name, runtimes } = schema.parse(args);
                for (const runtime of runtimes) {
                    const cmd = this.getInstallRuntimeCommand(runtime);
                    if (cmd) await this.vagrant!.executeCommand(vm_name, cmd);
                }
                return { content: [{ type: "text", text: `Environment setup completed for ${vm_name}` }] };
            }

            if (name === "install_dev_tools") {
                const schema = z.object({ vm_name: z.string(), tools: z.array(z.string()) });
                const { vm_name, tools } = schema.parse(args);
                for (const tool of tools) {
                    const cmd = this.getInstallToolCommand(tool);
                    await this.vagrant!.executeCommand(vm_name, cmd);
                }
                return { content: [{ type: "text", text: `Tools installation completed for ${vm_name}` }] };
            }

            if (name === "configure_shell") {
                const schema = z.object({ vm_name: z.string(), secrets: z.record(z.string()).optional() });
                const { vm_name, secrets } = schema.parse(args);
                if (secrets) {
                    let config = "";
                    for (const [key, value] of Object.entries(secrets)) {
                        config += `export ${key}="${value}"\n`;
                    }
                    await this.vagrant!.executeCommand(vm_name, `echo '${config}' >> ~/.profile`);
                }
                return { content: [{ type: "text", text: `Shell configured for ${vm_name}` }] };
            }

            if (name === "grep_log_stream") {
                const schema = z.object({
                    vm_name: z.string(),
                    path: z.string(),
                    pattern: z.string(),
                    limit: z.number().default(100),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, path: logPath, pattern, limit, username, password } = schema.parse(args);
                const result = await this.vagrant!.grepLog(vm_name, logPath, pattern, limit, false, { username, password });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "snapshot_save") {
                const schema = z.object({ vm_name: z.string(), snapshot_name: z.string() });
                const { vm_name, snapshot_name } = schema.parse(args);
                const result = await this.vagrant!.snapshotSave(vm_name, snapshot_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "snapshot_restore") {
                const schema = z.object({ vm_name: z.string(), snapshot_name: z.string() });
                const { vm_name, snapshot_name } = schema.parse(args);
                const result = await this.vagrant!.snapshotRestore(vm_name, snapshot_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "snapshot_list") {
                const schema = z.object({ vm_name: z.string() });
                const { vm_name } = schema.parse(args);
                const result = await this.vagrant!.snapshotList(vm_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "snapshot_delete") {
                const schema = z.object({ vm_name: z.string(), snapshot_name: z.string() });
                const { vm_name, snapshot_name } = schema.parse(args);
                const result = await this.vagrant!.snapshotDelete(vm_name, snapshot_name);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "configure_sync") {
                const schema = z.object({
                    vm_name: z.string(), host_path: z.string(), guest_path: z.string(),
                    direction: z.enum(["bidirectional", "to_vm", "from_vm"]),
                    exclude_patterns: z.array(z.string()).optional()
                });
                const config = schema.parse(args);
                await this.syncManager!.configureSync({
                    vmName: config.vm_name, hostPath: config.host_path, guestPath: config.guest_path,
                    direction: config.direction, excludePatterns: config.exclude_patterns
                });
                return { content: [{ type: "text", text: `Sync configured for ${config.vm_name}` }] };
            }

            if (name === "kill_process") {
                const schema = z.object({
                    vm_name: z.string(),
                    pid: z.number(),
                    signal: z.string().default("SIGTERM"),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, pid, signal, username, password } = schema.parse(args);
                const result = await this.vagrant!.killProcess(vm_name, pid, signal, { username, password });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "get_vm_dashboard") {
                const schema = z.object({
                    vm_name: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, username, password } = schema.parse(args);
                const status = this.vmStateCache.getCachedState(vm_name)
                    ?? this.vmStateCache.setState(vm_name, await this.vagrant!.getVMStatus(vm_name));
                if (status !== "running") {
                    return this.jsonResponse({
                        vm_name,
                        status,
                        resources: null,
                        processes: [],
                        message: "VM is not running; dashboard is limited to status only."
                    });
                }

                const [resources, processes] = await Promise.all([
                    this.vagrant!.getResourceUsage(vm_name, { username, password }),
                    this.vagrant!.listProcesses(vm_name, undefined, { username, password })
                ]);
                return this.jsonResponse({ status, resources, processes: processes.processes.slice(0, 10) });
            }

            if (name === "start_download") {
                const schema = z.object({
                    vm_name: z.string(),
                    url: z.string(),
                    destination: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, url, destination, username, password } = schema.parse(args);
                const op = await this.operationTracker!.startDownload(vm_name, url, destination, { username, password });
                return { content: [{ type: "text", text: JSON.stringify(op, null, 2) }] };
            }

            if (name === "get_operation_progress") {
                const { operation_id } = z.object({ operation_id: z.string() }).parse(args);
                const progress = this.operationTracker!.getOperationProgress(operation_id);
                return { content: [{ type: "text", text: JSON.stringify(progress, null, 2) }] };
            }

            if (name === "wait_for_operation") {
                const { operation_id, timeout_seconds } = z.object({ operation_id: z.string(), timeout_seconds: z.number().default(600) }).parse(args);
                const result = await this.operationTracker!.waitForOperation(operation_id, { timeoutMs: timeout_seconds * 1000 });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "cancel_operation") {
                const { operation_id } = z.object({ operation_id: z.string() }).parse(args);
                await this.operationTracker!.cancelOperation(operation_id);
                return { content: [{ type: "text", text: `Operation ${operation_id} canceled.` }] };
            }

            if (name === "list_active_operations") {
                const { vm_name } = z.object({ vm_name: z.string().optional() }).parse(args);
                const ops = this.operationTracker!.listActiveOperations(vm_name);
                return { content: [{ type: "text", text: JSON.stringify(ops, null, 2) }] };
            }

            if (name === "scan_system_health") {
                const schema = z.object({ vm_name: z.string().optional(), security_scan: z.boolean().default(false) });
                const { vm_name, security_scan } = schema.parse(args);
                const snapshot = this.vmStateCache.setSnapshot(await this.vagrant!.listVMs());
                const healthy = snapshot.vms.filter(v => v.state === 'running');
                return this.jsonResponse({
                    observed_at_utc: snapshot.observed_at_utc,
                    scanned_vms: snapshot.vms.length,
                    running_vms: healthy.length,
                    vms: snapshot.vms
                });
            }

            if (name === "cleanup_zombies") {
                const { vm_names, dry_run } = z.object({ vm_names: z.array(z.string()), dry_run: z.boolean().default(true) }).parse(args);
                return { content: [{ type: "text", text: `Cleanup ${dry_run ? '(dry run)' : ''} initiated for: ${vm_names.join(', ')}` }] };
            }

            if (name === "set_display_mode") {
                const { vm_name, mode } = z.object({ vm_name: z.string(), mode: z.enum(["headless", "gui"]) }).parse(args);
                const result = await this.vagrant!.setDisplayMode(vm_name, mode);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "atomic_transaction_exec") {
                const schema = z.object({
                    vm_name: z.string(),
                    command: z.string(),
                    rollback_on_fail: z.boolean().default(true),
                    username: z.string().optional(),
                    password: z.string().optional()
                });
                const { vm_name, command, rollback_on_fail, username, password } = schema.parse(args);
                const snapshotName = `pre-atomic-${Date.now()}`;
                await this.vagrant!.snapshotSave(vm_name, snapshotName);
                try {
                    const result = await this.vagrant!.executeCommand(vm_name, command, { username, password });
                    if (result.exitCode !== 0 && rollback_on_fail) throw new Error(`Command failed with exit code ${result.exitCode}. Rolling back...`);
                    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
                } catch (err) {
                    if (rollback_on_fail) await this.vagrant!.snapshotRestore(vm_name, snapshotName);
                    throw err;
                }
            }

            if (name === "sentinel_await") {
                const schema = z.object({ vm_name: z.string(), condition_type: z.enum(["port", "file", "service"]), target: z.string(), timeout: z.number().default(300000) });
                const { vm_name, condition_type, target, timeout } = schema.parse(args);
                const startTime = Date.now();
                while (Date.now() - startTime < timeout) {
                    let satisfied = false;
                    if (condition_type === 'port') {
                        const res = await this.vagrant!.checkPortInVM(vm_name, parseInt(target));
                        satisfied = res.listening;
                    } else if (condition_type === 'file') {
                        const res = await this.vagrant!.executeCommand(vm_name, `ls "${target}"`);
                        satisfied = res.exitCode === 0;
                    }
                    if (satisfied) return { content: [{ type: "text", text: `Condition ${condition_type}:${target} met.` }] };
                    await new Promise(r => setTimeout(r, 5000));
                }
                throw new Error("Sentinel timeout reached.");
            }

            if (name === "forensic_blackbox_capture") {
                const { vm_name, username, password } = z.object({
                    vm_name: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                }).parse(args);
                const [processes, network] = await Promise.all([
                    this.vagrant!.listProcesses(vm_name, undefined, { username, password }),
                    this.vagrant!.executeCommand(vm_name, "ss -tlpn; ip addr", { username, password })
                ]);
                return { content: [{ type: "text", text: JSON.stringify({ processes: processes.processes, network: network.stdout }, null, 2) }] };
            }

            if (name === "resize_vm_resources") {
                const { vm_name, cpu, memory } = z.object({ vm_name: z.string(), cpu: z.number().optional(), memory: z.number().optional() }).parse(args);
                const result = await this.vagrant!.modifyVMResources(vm_name, { cpu, memory });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "package_box") {
                const { vm_name, output_file } = z.object({ vm_name: z.string(), output_file: z.string().optional() }).parse(args);
                const result = await this.vagrant!.packageVM(vm_name, output_file);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }

            if (name === "inject_secrets") {
                const { vm_name, secrets, username, password } = z.object({
                    vm_name: z.string(),
                    secrets: z.record(z.string()),
                    username: z.string().optional(),
                    password: z.string().optional()
                }).parse(args);
                let config = "";
                for (const [key, value] of Object.entries(secrets)) {
                    config += `export ${key}="${value}"\n`;
                }
                await this.vagrant!.executeCommand(vm_name, `echo '${config}' >> ~/.profile`, { username, password });
                return { content: [{ type: "text", text: "Secrets injected." }] };
            }

            if (name === "audit_security") {
                const { vm_name, username, password } = z.object({
                    vm_name: z.string(),
                    username: z.string().optional(),
                    password: z.string().optional()
                }).parse(args);
                const result = await this.vagrant!.executeCommand(vm_name, "ss -tlpn; grep -E 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config; sudo grep 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null", { username, password });
                return { content: [{ type: "text", text: result.stdout }] };
            }





            if (name === "sequentialthinking") {
                const schema = z.object({
                    thought: z.string(),
                    thoughtNumber: z.number().optional(),
                    thought_number: z.number().optional(),
                    totalThoughts: z.number().optional(),
                    total_thoughts: z.number().optional(),
                    nextThoughtNeeded: z.boolean().optional(),
                    next_thought_needed: z.boolean().optional(),
                    isRevision: z.boolean().optional(),
                    is_revision: z.boolean().optional(),
                    revisesThought: z.number().optional(),
                    revises_thought: z.number().optional(),
                    branchFromThought: z.number().optional(),
                    branch_from_thought: z.number().optional(),
                    branchId: z.string().optional(),
                    branch_id: z.string().optional(),
                    needsMoreThoughts: z.boolean().optional(),
                    needs_more_thoughts: z.boolean().optional(),
                }).transform((data) => {
                    const thoughtNumber = data.thoughtNumber ?? data.thought_number;
                    const totalThoughts = data.totalThoughts ?? data.total_thoughts;
                    const nextThoughtNeeded = data.nextThoughtNeeded ?? data.next_thought_needed;
                    if (thoughtNumber === undefined || totalThoughts === undefined || nextThoughtNeeded === undefined) {
                        throw new Error("sequentialthinking requires thoughtNumber/totalThoughts/nextThoughtNeeded (snake_case aliases accepted).");
                    }
                    return {
                        thought: data.thought,
                        thoughtNumber,
                        totalThoughts,
                        nextThoughtNeeded,
                        isRevision: data.isRevision ?? data.is_revision,
                        revisesThought: data.revisesThought ?? data.revises_thought,
                        branchFromThought: data.branchFromThought ?? data.branch_from_thought,
                        branchId: data.branchId ?? data.branch_id,
                        needsMoreThoughts: data.needsMoreThoughts ?? data.needs_more_thoughts,
                    };
                });
                const params = schema.parse(args);
                const result = this.thinkingManager!.processThought(params);
                return result;
            }



            throw new Error(`Unknown tool: ${name}`);
        } catch (error: any) {
            return handleToolError(name, error) as any;
        }
    }

    private getInstallRuntimeCommand(runtime: string): string | null {
        switch (runtime) {
            case 'node': return 'curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs';
            case 'python': return 'sudo apt-get update && sudo apt-get install -y python3 python3-pip';
            case 'go': return 'sudo apt-get update && sudo apt-get install -y golang-go';
            case 'docker': return 'curl -fsSL https://get.docker.com | sh && sudo usermod -aG docker $USER';
            default: return null;
        }
    }

    private getInstallToolCommand(tool: string): string {
        switch (tool) {
            case 'git': return 'sudo apt-get install -y git';
            case 'curl': return 'sudo apt-get install -y curl';
            case 'wget': return 'sudo apt-get install -y wget';
            case 'jq': return 'sudo apt-get install -y jq';
            case 'zip': return 'sudo apt-get install -y zip unzip';
            default: return `sudo apt-get install -y ${tool}`;
        }
    }

    async start() {
        setLogLevel(process.env.LOG_LEVEL || "error");
        try {
            fs.appendFileSync('C:\\FastMCP\\boot.log', `[${new Date().toISOString()}] Server starting up...\n`);
        } catch (e) { }
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        try {
            fs.appendFileSync('C:\\FastMCP\\boot.log', `[${new Date().toISOString()}] Server connected to transport.\n`);
        } catch (e) { }
    }
}

// Start the server
const server = new McpServer();
server.start().catch((err) => {
    logger.error("Server failed to start", err);
    process.exit(1);
});
