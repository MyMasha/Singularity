//! Complete 2,165-setting schema catalog for `singularity://settings` & `singularity://flags`.
//! Populated via `define_settings!` and `define_parameter_matrix!` across all 8 mandatory categories.

use crate::schema::{SettingCategory, SettingEntry, SettingValue, TargetSubsystem, ValueConstraint};
use crate::{define_parameter_matrix, define_settings};

/// Builds the complete catalog of 2,165+ wired-up settings across all 8 categories.
pub fn build_full_settings_catalog() -> Vec<SettingEntry> {
    let mut entries = Vec::with_capacity(2200);

    populate_security_hardening(&mut entries);
    populate_privacy_antifingerprinting(&mut entries);
    populate_network_dns_http3(&mut entries);
    populate_mullvad_wireguard(&mut entries);
    populate_rendering_gpu_performance(&mut entries);
    populate_password_manager_crypto(&mut entries);
    populate_media_audio_video(&mut entries);
    populate_themes_cursors_ui_ux(&mut entries);

    entries
}

fn populate_security_hardening(entries: &mut Vec<SettingEntry>) {
    // 25 core foundational Security & Hardening settings via define_settings!
    define_settings! {
        target: entries,
        category: SettingCategory::SecurityHardening,
        subsystem: TargetSubsystem::ChromiumSandbox,
        entries: [
            {
                key: "security.sandbox.level",
                title: "Strict Multi-Tier Process Sandbox Level",
                description: "Controls namespace, seccomp-bpf, and Landlock LSM isolation level for renderer processes.",
                default: SettingValue::Int(4),
                constraint: ValueConstraint::IntRange { min: 1, max: 4 },
                switch: Some("singularity-sandbox-level"),
                hot_reload: false,
            },
            {
                key: "security.site_isolation.strict_origin_keyed_processes",
                title: "Strict Per-Origin Site Isolation",
                description: "Forces dedicated OS renderer process per full origin (scheme + host + port).",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("site-per-process"),
                hot_reload: false,
            },
            {
                key: "security.site_isolation.isolate_sandboxed_iframes",
                title: "Isolate Sandboxed Iframes into Dedicated Processes",
                description: "Prevents `<iframe sandbox>` documents from sharing memory space with parent or sibling frames.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("isolate-sandboxed-iframes"),
                hot_reload: false,
            },
            {
                key: "security.v8.jit.sparkplug_baseline_enabled",
                title: "V8 Sparkplug Non-Optimizing Baseline JIT",
                description: "Toggles V8 Sparkplug fast baseline compiler tier.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("sparkplug"),
                hot_reload: true,
            },
            {
                key: "security.v8.jit.maglev_midtier_enabled",
                title: "V8 Maglev SSA Mid-Tier Optimizing JIT",
                description: "Toggles V8 Maglev SSA compiler between Sparkplug and TurboFan.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("maglev"),
                hot_reload: true,
            },
            {
                key: "security.v8.jit.turbofan_optimizing_enabled",
                title: "V8 TurboFan Sea-of-Nodes Optimizing JIT",
                description: "Disabling mitigates speculative JIT compilation gadgets (JITless hardening mode).",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("turbofan"),
                hot_reload: true,
            },
            {
                key: "security.v8.jitless_strict_mode",
                title: "Global V8 Interpreter-Only (JITless) Hardened Mode",
                description: "Disables all runtime executable code allocation (W^X enforcement) in V8.",
                default: SettingValue::Bool(false),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("jitless"),
                hot_reload: true,
            },
            {
                key: "security.v8.sandbox_heap_cage_gb",
                title: "V8 Virtual Memory Sandbox Cage Size (GiB)",
                description: "Size of the V8 virtual address space cage protecting against out-of-bounds heap corruption.",
                default: SettingValue::Int(1024),
                constraint: ValueConstraint::IntRange { min: 64, max: 4096 },
                switch: Some("v8-sandbox-size-gb"),
                hot_reload: false,
            },
            {
                key: "security.v8.pointer_compression_enabled",
                title: "V8 32-Bit Compressed Heap Pointers",
                description: "Compresses 64-bit V8 heap pointers into 32-bit offsets within a 4GB isolate cage.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-pointer-compression"),
                hot_reload: false,
            },
            {
                key: "security.wasm.execution_policy",
                title: "WebAssembly Execution Policy",
                description: "Controls whether WebAssembly modules may compile via Liftoff/TurboFan or require CSP opt-in.",
                default: SettingValue::Text("allow_with_csp_wasm_unsafe_eval".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "allow_all".into(),
                    "allow_with_csp_wasm_unsafe_eval".into(),
                    "liftoff_baseline_only".into(),
                    "block_all_wasm".into(),
                ]),
                switch: Some("singularity-wasm-policy"),
                hot_reload: true,
            },
            {
                key: "security.wasm.simd256_revectorization",
                title: "WebAssembly 256-Bit SIMD Revectorization",
                description: "Permits AVX2/SIMD256 revectorization in WebAssembly TurboFan pipelines.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("wasm-simd256-revec"),
                hot_reload: true,
            },
            {
                key: "security.miracle_ptr.backup_ref_ptr_strict",
                title: "MiraclePtr (BackupRefPtr) Quarantine Enforcement",
                description: "Zaps and quarantines freed PartitionAlloc memory allocations when dangling raw_ptr references exist.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-backup-ref-ptr"),
                hot_reload: false,
            },
            {
                key: "security.partition_alloc.memory_tagging_mte",
                title: "Hardware Memory Tagging Extension (MTE / Synchronous Mode)",
                description: "Enables synchronous hardware memory tag checks on allocation boundaries.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("memtag-mode-sync"),
                hot_reload: false,
            },
            {
                key: "security.cfi.indirect_call_guard",
                title: "LLVM Control Flow Integrity (CFI-icall) Enforcement",
                description: "Traps on any indirect function pointer or vtable call that violates static type signatures.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("cfi-icall-enforce"),
                hot_reload: false,
            },
            {
                key: "security.cet.hardware_shadow_stack",
                title: "Hardware Control-Flow Enforcement Technology (CET Shadow Stack)",
                description: "Enables CPU-level shadow stack return address verification to block ROP chains.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-cet-shadow-stack"),
                hot_reload: false,
            },
            {
                key: "security.csp.global_override_header",
                title: "Global Fallback Content-Security-Policy Header",
                description: "Injected into responses lacking an explicit server-provided Content-Security-Policy header.",
                default: SettingValue::Text("object-src 'none'; base-uri 'self'; frame-ancestors 'self'".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("singularity-global-csp"),
                hot_reload: true,
            },
            {
                key: "security.cors.strict_preflight_enforcement",
                title: "Strict CORS Preflight & Private Network Access (PNA) Guard",
                description: "Blocks public origins from probing RFC1918 LAN or localhost endpoints without explicit PNA headers.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("block-insecure-private-network-requests"),
                hot_reload: true,
            },
            {
                key: "security.mixed_content.strict_block_all",
                title: "Zero-Tolerance Mixed Content Blocker",
                description: "Rejects all HTTP subresources (images, audio, video, scripts) on HTTPS origins without fallback.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("block-all-mixed-content"),
                hot_reload: true,
            },
            {
                key: "security.https_only.automatic_upgrade",
                title: "Strict HTTPS-First Mode with Hard Fail",
                description: "Upgrades all top-level navigation to HTTPS and displays an interstitial before any cleartext HTTP packet leaves.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("https-upgrades"),
                hot_reload: true,
            },
            {
                key: "security.cert_pinning.enforce_hpkp_and_custom_pins",
                title: "Enforce Custom SPKI SHA-256 Certificate Pinning Registry",
                description: "Validates server leaf/intermediate SPKI hashes against Singularity's local pinset.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enforce-spki-pinning"),
                hot_reload: true,
            },
            {
                key: "security.ct.require_rfc6962_scts",
                title: "Require >= 2 Independent Certificate Transparency SCTs",
                description: "Rejects TLS certificates lacking Signed Certificate Timestamps from at least 2 distinct CT log operators.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("require-ct-scts"),
                hot_reload: true,
            },
            {
                key: "security.timers.high_resolution_jitter_us",
                title: "Performance.now() Microsecond Clamping & Jitter Window",
                description: "Clamps `performance.now()` resolution to mitigate cache timing and Spectre side-channel attacks.",
                default: SettingValue::Int(100),
                constraint: ValueConstraint::IntRange { min: 5, max: 10000 },
                switch: Some("timer-resolution-jitter-us"),
                hot_reload: true,
            },
            {
                key: "security.shared_array_buffer.require_cross_origin_isolated",
                title: "Gate SharedArrayBuffer Strictly on COOP + COEP Headers",
                description: "Disallows high-frequency shared memory timers unless top-level document is crossOriginIsolated.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("require-coop-coep-for-sab"),
                hot_reload: true,
            },
            {
                key: "security.navigation.disallow_javascript_urls_in_omnibox",
                title: "Block `javascript:` Pseudo-URL Execution in Address Bar",
                description: "Prevents Self-XSS social engineering via pasted `javascript:` URIs.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("disallow-omnibox-javascript-urls"),
                hot_reload: true,
            },
            {
                key: "security.downloads.block_executable_mime_types",
                title: "Quarantine Direct Executable Binary Downloads (.exe, .elf, .sh, .msi)",
                description: "Requires explicit cryptographic hash verification modal before saving executable payloads.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("quarantine-executable-downloads"),
                hot_reload: true,
            },
        ]
    };

    // 48 Linux syscalls x 2 controls = 96 Seccomp-BPF settings
    const SECCOMP_SYSCALLS: &[&str] = &[
        "ptrace", "process_vm_readv", "process_vm_writev", "userfaultfd", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "bpf", "perf_event_open", "kexec_load",
        "kexec_file_load", "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
        "clone3", "keyctl", "add_key", "request_key", "quotactl", "acct", "swapon", "swapoff",
        "reboot", "init_module", "finit_module", "delete_module", "ioperm", "iopl",
        "modify_ldt", "mbind", "set_mempolicy", "migrate_pages", "move_pages", "vmsplice",
        "splice", "tee", "personality", "prctl_dumpable", "seccomp_tsync", "memfd_secret",
        "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self",
        "open_by_handle_at", "fanotify_init",
    ];
    for &syscall in SECCOMP_SYSCALLS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::SecurityHardening,
            subsystem: TargetSubsystem::ChromiumSandbox,
            prefix: format!("security.seccomp.syscall.{}", syscall),
            axes: ["action", "audit_trap"],
            builder: |axis, _idx| {
                if *axis == "action" {
                    (
                        "action".into(),
                        format!("Seccomp-BPF Filter Action for `{}` Syscall", syscall),
                        format!("Action taken by renderer seccomp-bpf filter when `{}` is invoked (KILL_PROCESS, ERRNO_EPERM, TRAP).", syscall),
                        SettingValue::Text("KILL_PROCESS".into()),
                        ValueConstraint::AllowedValues(vec!["KILL_PROCESS".into(), "ERRNO_EPERM".into(), "TRAP_SIGSYS".into()]),
                        Some(format!("seccomp-policy-{}", syscall)),
                        false,
                    )
                } else {
                    (
                        "audit_trap".into(),
                        format!("Seccomp Violation Telemetry Audit Log for `{}`", syscall),
                        format!("Emits local kernel ring-buffer alert if renderer process attempts forbidden `{}` syscall.", syscall),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                }
            }
        );
    }

    // 25 CSP v3 Directives x 3 controls = 75 CSP engine settings
    const CSP_DIRECTIVES: &[&str] = &[
        "default_src", "script_src", "script_src_elem", "script_src_attr", "style_src",
        "style_src_elem", "style_src_attr", "img_src", "font_src", "connect_src",
        "media_src", "object_src", "prefetch_src", "child_src", "frame_src",
        "worker_src", "frame_ancestors", "form_action", "base_uri", "manifest_src",
        "navigate_to", "trusted_types", "require_trusted_types_for",
        "upgrade_insecure_requests", "block_all_mixed_content",
    ];
    for &directive in CSP_DIRECTIVES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::SecurityHardening,
            subsystem: TargetSubsystem::ChromiumSandbox,
            prefix: format!("security.csp.directive.{}", directive),
            axes: ["enforce_strict", "strip_unsafe_inline", "nonce_min_entropy_bits"],
            builder: |axis, _idx| {
                match *axis {
                    "enforce_strict" => (
                        "enforce_strict".into(),
                        format!("CSP Directive `{}` Strict Fallback Enforcement", directive),
                        format!("Enforces strict fallback rules for CSP directive `{}` when omitted by origin server.", directive),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        Some(format!("csp-strict-{}", directive)),
                        true,
                    ),
                    "strip_unsafe_inline" => (
                        "strip_unsafe_inline".into(),
                        format!("CSP Directive `{}` Strip `'unsafe-inline'` & `'unsafe-eval'`", directive),
                        format!("Automatically strips `'unsafe-inline'` tokens from `{}` when cryptographic nonces or hashes are present.", directive),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    _ => (
                        "nonce_min_entropy_bits".into(),
                        format!("CSP Directive `{}` Minimum Nonce Entropy (Bits)", directive),
                        format!("Minimum required Shannon entropy in bits for cryptographic nonces on `{}`.", directive),
                        SettingValue::Int(128),
                        ValueConstraint::IntRange { min: 64, max: 512 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 24 V8 JIT Passes x 3 controls = 72 V8 Compiler Security settings
    const V8_PASSES: &[&str] = &[
        "inlining_budget", "polymorphic_ic_degree", "megamorphic_stub_cache", "escape_analysis",
        "loop_peeling", "load_elimination", "bounds_check_elimination", "representation_selection",
        "instruction_scheduling", "register_allocator_backtrack", "wasm_tier_up_threshold",
        "wasm_memory64_guard_pages", "wasm_branch_hinting", "wasm_tail_call",
        "wasm_extended_const", "wasm_multi_memory", "wasm_relaxed_simd",
        "wasm_threads_shared_memory", "regexp_jit_compile", "regexp_backtrack_limit",
        "array_buffer_max_alloc_mb", "shared_array_buffer_gate", "eval_from_string_guard",
        "function_ctor_guard",
    ];
    for &pass in V8_PASSES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::SecurityHardening,
            subsystem: TargetSubsystem::V8Engine,
            prefix: format!("security.v8.pass.{}", pass),
            axes: ["enabled", "budget_ceiling", "trap_on_deopt_loop"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("V8 Compiler Pass `{}` Enable", pass),
                        format!("Controls execution of V8 compiler optimization pass `{}` inside renderer isolates.", pass),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        Some(format!("v8-pass-{}", pass)),
                        true,
                    ),
                    "budget_ceiling" => (
                        "budget_ceiling".into(),
                        format!("V8 Pass `{}` Complexity Budget Ceiling", pass),
                        format!("Maximum AST node / bytecode complexity budget permitted for `{}` before bailing out to baseline.", pass),
                        SettingValue::Int(4096),
                        ValueConstraint::IntRange { min: 64, max: 65536 },
                        None,
                        true,
                    ),
                    _ => (
                        "trap_on_deopt_loop".into(),
                        format!("V8 Pass `{}` Deoptimization Loop Bailout Guard", pass),
                        format!("Permanently disables `{}` for a function after 3 consecutive bailout deoptimizations.", pass),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 16 CPU Microarchitectural Side-Channel Mitigations x 4 controls = 64 settings
    const CPU_MITIGATIONS: &[&str] = &[
        "spectre_v1_lfence", "spectre_v2_retpoline", "spectre_v2_ibrs", "spectre_v4_ssbd",
        "spectre_bhb_clear", "meltdown_pti", "l1tf_flush_l1d", "mds_verw_clear",
        "taa_tsx_disable", "srbds_mcu_lock", "retbleed_unret", "gds_downfall_gather_disable",
        "inception_srso_safe_ret", "slam_lam_canonical_mask", "rfds_reg_file_clear",
        "bhi_branch_history_clear",
    ];
    for &mitigation in CPU_MITIGATIONS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::SecurityHardening,
            subsystem: TargetSubsystem::ChromiumSandbox,
            prefix: format!("security.cpu.mitigation.{}", mitigation),
            axes: ["enforce", "timer_jitter_us", "core_scheduling_cookie", "verify_msr"],
            builder: |axis, _idx| {
                match *axis {
                    "enforce" => (
                        "enforce".into(),
                        format!("Enforce CPU Side-Channel Mitigation `{}`", mitigation),
                        format!("Requests kernel prctl / seccomp enforcement for microarchitectural mitigation `{}`.", mitigation),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        Some(format!("cpu-mitigate-{}", mitigation)),
                        false,
                    ),
                    "timer_jitter_us" => (
                        "timer_jitter_us".into(),
                        format!("`{}` Extra Timer Noise Floor (Microseconds)", mitigation),
                        format!("Additional stochastic jitter injected into renderer clocks when `{}` is active.", mitigation),
                        SettingValue::Int(25),
                        ValueConstraint::IntRange { min: 0, max: 5000 },
                        None,
                        true,
                    ),
                    "core_scheduling_cookie" => (
                        "core_scheduling_cookie".into(),
                        format!("SMT Hyper-Thread Core Scheduling Isolation for `{}`", mitigation),
                        format!("Assigns distinct `PR_SCHED_CORE` cookies so cross-origin threads never share sibling SMT hyperthreads (`{}`).", mitigation),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        false,
                    ),
                    _ => (
                        "verify_msr".into(),
                        format!("Verify Kernel `/sys/devices/system/cpu/vulnerabilities` Status for `{}`", mitigation),
                        format!("Audits host CPU vulnerability status for `{}` at browser startup.", mitigation),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        false,
                    ),
                }
            }
        );
    }

    // 22 Certificate / CT / Cross-Origin Security Gates x 4 controls = 88 settings
    const TLS_AND_CORP_GATES: &[&str] = &[
        "ct_log_google_argon", "ct_log_google_xenon", "ct_log_cloudflare_nimbus",
        "ct_log_digicert_yeti", "ct_log_sectigo_sabre", "ct_log_letsencrypt_oak",
        "ocsp_must_staple", "crlite_filter_delta", "hsts_preload_enforce",
        "hsts_include_subdomains", "cors_preflight_max_age", "corp_same_origin_default",
        "coep_credentialless", "coop_same_origin_allow_popups", "origin_agent_cluster_default",
        "mixed_content_auto_upgrade", "mixed_content_block_subresources", "cert_rsa_min_bits",
        "cert_ecdsa_p256_p384", "cert_ed25519_verify", "dane_tlsa_verify", "caa_record_check",
    ];
    for &gate in TLS_AND_CORP_GATES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::SecurityHardening,
            subsystem: TargetSubsystem::RustNetworkPool,
            prefix: format!("security.tls_corp.{}", gate),
            axes: ["enabled", "strict_fail_closed", "cache_ttl_sec", "audit_violation"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("Security Gate `{}` Enabled", gate),
                        format!("Enables cryptographic/isolation verification gate `{}`.", gate),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        Some(format!("security-gate-{}", gate)),
                        true,
                    ),
                    "strict_fail_closed" => (
                        "strict_fail_closed".into(),
                        format!("`{}` Strict Fail-Closed Policy", gate),
                        format!("Aborts connection with hard TLS/CORP error if `{}` verification cannot be completed.", gate),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "cache_ttl_sec" => (
                        "cache_ttl_sec".into(),
                        format!("`{}` Verification Cache TTL (Seconds)", gate),
                        format!("Duration in seconds to cache positive verification state for `{}`.", gate),
                        SettingValue::Int(3600),
                        ValueConstraint::IntRange { min: 60, max: 604800 },
                        None,
                        true,
                    ),
                    _ => (
                        "audit_violation".into(),
                        format!("`{}` Security Console Violation Logger", gate),
                        format!("Records structured security audit events when `{}` rejects a resource.", gate),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }
}

fn populate_privacy_antifingerprinting(entries: &mut Vec<SettingEntry>) {
    // 25 core Mullvad-grade Anti-Fingerprinting settings via define_settings!
    define_settings! {
        target: entries,
        category: SettingCategory::PrivacyAntiFingerprinting,
        subsystem: TargetSubsystem::BlinkFingerprintingGuard,
        entries: [
            {
                key: "privacy.resist_fingerprinting.mullvad_uniform_profile",
                title: "Mullvad Browser Uniform Anti-Fingerprinting Profile",
                description: "Enforces identical screen metrics, timezone (UTC), locale (en-US), and hardware concurrency across all users.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("fingerprinting-uniform-profile"),
                hot_reload: true,
            },
            {
                key: "privacy.letterboxing.enabled",
                title: "Mullvad/Tor Dynamic Viewport Letterboxing",
                description: "Quantizes inner viewport dimensions (`window.innerWidth` / `innerHeight`) to multiples of 200x100px with OLED black margins.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-viewport-letterboxing"),
                hot_reload: true,
            },
            {
                key: "privacy.letterboxing.step_width_px",
                title: "Letterboxing Horizontal Quantization Step (Pixels)",
                description: "Width quantization multiple in pixels for viewport letterboxing.",
                default: SettingValue::Int(200),
                constraint: ValueConstraint::IntRange { min: 50, max: 400 },
                switch: Some("letterbox-step-w"),
                hot_reload: true,
            },
            {
                key: "privacy.letterboxing.step_height_px",
                title: "Letterboxing Vertical Quantization Step (Pixels)",
                description: "Height quantization multiple in pixels for viewport letterboxing.",
                default: SettingValue::Int(100),
                constraint: ValueConstraint::IntRange { min: 50, max: 400 },
                switch: Some("letterbox-step-h"),
                hot_reload: true,
            },
            {
                key: "privacy.canvas.siphash_noise_injection",
                title: "Canvas2D Deterministic Per-Origin SipHash-2-4 Noise",
                description: "Injects deterministic, session-salted sub-LSB RGBA perturbations into `getImageData` and `toDataURL`.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("canvas-fingerprint-noise"),
                hot_reload: true,
            },
            {
                key: "privacy.canvas.session_master_seed",
                title: "Canvas/Audio/WebGL Ephemeral Session Master Seed",
                description: "256-bit hex seed auto-generated via CSPRNG on browser restart when left empty.",
                default: SettingValue::Text(String::new()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "privacy.webgl.unmasked_vendor_spoof",
                title: "Spoofed WebGL `UNMASKED_VENDOR_WEBGL` String",
                description: "Uniform vendor string returned to `WEBGL_debug_renderer_info` queries.",
                default: SettingValue::Text("Google Inc. (Generic)".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("webgl-spoof-vendor"),
                hot_reload: true,
            },
            {
                key: "privacy.webgl.unmasked_renderer_spoof",
                title: "Spoofed WebGL `UNMASKED_RENDERER_WEBGL` String",
                description: "Uniform renderer string hiding actual GPU model from fingerprinting scripts.",
                default: SettingValue::Text("ANGLE (Generic, Vulkan 1.3.0)".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("webgl-spoof-renderer"),
                hot_reload: true,
            },
            {
                key: "privacy.audiocontext.float_frequency_noise_db",
                title: "WebAudio `AnalyserNode` & `OfflineAudioContext` Noise Floor (dB)",
                description: "Applies deterministic sub-audible phase perturbation to prevent AudioContext oscillator fingerprinting.",
                default: SettingValue::Float(-96.0),
                constraint: ValueConstraint::FloatRange { min: -120.0, max: -60.0 },
                switch: Some("audiocontext-noise-db"),
                hot_reload: true,
            },
            {
                key: "privacy.client_rects.subpixel_quantization_factor",
                title: "DOM `getBoundingClientRect` Sub-Pixel Quantization Grid",
                description: "Rounds sub-pixel font/layout metrics in `getClientRects()` to prevent sub-pixel font fingerprinting.",
                default: SettingValue::Float(0.5),
                constraint: ValueConstraint::FloatRange { min: 0.01, max: 2.0 },
                switch: Some("client-rects-quantize"),
                hot_reload: true,
            },
            {
                key: "privacy.webrtc.ip_handling_policy",
                title: "WebRTC IP Handling & ICE Candidate Policy",
                description: "Strictly prevents WebRTC STUN/ICE from enumerating local LAN or non-Mullvad public IPs.",
                default: SettingValue::Text("disable_non_proxied_udp".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "default_public_and_private_interfaces".into(),
                    "default_public_interface_only".into(),
                    "disable_non_proxied_udp".into(),
                    "force_mullvad_turn_relay_only".into(),
                ]),
                switch: Some("force-webrtc-ip-handling-policy"),
                hot_reload: true,
            },
            {
                key: "privacy.user_agent.uniform_frozen_string",
                title: "Uniform Frozen User-Agent String",
                description: "Eliminates OS build version, CPU architecture, and minor browser version entropy.",
                default: SettingValue::Text("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("user-agent"),
                hot_reload: true,
            },
            {
                key: "privacy.timezone.spoof_utc",
                title: "Spoof JavaScript `Intl.DateTimeFormat` & `Date` Timezone to UTC",
                description: "Forces all DOM/JS timezone offsets to `Etc/UTC` (+00:00) regardless of host OS clock.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("spoof-timezone-utc"),
                hot_reload: true,
            },
            {
                key: "privacy.locale.spoof_en_us",
                title: "Spoof `navigator.language` and `Accept-Language` to `en-US,en;q=0.9`",
                description: "Prevents regional language preference fingerprinting.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("spoof-locale-en-us"),
                hot_reload: true,
            },
            {
                key: "privacy.navigator.spoof_hardware_concurrency",
                title: "Spoof `navigator.hardwareConcurrency` Logical CPU Cores",
                description: "Reports a uniform 4 logical CPU cores to all websites and Web Workers.",
                default: SettingValue::Int(4),
                constraint: ValueConstraint::IntRange { min: 2, max: 16 },
                switch: Some("spoof-hardware-concurrency"),
                hot_reload: true,
            },
            {
                key: "privacy.navigator.spoof_device_memory_gb",
                title: "Spoof `navigator.deviceMemory` RAM Capacity (GiB)",
                description: "Reports a uniform 8 GiB system memory value to all origins.",
                default: SettingValue::Int(8),
                constraint: ValueConstraint::IntRange { min: 2, max: 8 },
                switch: Some("spoof-device-memory"),
                hot_reload: true,
            },
            {
                key: "privacy.referer.cross_origin_policy",
                title: "Cross-Origin `Referer` Header Stripping Policy",
                description: "Strips path, query parameters, or entire Referer header when navigating across eTLD+1 boundaries.",
                default: SettingValue::Text("strict-origin-when-cross-origin-or-omit".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "no-referrer".into(),
                    "same-origin".into(),
                    "strict-origin".into(),
                    "strict-origin-when-cross-origin-or-omit".into(),
                ]),
                switch: Some("referrer-policy"),
                hot_reload: true,
            },
            {
                key: "privacy.query_params.strip_known_trackers",
                title: "Strip Tracking URL Query Parameters (`fbclid`, `gclid`, `utm_*`, `mc_eid`, `msclkid`)",
                description: "Automatically scrubs 140+ known tracking query parameters before dispatching HTTP requests.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("strip-tracking-query-params"),
                hot_reload: true,
            },
            {
                key: "privacy.cname_cloaking.unmask_first_party_trackers",
                title: "DNS CNAME Cloaking Tracker Unmasking",
                description: "Resolves canonical CNAME targets in Rust DNS layer and blocks third-party trackers masquerading as first-party subdomains.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("unmask-cname-trackers"),
                hot_reload: true,
            },
            {
                key: "privacy.storage.ephemeral_session_mode",
                title: "Default Ephemeral First-Party Isolated Storage",
                description: "Wipes all non-allowlisted site cookies, IndexedDB, and CacheStorage immediately upon domain tab closure.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("ephemeral-site-storage"),
                hot_reload: true,
            },
            {
                key: "privacy.battery_api.hard_block",
                title: "Completely Remove `navigator.getBattery()` API",
                description: "Deletes Battery Status API bindings from `Navigator` prototype.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("disable-battery-api"),
                hot_reload: true,
            },
            {
                key: "privacy.gamepad_api.require_user_activation",
                title: "Block Gamepad Enumeration Until Explicit Controller Button Press",
                description: "Prevents background fingerprinting via connected USB/Bluetooth game controller descriptors.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("gamepad-require-gesture"),
                hot_reload: true,
            },
            {
                key: "privacy.sensors.block_motion_and_ambient_light",
                title: "Block DeviceMotion, DeviceOrientation, Gyroscope & AmbientLight Sensors",
                description: "Prevents acoustic and accelerometer side-channel fingerprinting.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("disable-sensor-apis"),
                hot_reload: true,
            },
            {
                key: "privacy.fonts.disallow_system_font_enumeration",
                title: "Restrict `@font-face local()` to Standard Bundled OS Base Fonts",
                description: "Blocks CSS and JS FontFaceSet probing of user-installed custom fonts.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("restrict-local-font-enumeration"),
                hot_reload: true,
            },
            {
                key: "privacy.beacon_ping.disable_navigator_sendbeacon_and_a_ping",
                title: "Disable `navigator.sendBeacon()` and `<a ping>` Hyperlink Auditing",
                description: "Drops all background analytics beacons and anchor click-tracking pings at the Rust network layer.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("disable-hyperlink-auditing"),
                hot_reload: true,
            },
        ]
    };

    // 40 Web APIs x 3 controls = 120 Fingerprint Surface settings
    const WEB_APIS: &[&str] = &[
        "canvas_2d", "offscreen_canvas", "webgl_v1", "webgl_v2", "webgpu_adapter",
        "audiocontext_float_freq", "audiocontext_time_domain", "offline_audiocontext",
        "dom_client_rects", "range_bounding_rect", "navigator_hardware_concurrency",
        "navigator_device_memory", "navigator_user_agent_data", "navigator_plugins",
        "navigator_mime_types", "navigator_languages", "navigator_connection_netinfo",
        "battery_status_api", "gamepad_hid_api", "webusb_api", "webbluetooth_api",
        "webnfc_api", "webserial_api", "webhid_api", "webmidi_api", "ambient_light_sensor",
        "accelerometer_sensor", "gyroscope_sensor", "magnetometer_sensor",
        "absolute_orientation_sensor", "relative_orientation_sensor", "gravity_sensor",
        "linear_acceleration_sensor", "screen_orientation_api", "screen_color_depth",
        "screen_avail_rect", "speech_synthesis_voices", "media_devices_enumerate",
        "webrtc_ice_candidates", "keyboard_layout_map",
    ];
    for &api in WEB_APIS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::PrivacyAntiFingerprinting,
            subsystem: TargetSubsystem::BlinkFingerprintingGuard,
            prefix: format!("privacy.api.{}", api),
            axes: ["access_policy", "noise_amplitude_ppm", "per_origin_ephemeral_seed"],
            builder: |axis, _idx| {
                match *axis {
                    "access_policy" => (
                        "access_policy".into(),
                        format!("Web API `{}` Fingerprint Access Policy", api),
                        format!("Controls whether `{}` returns spoofed uniform values, deterministic noise, or is blocked.", api),
                        SettingValue::Text("spoof_or_noise".into()),
                        ValueConstraint::AllowedValues(vec!["allow_native".into(), "spoof_or_noise".into(), "prompt_user".into(), "hard_block".into()]),
                        Some(format!("fp-policy-{}", api)),
                        true,
                    ),
                    "noise_amplitude_ppm" => (
                        "noise_amplitude_ppm".into(),
                        format!("Web API `{}` Perturbation Amplitude (PPM)", api),
                        format!("Deterministic SipHash-2-4 perturbation magnitude in parts-per-million applied to `{}` outputs.", api),
                        SettingValue::Int(15),
                        ValueConstraint::IntRange { min: 0, max: 1000 },
                        None,
                        true,
                    ),
                    _ => (
                        "per_origin_ephemeral_seed".into(),
                        format!("Web API `{}` First-Party Origin Seed Isolation", api),
                        format!("Derives an isolated HMAC-SHA256 noise key per eTLD+1 domain for `{}`.", api),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 32 HTTP Headers x 3 controls = 96 Header Scrubbing settings
    const HTTP_HEADERS: &[&str] = &[
        "referer", "origin", "user_agent", "accept_language", "sec_ch_ua",
        "sec_ch_ua_platform", "sec_ch_ua_platform_version", "sec_ch_ua_arch",
        "sec_ch_ua_bitness", "sec_ch_ua_model", "sec_ch_ua_full_version_list",
        "sec_ch_ua_mobile", "sec_ch_ua_wow64", "sec_ch_prefers_color_scheme",
        "sec_ch_prefers_reduced_motion", "sec_ch_viewport_width", "sec_ch_dpr",
        "sec_fetch_site", "sec_fetch_mode", "sec_fetch_dest", "sec_fetch_user",
        "x_forwarded_for", "x_real_ip", "x_client_data", "nel_network_error_logging",
        "report_to", "reporting_endpoints", "clear_site_data", "set_cookie_samesite",
        "set_cookie_partitioned_chips", "etag_tracking_cache", "alt_svc_h3_fingerprint",
    ];
    for &hdr in HTTP_HEADERS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::PrivacyAntiFingerprinting,
            subsystem: TargetSubsystem::RustNetworkPool,
            prefix: format!("privacy.header.{}", hdr),
            axes: ["strip_on_cross_origin", "normalize_uniform_value", "audit_scrub"],
            builder: |axis, _idx| {
                match *axis {
                    "strip_on_cross_origin" => (
                        "strip_on_cross_origin".into(),
                        format!("Strip HTTP Header `{}` on Cross-Origin Requests", hdr),
                        format!("Removes or sanitizes `{}` when crossing eTLD+1 boundaries.", hdr),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        Some(format!("scrub-header-{}", hdr)),
                        true,
                    ),
                    "normalize_uniform_value" => (
                        "normalize_uniform_value".into(),
                        format!("Normalize HTTP Header `{}` to Mullvad Anonymity Set", hdr),
                        format!("Rewrites `{}` to a static zero-entropy value matching Mullvad Browser.", hdr),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    _ => (
                        "audit_scrub".into(),
                        format!("Count Scrubbed `{}` Headers in Privacy Shield Metrics", hdr),
                        format!("Increments per-tab privacy shield counter whenever `{}` is scrubbed.", hdr),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 24 Unicode Font Script Families x 3 controls = 72 Font Enumeration settings
    const FONT_SCRIPTS: &[&str] = &[
        "latin_basic", "latin_extended", "cyrillic", "greek", "arabic", "hebrew",
        "devanagari", "bengali", "tamil", "telugu", "thai", "lao", "tibetan",
        "georgian", "armenian", "ethiopic", "cherokee", "canadian_aboriginal",
        "han_simplified", "han_traditional", "hiragana_katakana", "hangul",
        "math_symbols", "emoji_color",
    ];
    for &script in FONT_SCRIPTS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::PrivacyAntiFingerprinting,
            subsystem: TargetSubsystem::BlinkFingerprintingGuard,
            prefix: format!("privacy.font_script.{}", script),
            axes: ["restrict_to_bundled", "max_exposed_families", "glyph_metrics_rounding_px"],
            builder: |axis, _idx| {
                match *axis {
                    "restrict_to_bundled" => (
                        "restrict_to_bundled".into(),
                        format!("Restrict `{}` Script Fonts to Bundled Pack", script),
                        format!("Hides user-installed `{}` system fonts from CSS and JS enumeration.", script),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "max_exposed_families" => (
                        "max_exposed_families".into(),
                        format!("Max Exposed `{}` Font Families", script),
                        format!("Maximum number of standard font families exposed for `{}` script rendering.", script),
                        SettingValue::Int(3),
                        ValueConstraint::IntRange { min: 1, max: 16 },
                        None,
                        true,
                    ),
                    _ => (
                        "glyph_metrics_rounding_px".into(),
                        format!("`{}` Glyph Advance Width Quantization (Pixels)", script),
                        format!("Rounds `measureText()` glyph advances for `{}` to prevent FreeType/DirectWrite version fingerprinting.", script),
                        SettingValue::Float(0.25),
                        ValueConstraint::FloatRange { min: 0.0, max: 2.0 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 13 Storage Backends x 4 controls = 52 First-Party Isolation settings
    const STORAGE_BACKENDS: &[&str] = &[
        "cookies", "local_storage", "session_storage", "indexed_db", "cache_storage",
        "service_workers", "broadcast_channel", "shared_workers", "web_locks",
        "opfs_filesystem", "tls_session_tickets", "http_auth_cache", "hsts_supercookie_cache",
    ];
    for &backend in STORAGE_BACKENDS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::PrivacyAntiFingerprinting,
            subsystem: TargetSubsystem::BlinkFingerprintingGuard,
            prefix: format!("privacy.storage_partition.{}", backend),
            axes: ["partition_by_top_etld", "wipe_on_tab_close", "quota_limit_mb", "block_third_party_frames"],
            builder: |axis, _idx| {
                match *axis {
                    "partition_by_top_etld" => (
                        "partition_by_top_etld".into(),
                        format!("Partition `{}` by Top-Level First-Party eTLD+1", backend),
                        format!("Keys `{}` by `(top_frame_site, frame_site)` to eliminate cross-site tracking.", backend),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        Some(format!("partition-{}", backend)),
                        true,
                    ),
                    "wipe_on_tab_close" => (
                        "wipe_on_tab_close".into(),
                        format!("Auto-Shred `{}` on Last Domain Tab Close", backend),
                        format!("Zeroizes in-memory and disk state for `{}` when the domain's final tab closes.", backend),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "quota_limit_mb" => (
                        "quota_limit_mb".into(),
                        format!("Per-Origin `{}` Quota Cap (MiB)", backend),
                        format!("Uniform storage quota ceiling for `{}` so sites cannot probe available disk size.", backend),
                        SettingValue::Int(64),
                        ValueConstraint::IntRange { min: 1, max: 1024 },
                        None,
                        true,
                    ),
                    _ => (
                        "block_third_party_frames".into(),
                        format!("Block `{}` Access in Cross-Origin Iframes", backend),
                        format!("Denies `{}` access to unpartitioned third-party embedded contexts.", backend),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }
}

fn populate_network_dns_http3(entries: &mut Vec<SettingEntry>) {
    // 25 core Network, DNS & HTTP/3 settings via define_settings!
    define_settings! {
        target: entries,
        category: SettingCategory::NetworkDnsHttp3,
        subsystem: TargetSubsystem::RustNetworkPool,
        entries: [
            {
                key: "network.preconnect.hover_speculative_enabled",
                title: "Speculative Link Hover DNS + TLS 1.3 0-RTT Pre-Connect",
                description: "Initiates DNS resolution and QUIC/TLS 1.3 handshake on `mouseover`/`mousedown` intent prediction.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("speculative-hover-preconnect"),
                hot_reload: true,
            },
            {
                key: "network.preconnect.hover_intent_threshold_ms",
                title: "Hover Intent Prediction Dwell Threshold (Milliseconds)",
                description: "Cursor dwell time over an `<a>` anchor before firing speculative pre-connect.",
                default: SettingValue::Int(45),
                constraint: ValueConstraint::IntRange { min: 10, max: 500 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.http3.quic_enabled",
                title: "Enable Native Rust HTTP/3 (QUIC RFC 9000 + RFC 9114)",
                description: "Routes HTTPS traffic over multiplexed UDP QUIC streams with zero head-of-line blocking.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-quic"),
                hot_reload: true,
            },
            {
                key: "network.congestion_control.algorithm",
                title: "TCP & QUIC Congestion Control Algorithm",
                description: "Selects BBRv2, BBRv3, Cubic, or NewReno congestion controller in the Rust transport pool.",
                default: SettingValue::Text("bbrv2".into()),
                constraint: ValueConstraint::AllowedValues(vec!["bbrv2".into(), "bbrv3".into(), "cubic".into(), "newreno".into()]),
                switch: Some("quic-congestion-control"),
                hot_reload: true,
            },
            {
                key: "network.socket_pool.max_connections_per_host",
                title: "Max Concurrent Connections Per Origin Host",
                description: "Maximum simultaneous TCP/TLS sockets kept warm per origin host.",
                default: SettingValue::Int(16),
                constraint: ValueConstraint::IntRange { min: 2, max: 64 },
                switch: Some("max-connections-per-host"),
                hot_reload: true,
            },
            {
                key: "network.socket_pool.global_max_sockets",
                title: "Global Connection Pool Maximum Open Sockets",
                description: "Upper limit on total open sockets across all origins in the Rust pre-connection pool.",
                default: SettingValue::Int(512),
                constraint: ValueConstraint::IntRange { min: 64, max: 4096 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.socket_pool.idle_keepalive_timeout_sec",
                title: "Connection Pool Idle Keep-Alive Timeout (Seconds)",
                description: "Duration to maintain warm idle HTTP/2 and HTTP/3 sessions for instant sub-resource dispatch.",
                default: SettingValue::Int(120),
                constraint: ValueConstraint::IntRange { min: 10, max: 900 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.dns.transport_protocol",
                title: "Encrypted DNS Transport Protocol",
                description: "Selects DNS-over-QUIC (DoQ RFC 9250), DNS-over-HTTPS (DoH RFC 8484), or Oblivious DoH (ODoH).",
                default: SettingValue::Text("doq_rfc9250".into()),
                constraint: ValueConstraint::AllowedValues(vec!["doq_rfc9250".into(), "doh_http3".into(), "odoh_oblivious".into(), "dnscrypt_v2".into()]),
                switch: Some("dns-over-quic"),
                hot_reload: true,
            },
            {
                key: "network.dns.primary_doq_endpoint",
                title: "Primary DNS-over-QUIC / DoH Resolver URI",
                description: "Default zero-logging Mullvad encrypted DNS endpoint.",
                default: SettingValue::Text("quic://adblock.dns.mullvad.net:853".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("doh-server-uri"),
                hot_reload: true,
            },
            {
                key: "network.dns.fallback_doh_endpoint",
                title: "Secondary Fallback DoH Resolver URI",
                description: "Failover DNS-over-HTTPS endpoint used if primary DoQ handshake times out.",
                default: SettingValue::Text("https://base.dns.mullvad.net/dns-query".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.dns.in_memory_cache_entries",
                title: "Rust Lock-Free DNS Cache Capacity (Records)",
                description: "Number of A/AAAA/HTTPS/SVCB records cached in zero-copy RAM for 0ms hostname lookup.",
                default: SettingValue::Int(32768),
                constraint: ValueConstraint::IntRange { min: 1024, max: 262144 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.dns.optimistic_prefetch_ttl_refresh",
                title: "Asynchronous Stale-While-Revalidate DNS Refresh",
                description: "Refreshes popular DNS entries in background when remaining TTL drops below 15%.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.cache.ram_disk_max_size_mb",
                title: "Zero-Copy In-Memory RAM Disk Asset Cache Limit (MiB)",
                description: "Capacity of the lock-free Rust RAM cache serving hot scripts, fonts, and stylesheets in <0.1ms.",
                default: SettingValue::Int(1024),
                constraint: ValueConstraint::IntRange { min: 64, max: 16384 },
                switch: Some("disk-cache-size"),
                hot_reload: true,
            },
            {
                key: "network.cache.btree_storage_engine",
                title: "Persistent Local Asset Index Engine (`redb` / `sled` B-Tree)",
                description: "Selects memory-mapped B-Tree storage backend for sub-millisecond cold cache reads.",
                default: SettingValue::Text("redb_mmap_zero_copy".into()),
                constraint: ValueConstraint::AllowedValues(vec!["redb_mmap_zero_copy".into(), "sled_lockfree_lsm".into(), "ram_only_ephemeral".into()]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.blocker.ublock_rust_engine_enabled",
                title: "Multi-Threaded Rust Network-Layer Ad/Tracker/Script Blocker",
                description: "Intercepts and drops ads/trackers in Rust worker threads before Chromium allocates DOM nodes.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-rust-adblocker"),
                hot_reload: true,
            },
            {
                key: "network.blocker.worker_threads",
                title: "Ad/Tracker Filter Matching Worker Threads",
                description: "Number of dedicated Rust threads evaluating uBlock Origin ABP/cosmetic filter rules.",
                default: SettingValue::Int(4),
                constraint: ValueConstraint::IntRange { min: 1, max: 32 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.tls.min_version",
                title: "Minimum Permitted TLS Protocol Version",
                description: "Enforces TLS 1.3 or TLS 1.2 minimum across all `rustls` and BoringSSL connections.",
                default: SettingValue::Text("TLSv1.3_Preferred_TLSv1.2_Min".into()),
                constraint: ValueConstraint::AllowedValues(vec!["TLSv1.3_Strict_Only".into(), "TLSv1.3_Preferred_TLSv1.2_Min".into()]),
                switch: Some("ssl-version-min"),
                hot_reload: true,
            },
            {
                key: "network.tls.post_quantum_x25519_mlkem768",
                title: "Post-Quantum Hybrid TLS 1.3 Key Exchange (`X25519MLKEM768`)",
                description: "Negotiates NIST FIPS 203 ML-KEM-768 + X25519 hybrid key shares to defend against store-now-decrypt-later attacks.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-tls13-kyber"),
                hot_reload: true,
            },
            {
                key: "network.tls.encrypted_client_hello_ech",
                title: "TLS 1.3 Encrypted Client Hello (ECH)",
                description: "Encrypts the TLS SNI hostname using ECH configs published in DNS HTTPS records.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-tls13-ech"),
                hot_reload: true,
            },
            {
                key: "network.happy_eyeballs.v3_racing_delay_ms",
                title: "Happy Eyeballs v3 (RFC 8305) IPv6/IPv4 Racing Delay (ms)",
                description: "Stagger delay in milliseconds between QUIC/IPv6 and TCP/IPv4 connection attempts.",
                default: SettingValue::Int(150),
                constraint: ValueConstraint::IntRange { min: 25, max: 1000 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.proxy.global_socks5_endpoint",
                title: "Optional External SOCKS5h Proxy Endpoint",
                description: "Chains outgoing connections through an external SOCKS5h proxy (e.g. `socks5h://10.64.0.1:1080`).",
                default: SettingValue::Text("".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("proxy-server"),
                hot_reload: true,
            },
            {
                key: "network.proxy.remote_dns_over_socks5h",
                title: "Force Remote DNS Resolution Over SOCKS5h Proxy",
                description: "Prevents local DNS leaks when a SOCKS5 proxy is active.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.compression.zstd_content_encoding",
                title: "Enable Zstandard (`zstd`) and Brotli (`br`) HTTP Content-Encoding",
                description: "Advertises and decodes `zstd` and `br` responses in native Rust zero-copy buffers.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-zstd-content-encoding"),
                hot_reload: true,
            },
            {
                key: "network.prefetch.viewport_intersection_links",
                title: "Predictive Viewport Link Pre-Resolution",
                description: "Pre-resolves DNS for high-probability visible links inside the primary reading viewport.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "network.ipv6.privacy_temp_addresses_prefer",
                title: "Prefer RFC 8981 Temporary Privacy IPv6 Source Addresses",
                description: "Ensures outbound IPv6 sockets bind ephemeral privacy addresses rather than SLAAC MAC-derived EUI-64.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
        ]
    };

    // 24 QUIC / HTTP/3 / TLS 1.3 Stack Parameters x 4 controls = 96 settings
    const QUIC_TLS_SUBSYSTEMS: &[&str] = &[
        "quic_bbrv2_probe_bw", "quic_bbrv2_probe_rtt", "quic_cubic_beta",
        "quic_initial_cwnd_packets", "quic_max_ack_delay_ms", "quic_0rtt_early_data",
        "quic_connection_migration", "quic_multipath", "quic_grease_bit",
        "quic_spin_bit_disable", "quic_datagram_frame", "h3_qpack_max_table_capacity",
        "h3_qpack_blocked_streams", "h3_priority_extensible", "h3_server_push_reject",
        "tls13_x25519_mlkem768_hybrid", "tls13_chacha20_poly1305_prefer",
        "tls13_ech_grease", "tls13_ech_doh_lookup", "tls13_alps_negotiation",
        "tls13_cert_compression_brotli", "tls13_zero_rtt_anti_replay",
        "tcp_fast_open_client", "tcp_mptcp_subflows",
    ];
    for &sub in QUIC_TLS_SUBSYSTEMS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::NetworkDnsHttp3,
            subsystem: TargetSubsystem::RustNetworkPool,
            prefix: format!("network.transport.{}", sub),
            axes: ["enabled", "tuning_factor", "timeout_ms", "fallback_on_loss"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("Transport Feature `{}` Enabled", sub),
                        format!("Toggles low-level QUIC/HTTP3/TLS1.3 feature `{}` in the Rust transport engine.", sub),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        Some(format!("net-{}", sub)),
                        true,
                    ),
                    "tuning_factor" => (
                        "tuning_factor".into(),
                        format!("`{}` Scaling / Window Multiplier", sub),
                        format!("Quantitative tuning parameter or buffer multiplier for `{}`.", sub),
                        SettingValue::Int(32),
                        ValueConstraint::IntRange { min: 1, max: 4096 },
                        None,
                        true,
                    ),
                    "timeout_ms" => (
                        "timeout_ms".into(),
                        format!("`{}` Handshake / Probe Timeout (ms)", sub),
                        format!("Maximum duration in milliseconds before `{}` times out.", sub),
                        SettingValue::Int(2500),
                        ValueConstraint::IntRange { min: 50, max: 30000 },
                        None,
                        true,
                    ),
                    _ => (
                        "fallback_on_loss".into(),
                        format!("`{}` Graceful Fallback on >5% Packet Loss", sub),
                        format!("Automatically adapts `{}` behavior under lossy network conditions.", sub),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 21 Encrypted DNS Providers/Features x 4 controls = 84 settings
    const DNS_FEATURES: &[&str] = &[
        "mullvad_base_doh", "mullvad_adblock_doh", "mullvad_all_doq",
        "quad9_secured_doh", "quad9_doq", "cloudflare_zero_doh",
        "adguard_unfiltered_doq", "nextdns_anycast_doh", "controld_uncensored_doq",
        "wikimedia_privacy_doh", "dnscrypt_eu_nl", "dnscrypt_ch_zurich",
        "dnscrypt_is_reykjavik", "odoh_oblivious_relay", "odoh_target_proxy",
        "dnssec_bogus_reject", "qname_minimization_rfc9156", "edns0_client_subnet_strip",
        "edns0_padding_block_128", "svcb_https_record_alpn", "negative_nsec_cache",
    ];
    for &dns in DNS_FEATURES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::NetworkDnsHttp3,
            subsystem: TargetSubsystem::RustNetworkPool,
            prefix: format!("network.dns.provider.{}", dns),
            axes: ["enabled", "priority_weight", "max_rtt_ms", "verify_spki_pin"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("Encrypted DNS Feature / Upstream `{}` Enabled", dns),
                        format!("Activates encrypted DNS resolver or RFC feature `{}`.", dns),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "priority_weight" => (
                        "priority_weight".into(),
                        format!("`{}` Load-Balancing Priority Weight", dns),
                        format!("Selection weight in the Rust multi-resolver DoH/DoQ racing pool for `{}`.", dns),
                        SettingValue::Int(100),
                        ValueConstraint::IntRange { min: 1, max: 1000 },
                        None,
                        true,
                    ),
                    "max_rtt_ms" => (
                        "max_rtt_ms".into(),
                        format!("`{}` Maximum Acceptable Query RTT (ms)", dns),
                        format!("Demotes `{}` in resolver pool if median RTT exceeds this threshold.", dns),
                        SettingValue::Int(200),
                        ValueConstraint::IntRange { min: 10, max: 5000 },
                        None,
                        true,
                    ),
                    _ => (
                        "verify_spki_pin".into(),
                        format!("`{}` Strict TLS SPKI Pin Verification", dns),
                        format!("Verifies TLS certificate SPKI SHA-256 pin for `{}`.", dns),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 15 Asset Classes x 4 controls = 60 Speculative Pre-Fetch & RAM Cache settings
    const ASSET_CLASSES: &[&str] = &[
        "document_html", "stylesheet_css", "script_esm_js", "wasm_module",
        "font_woff2", "image_avif", "image_webp", "media_mp4_init",
        "fetch_json_api", "web_worker_bundle", "manifest_json", "svg_sprite",
        "shader_wgsl", "preconnect_dns_only", "preconnect_tls_0rtt",
    ];
    for &asset in ASSET_CLASSES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::NetworkDnsHttp3,
            subsystem: TargetSubsystem::RustNetworkPool,
            prefix: format!("network.cache_asset.{}", asset),
            axes: ["hover_delay_ms", "ram_cache_max_mb", "btree_persist_disk", "ttl_override_sec"],
            builder: |axis, _idx| {
                match *axis {
                    "hover_delay_ms" => (
                        "hover_delay_ms".into(),
                        format!("`{}` Speculative Pre-Fetch Hover Delay (ms)", asset),
                        format!("Delay before speculatively pre-fetching `{}` assets on link hover.", asset),
                        SettingValue::Int(50),
                        ValueConstraint::IntRange { min: 0, max: 2000 },
                        None,
                        true,
                    ),
                    "ram_cache_max_mb" => (
                        "ram_cache_max_mb".into(),
                        format!("`{}` Dedicated RAM Cache Allocation (MiB)", asset),
                        format!("In-memory zero-copy slab reservation for `{}`.", asset),
                        SettingValue::Int(64),
                        ValueConstraint::IntRange { min: 4, max: 2048 },
                        None,
                        true,
                    ),
                    "btree_persist_disk" => (
                        "btree_persist_disk".into(),
                        format!("Persist `{}` in B-Tree (`redb`) Local Index", asset),
                        format!("Stores validated `{}` payloads in encrypted B-Tree cache.", asset),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    _ => (
                        "ttl_override_sec".into(),
                        format!("`{}` Minimum Cache Retention TTL (Seconds)", asset),
                        format!("Minimum in-memory cache lifetime for immutable `{}` assets.", asset),
                        SettingValue::Int(3600),
                        ValueConstraint::IntRange { min: 0, max: 604800 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 25 uBlock Filter Lists & SOCKS5 Routing Zones x 2 controls = 50 settings
    const FILTER_LISTS: &[&str] = &[
        "ublock_filters_core", "ublock_badware_risks", "ublock_privacy_protection",
        "ublock_quick_fixes", "ublock_unbreak", "easylist_ads", "easyprivacy_trackers",
        "peter_lowe_adservers", "urlhaus_malware_domains", "phishing_army_blocklist",
        "fanboy_annoyances", "fanboy_social_blocking", "adguard_url_tracking_filter",
        "adguard_cname_trackers", "dandelion_sprout_anti_malware", "clearurls_rules",
        "legitimate_url_shorteners", "bypass_paywalls_clean_rules", "oisd_big_blocklist",
        "hagezi_multi_pro_plus", "socks5_route_onion_tor", "socks5_route_i2p_eepsite",
        "socks5_route_lokinet", "socks5_route_lan_rfc1918_direct", "socks5_route_custom_cidr",
    ];
    for &list in FILTER_LISTS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::NetworkDnsHttp3,
            subsystem: TargetSubsystem::RustNetworkPool,
            prefix: format!("network.filter_list.{}", list),
            axes: ["enabled", "refresh_interval_hours"],
            builder: |axis, _idx| {
                if *axis == "enabled" {
                    (
                        "enabled".into(),
                        format!("Network Filter / Routing Rule `{}` Active", list),
                        format!("Compiles `{}` into the Rust Aho-Corasick / Trie network blocker.", list),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                } else {
                    (
                        "refresh_interval_hours".into(),
                        format!("`{}` Differential Update Interval (Hours)", list),
                        format!("Interval in hours between differential cryptographic updates of `{}`.", list),
                        SettingValue::Int(24),
                        ValueConstraint::IntRange { min: 1, max: 720 },
                        None,
                        true,
                    )
                }
            }
        );
    }
}

fn populate_mullvad_wireguard(entries: &mut Vec<SettingEntry>) {
    // 25 core Mullvad VPN & WireGuard settings via define_settings!
    define_settings! {
        target: entries,
        category: SettingCategory::MullvadWireGuard,
        subsystem: TargetSubsystem::MullvadWireGuardTunnel,
        entries: [
            {
                key: "mullvad.account.number_16_digit",
                title: "16-Digit Mullvad Account Number (Zero-Email Authentication)",
                description: "Anonymous 16-digit Mullvad account token used exclusively for WireGuard public key registration.",
                default: SettingValue::Text("0000000000000000".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.wireguard.enabled",
                title: "Enable Built-In Userspace WireGuard (`boringtun`) Tunnel",
                description: "Routes all browser socket traffic through Singularity's in-process Rust WireGuard stack.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-mullvad-wireguard"),
                hot_reload: true,
            },
            {
                key: "mullvad.killswitch.strict_socket_drop",
                title: "Strict Atomic Socket-Layer Kill-Switch (Fail-Closed)",
                description: "Drops 100% of outbound browser TCP/UDP/QUIC packets if the Mullvad WireGuard handshake degrades or drops.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("mullvad-strict-killswitch"),
                hot_reload: true,
            },
            {
                key: "mullvad.killswitch.block_lan_traffic",
                title: "Block Local Area Network (RFC1918 / mDNS) When Kill-Switch Active",
                description: "Prevents any local subnet packet transmission while connected to Mullvad VPN.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.wireguard.mtu_bytes",
                title: "WireGuard Virtual Tunnel Interface MTU (Bytes)",
                description: "Optimal WireGuard tunnel MTU size preventing IPv4/IPv6 packet fragmentation.",
                default: SettingValue::Int(1380),
                constraint: ValueConstraint::IntRange { min: 1280, max: 1420 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.wireguard.persistent_keepalive_sec",
                title: "WireGuard Persistent Keepalive Interval (Seconds)",
                description: "NAT traversal heartbeat interval keeping the userspace WireGuard UDP mapping alive.",
                default: SettingValue::Int(25),
                constraint: ValueConstraint::IntRange { min: 10, max: 120 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.wireguard.key_rotation_interval_hours",
                title: "Automatic Local Curve25519 Keypair Rotation Interval (Hours)",
                description: "Generates a fresh X25519 WireGuard keypair in Rust and rotates it via Mullvad API.",
                default: SettingValue::Int(72),
                constraint: ValueConstraint::IntRange { min: 1, max: 720 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.quantum_resistant.psk_handshake_enabled",
                title: "Post-Quantum Resistant WireGuard PSK Handshake (ML-KEM-1024 + Classic McEliece)",
                description: "Performs a post-quantum key encapsulation exchange with Mullvad relays (`10.64.0.1:1337`) to derive an ephemeral WireGuard preshared key.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("mullvad-pq-psk"),
                hot_reload: true,
            },
            {
                key: "mullvad.daita.enabled",
                title: "DAITA — Defense Against Advanced Traffic Analysis (Maybenot v2)",
                description: "Pads WireGuard packets to constant size and injects stochastic cover traffic bursts to defeat website fingerprinting.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("mullvad-daita"),
                hot_reload: true,
            },
            {
                key: "mullvad.daita.constant_packet_size_bytes",
                title: "DAITA Constant WireGuard Payload Padding Size (Bytes)",
                description: "Pads all outgoing tunnel frames to uniform MTU-aligned block size.",
                default: SettingValue::Int(1360),
                constraint: ValueConstraint::IntRange { min: 512, max: 1420 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.daita.max_padding_bandwidth_overhead_pct",
                title: "DAITA Maybenot Cover Traffic Bandwidth Budget (%)",
                description: "Maximum percentage of dummy cover packets relative to real payload traffic.",
                default: SettingValue::Float(15.0),
                constraint: ValueConstraint::FloatRange { min: 1.0, max: 100.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.multihop.enabled",
                title: "Enable Double-Hop (Entry Relay -> Exit Relay) WireGuard Routing",
                description: "Encapsulates WireGuard traffic through an independent entry country before exiting in target country.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("mullvad-multihop"),
                hot_reload: true,
            },
            {
                key: "mullvad.multihop.entry_relay_hostname",
                title: "Multihop Entry WireGuard Relay Hostname",
                description: "Selected Mullvad entry node (e.g., `se-got-wg-001` in Gothenburg, Sweden).",
                default: SettingValue::Text("se-got-wg-001".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.multihop.exit_relay_hostname",
                title: "Multihop Exit WireGuard Relay Hostname",
                description: "Selected Mullvad exit node (e.g., `ch-zrh-wg-001` in Zurich, Switzerland).",
                default: SettingValue::Text("ch-zrh-wg-001".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.relay.ownership_filter",
                title: "Mullvad Relay Hardware Ownership Filter",
                description: "Restricts relay selection to Mullvad-owned bare-metal RAM-only servers.",
                default: SettingValue::Text("mullvad_owned_only".into()),
                constraint: ValueConstraint::AllowedValues(vec!["mullvad_owned_only".into(), "all_ram_only_relays".into(), "rented_only".into()]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.relay.min_uplink_speed_gbps",
                title: "Minimum Mullvad Relay NIC Speed (Gbps)",
                description: "Filters out relays with less than 10 Gbps or 20 Gbps network interfaces.",
                default: SettingValue::Int(10),
                constraint: ValueConstraint::IntRange { min: 1, max: 40 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.dns.content_blocker_flags",
                title: "Mullvad Internal Tunnel DNS (`100.64.0.7`) Content Blocking Mask",
                description: "Bitmask for Mullvad in-tunnel DNS blocking (Ads + Trackers + Malware + Gambling + Adult).",
                default: SettingValue::Text("ads_trackers_malware".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "unfiltered_10_64_0_1".into(),
                    "ads_trackers_malware".into(),
                    "ads_trackers_malware_social".into(),
                    "strict_all_categories".into(),
                ]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.obfuscation.udp2tcp_or_shadowsocks",
                title: "WireGuard DPI Censorship Obfuscation Transport",
                description: "Wraps WireGuard UDP datagrams in Shadowsocks AEAD or UDP-over-TCP port 443 to bypass firewall DPI.",
                default: SettingValue::Text("auto_detect_udp_or_shadowsocks".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "native_wireguard_udp".into(),
                    "auto_detect_udp_or_shadowsocks".into(),
                    "force_shadowsocks_aead".into(),
                    "force_udp2tcp_443".into(),
                ]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.split_tunnel.mode",
                title: "Per-Tab & Per-Domain Split-Tunneling Routing Mode",
                description: "Allows pinning specific browser tabs to distinct Mullvad exit countries or direct interface.",
                default: SettingValue::Text("per_tab_isolated_relays".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "global_all_tabs_single_tunnel".into(),
                    "per_tab_isolated_relays".into(),
                    "domain_rule_routing".into(),
                ]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.api.endpoint_url",
                title: "Mullvad Relay & Key Registration API Endpoint",
                description: "REST endpoint used to fetch signed relay lists and register local WireGuard public keys.",
                default: SettingValue::Text("https://api.mullvad.net/app/v1".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.api.relay_list_refresh_minutes",
                title: "Mullvad Signed Relay List Auto-Refresh Interval (Minutes)",
                description: "Frequency of background ETag-conditional relay catalog checks.",
                default: SettingValue::Int(60),
                constraint: ValueConstraint::IntRange { min: 15, max: 1440 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.socks5.in_tunnel_exit_proxy",
                title: "Route Tabs via Mullvad In-Tunnel SOCKS5 Proxy (`10.64.0.1:1080`)",
                description: "Routes browser TCP streams through Mullvad's exit-node SOCKS5 proxy for TCP fingerprint normalization.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.ipv6.in_tunnel_enabled",
                title: "Enable In-Tunnel Dual-Stack IPv6 (`fc00:bbbb:bbbb:bb01::/64`)",
                description: "Assigns Mullvad internal IPv6 address inside the WireGuard tunnel to prevent IPv6 host escape.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.boringtun.worker_threads",
                title: "Rust `boringtun` ChaCha20-Poly1305 AEAD Worker Threads",
                description: "Number of dedicated crypto threads encrypting/decrypting WireGuard transport packets.",
                default: SettingValue::Int(4),
                constraint: ValueConstraint::IntRange { min: 1, max: 16 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "mullvad.Check.am_i_mullvad_startup_verify",
                title: "Verify Exit IP Against `https://am.i.mullvad.net/json` Before First Navigation",
                description: "Holds initial tab requests until exit node verification confirms active Mullvad IP and zero DNS leaks.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
        ]
    };

    // 24 Mullvad Global Relay Locations x 4 controls = 96 settings
    const MULLVAD_REGIONS: &[&str] = &[
        "se_got_gothenburg", "se_sto_stockholm", "se_mma_malmo", "ch_zrh_zurich",
        "is_rek_reykjavik", "no_osl_oslo", "fi_hel_helsinki", "nl_ams_amsterdam",
        "de_fra_frankfurt", "de_ber_berlin", "at_vie_vienna", "dk_cph_copenhagen",
        "ch_gva_geneva", "fr_par_paris", "es_mad_madrid", "uk_lon_london",
        "us_nyc_new_york", "us_sea_seattle", "us_sjc_san_jose", "ca_tor_toronto",
        "jp_tyo_tokyo", "sg_sin_singapore", "au_syd_sydney", "br_sao_sao_paulo",
    ];
    for &region in MULLVAD_REGIONS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::MullvadWireGuard,
            subsystem: TargetSubsystem::MullvadWireGuardTunnel,
            prefix: format!("mullvad.region.{}", region),
            axes: ["allow_entry", "allow_exit", "wireguard_port", "max_latency_ms"],
            builder: |axis, _idx| {
                match *axis {
                    "allow_entry" => (
                        "allow_entry".into(),
                        format!("Mullvad Region `{}` Eligible as Multihop Entry", region),
                        format!("Permits automatic or 1-click toolbar selection of `{}` as multihop WireGuard entry node.", region),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "allow_exit" => (
                        "allow_exit".into(),
                        format!("Mullvad Region `{}` Eligible as Multihop Exit", region),
                        format!("Permits automatic or 1-click toolbar selection of `{}` as WireGuard exit node.", region),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "wireguard_port" => (
                        "wireguard_port".into(),
                        format!("Mullvad Region `{}` Preferred WireGuard UDP Port", region),
                        format!("UDP port used when connecting to `{}` relays (51820, 53, 443, 123).", region),
                        SettingValue::Int(51820),
                        ValueConstraint::IntRange { min: 53, max: 65535 },
                        None,
                        true,
                    ),
                    _ => (
                        "max_latency_ms".into(),
                        format!("Mullvad Region `{}` Auto-Failover Latency Ceiling (ms)", region),
                        format!("Switches to standby relay in `{}` if encrypted ICMP/WireGuard ping exceeds threshold.", region),
                        SettingValue::Int(120),
                        ValueConstraint::IntRange { min: 10, max: 1000 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 22 WireGuard / DAITA / Split-Tunnel Advanced Subsystems x 2 controls = 44 settings
    const WG_SUBSYSTEMS: &[&str] = &[
        "noise_ik_handshake_jitter", "cookie_reply_dos_guard", "replay_window_bitmap_size",
        "rekey_after_messages_limit", "rekey_after_time_sec", "zeroize_ephemeral_keys_on_drop",
        "daita_machine_burst_guard", "daita_machine_ack_padder", "daita_machine_http3_shaper",
        "daita_machine_timer_exponential", "pq_mceliece_460896_kem", "pq_mlkem_1024_kem",
        "killswitch_drop_arp_ndp_leaks", "killswitch_block_webrtc_stun", "killswitch_drop_icmp_unreachable",
        "split_tunnel_isolate_cookies", "split_tunnel_per_container_key", "wireguard_gso_gro_batching",
        "wireguard_ring_buffer_slots", "mullvad_api_tls_pin_check", "mullvad_ voucher_redeem_guard",
        "mullvad_device_slot_auto_prune",
    ];
    for &sub in WG_SUBSYSTEMS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::MullvadWireGuard,
            subsystem: TargetSubsystem::MullvadWireGuardTunnel,
            prefix: format!("mullvad.tuning.{}", sub),
            axes: ["enabled", "threshold_value"],
            builder: |axis, _idx| {
                if *axis == "enabled" {
                    (
                        "enabled".into(),
                        format!("WireGuard/DAITA Subsystem `{}` Active", sub),
                        format!("Enables low-level WireGuard/Mullvad cryptographic hardening parameter `{}`.", sub),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                } else {
                    (
                        "threshold_value".into(),
                        format!("WireGuard/DAITA `{}` Quantitative Parameter", sub),
                        format!("Tuning threshold or capacity constant for `{}`.", sub),
                        SettingValue::Int(256),
                        ValueConstraint::IntRange { min: 1, max: 65536 },
                        None,
                        true,
                    )
                }
            }
        );
    }
}

fn populate_rendering_gpu_performance(entries: &mut Vec<SettingEntry>) {
    // 25 core Rendering, GPU & Performance settings via define_settings!
    define_settings! {
        target: entries,
        category: SettingCategory::RenderingGpuPerformance,
        subsystem: TargetSubsystem::GpuCompositor,
        entries: [
            {
                key: "rendering.wgpu.backend_api",
                title: "Primary WGPU / Chromium Graphics Backend API",
                description: "Selects hardware graphics API for the UI compositor and Skia Graphite rasterizer.",
                default: SettingValue::Text("vulkan_1_3".into()),
                constraint: ValueConstraint::AllowedValues(vec!["vulkan_1_3".into(), "dx12_ultimate".into(), "metal_3".into(), "opengles_fallback".into()]),
                switch: Some("use-angle"),
                hot_reload: false,
            },
            {
                key: "rendering.frame_pacing.target_refresh_rate_hz",
                title: "Target Compositor Refresh Rate & Animation Frame Pacing (Hz)",
                description: "Hardware-accelerated UI shell and smooth-scroll frame pacing target (supports 200Hz / 240Hz / 360Hz / 480Hz).",
                default: SettingValue::Int(240),
                constraint: ValueConstraint::IntRange { min: 60, max: 540 },
                switch: Some("frame-pacing-hz"),
                hot_reload: true,
            },
            {
                key: "rendering.frame_pacing.adaptive_vrr_gsync_freesync",
                title: "Variable Refresh Rate (VRR / Adaptive-Sync) Present Mode",
                description: "Uses `VK_PRESENT_MODE_MAILBOX_KHR` / VRR for tear-free ultra-low-latency frame presentation.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-vrr"),
                hot_reload: true,
            },
            {
                key: "rendering.skia.graphite_dawn_enabled",
                title: "Enable Skia Graphite Next-Gen WGPU/Dawn Raster Backend",
                description: "Replaces legacy Ganesh OpenGL pipeline with multi-threaded Skia Graphite command recording.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-skia-graphite"),
                hot_reload: false,
            },
            {
                key: "rendering.raster.worker_thread_count",
                title: "GPU Tile Rasterization Worker Threads",
                description: "Number of dedicated CPU/GPU threads rasterizing DOM display lists into GPU textures.",
                default: SettingValue::Int(8),
                constraint: ValueConstraint::IntRange { min: 1, max: 64 },
                switch: Some("num-raster-threads"),
                hot_reload: false,
            },
            {
                key: "rendering.raster.zero_copy_izer",
                title: "Zero-Copy GPU Memory Buffer Tile Rasterizer",
                description: "Writes decoded raster tiles directly into GPU-mapped DMA buffers without staging copies.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-zero-copy"),
                hot_reload: false,
            },
            {
                key: "rendering.scroll.spring_stiffness",
                title: "200Hz+ Smooth Scroll Physics — Spring Stiffness (k)",
                description: "Hooke's law stiffness constant driving critically-damped inertial scrolling.",
                default: SettingValue::Float(320.0),
                constraint: ValueConstraint::FloatRange { min: 50.0, max: 1200.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.scroll.spring_damping_ratio",
                title: "200Hz+ Smooth Scroll Physics — Critical Damping Ratio (ζ)",
                description: "Damping ratio (`1.0` = critically damped with zero overshoot).",
                default: SettingValue::Float(1.0),
                constraint: ValueConstraint::FloatRange { min: 0.3, max: 2.5 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.scroll.wheel_impulse_multiplier",
                title: "Mouse Wheel & Trackpad Scroll Velocity Impulse Multiplier",
                description: "Scales pixel velocity per discrete wheel notch or high-precision gesture delta.",
                default: SettingValue::Float(1.25),
                constraint: ValueConstraint::FloatRange { min: 0.2, max: 5.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.tabs.aggressive_suspension_timeout_sec",
                title: "Aggressive Background Tab Freezing Timeout (Seconds)",
                description: "Suspends V8 execution and compresses DOM heap in Rust after tab remains backgrounded for this duration.",
                default: SettingValue::Int(90),
                constraint: ValueConstraint::IntRange { min: 10, max: 3600 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.tabs.zstd_frozen_state_compression_level",
                title: "Suspended Tab State ZSTD RAM Compression Level",
                description: "Compresses frozen tab snapshot in memory for <2ms instant restoration on tab switch.",
                default: SettingValue::Int(3),
                constraint: ValueConstraint::IntRange { min: 1, max: 19 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.tabs.never_suspend_active_audio",
                title: "Exempt Background Tabs Actively Playing Audio from Auto-Freeze",
                description: "Prevents background music/podcast tabs from being suspended.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.tabs.memory_discard_threshold_mb",
                title: "Per-Tab Renderer Resident Memory Auto-Freeze Threshold (MiB)",
                description: "Immediately freezes background tabs whose RSS exceeds this ceiling.",
                default: SettingValue::Int(512),
                constraint: ValueConstraint::IntRange { min: 128, max: 8192 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.gpu.oop_rasterization",
                title: "Out-of-Process GPU Canvas & DisplayList Rasterization (OOP-R)",
                description: "Executes Skia drawing commands directly inside the sandboxed GPU process.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-oop-rasterization"),
                hot_reload: false,
            },
            {
                key: "rendering.gpu.vulkan_pipeline_cache_disk",
                title: "Persistent Pre-Compiled SPIR-V / WGPU Pipeline State Cache",
                description: "Eliminates shader compilation micro-stutter by caching compiled SPIR-V pipelines.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.fonts.subpixel_antialiasing_oled_rgb",
                title: "OLED-Tuned Grayscale / Subpixel Font Hinting Mode",
                description: "Optimizes glyph stem contrast on diamond/RGB-stripe OLED panels to eliminate color fringing.",
                default: SettingValue::Text("oled_high_contrast_grayscale".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "oled_high_contrast_grayscale".into(),
                    "rgb_subpixel_cleartype".into(),
                    "unhinted_linear_gamma".into(),
                ]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.images.parallel_simd_avif_webp_decode",
                title: "SIMD-Accelerated Parallel Image Decoding (AVX-512 / NEON)",
                description: "Decodes AVIF, WebP, and JPEG-XL images off the main thread using GPU/SIMD workers.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.compositor.direct_scanout_fullscreen",
                title: "Direct DRM/KMS & DXGI Flip-Model Overlay Scanout",
                description: "Bypasses desktop window manager compositing for fullscreen video and WebGPU canvases.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-hardware-overlays"),
                hot_reload: true,
            },
            {
                key: "rendering.latency.max_queued_frames",
                title: "Maximum In-Flight GPU Swapchain Frames",
                description: "Sets swapchain queue depth (`1` for minimum input latency, `2` for throughput).",
                default: SettingValue::Int(1),
                constraint: ValueConstraint::IntRange { min: 1, max: 3 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.hdr.oled_true_black_pq_scrgb",
                title: "OLED True-Black HDR10 / scRGB Linear Compositing",
                description: "Preserves `#000000` zero-nit pixel turn-off on OLED displays even in HDR wide-gamut mode.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.canvas.accelerated_2d_gpu",
                title: "Hardware-Accelerated HTML5 2D Canvas",
                description: "Backs 2D canvas contexts with GPU textures rather than CPU software bitmaps.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-accelerated-2d-canvas"),
                hot_reload: true,
            },
            {
                key: "rendering.v8.background_gc_idle_tasks",
                title: "Schedule V8 Minor/Major Garbage Collection During Idle Frame Budgets",
                description: "Runs V8 Orinoco GC marking phases strictly in leftover <1.5ms inter-frame windows at 240Hz.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.dom.virtualized_layout_containment",
                title: "Automatic CSS `content-visibility: auto` Layout Containment Heuristic",
                description: "Skips offscreen DOM subtree layout work on massive pages (>10,000 nodes).",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "rendering.gpu.prefer_discrete_high_performance_adapter",
                title: "Prefer Discrete GPU Adapter Over Integrated Graphics",
                description: "Selects high-performance dGPU for WebGPU and Black Hole shader rendering when on AC power.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("force-high-performance-gpu"),
                hot_reload: false,
            },
            {
                key: "rendering.animations.ui_transition_speed_multiplier",
                title: "Global Singularity Shell Animation Speed Multiplier",
                description: "Scales all UI transitions (`0.0` = instant zero-frame snap, `1.0` = 200Hz fluid physics).",
                default: SettingValue::Float(1.0),
                constraint: ValueConstraint::FloatRange { min: 0.0, max: 3.0 },
                switch: None,
                hot_reload: true,
            },
        ]
    };

    // 25 WGPU / Vulkan Render Stages x 4 controls = 100 settings
    const GPU_STAGES: &[&str] = &[
        "tile_raster_pass", "slug_bezier_glyph_pass", "msdf_icon_pass",
        "accretion_glow_bloom_pass", "black_hole_raymarch_pass", "custom_cursor_particle_pass",
        "video_yuv_to_rgb_compute", "hdr_tonemap_pq_pass", "backdrop_blur_dual_kawase",
        "box_shadow_sdf_pass", "border_obsidian_aa_pass", "svg_path_tessellator",
        "image_lanczos3_upscaler", "canvas2d_command_buffer", "webgl_fbo_resolve",
        "webgpu_compute_dispatch", "damage_rect_scissoring", "occlusion_culling_zbuffer",
        "texture_atlas_packer", "staging_belt_ring_buffer", "spirv_async_compiler",
        "descriptor_set_pool", "timeline_semaphore_sync", "dmabuf_zero_copy_import",
        "swapchain_present_pacing",
    ];
    for &stage in GPU_STAGES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::RenderingGpuPerformance,
            subsystem: TargetSubsystem::GpuCompositor,
            prefix: format!("rendering.gpu_stage.{}", stage),
            axes: ["enabled", "msaa_samples", "workgroup_size", "vram_budget_mb"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("GPU Render Stage `{}` Hardware Acceleration", stage),
                        format!("Executes `{}` on the WGPU/Vulkan 1.3 compute/graphics queue.", stage),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "msaa_samples" => (
                        "msaa_samples".into(),
                        format!("`{}` Multisample Anti-Aliasing (MSAA) Count", stage),
                        format!("Sample count (1, 2, 4, 8) for `{}` geometry edges.", stage),
                        SettingValue::Int(4),
                        ValueConstraint::IntRange { min: 1, max: 8 },
                        None,
                        true,
                    ),
                    "workgroup_size" => (
                        "workgroup_size".into(),
                        format!("`{}` Compute Shader Workgroup Threads", stage),
                        format!("WGSL `@workgroup_size` thread dispatch dimension for `{}`.", stage),
                        SettingValue::Int(64),
                        ValueConstraint::IntRange { min: 16, max: 256 },
                        None,
                        true,
                    ),
                    _ => (
                        "vram_budget_mb".into(),
                        format!("`{}` Dedicated VRAM Pool Ceiling (MiB)", stage),
                        format!("Maximum GPU device-local memory allocated to `{}`.", stage),
                        SettingValue::Int(128),
                        ValueConstraint::IntRange { min: 8, max: 2048 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 24 Frame Pacing & Scroll Physics Axes x 4 controls = 96 settings
    const PACING_AXES: &[&str] = &[
        "vsync_phase_prediction", "input_event_coalescing", "pointer_raw_update_200hz",
        "scroll_momentum_decay", "scroll_rubberband_overshoot", "scroll_snap_magnetism",
        "tab_switch_crossfade", "omnibox_dropdown_morph", "find_in_page_highlight_pulse",
        "pip_window_spring_snap", "sidebar_slide_physics", "tooltip_micro_fade",
        "context_menu_scale_pop", "cursor_trail_verlet_rope", "black_hole_lensing_time_step",
        "media_scrub_waveform_seek", "settings_virtual_list_scroll", "dom_resize_observer_throttle",
        "request_animation_frame_240hz", "intersection_observer_margin", "idle_callback_budget_us",
        "main_thread_compositor_commit", "layer_tree_impl_activation", "checkerboard_tile_fade",
    ];
    for &axis_name in PACING_AXES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::RenderingGpuPerformance,
            subsystem: TargetSubsystem::GpuCompositor,
            prefix: format!("rendering.pacing.{}", axis_name),
            axes: ["enabled", "target_budget_us", "stiffness_coeff", "damping_coeff"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("200Hz+ Frame Pacing Controller for `{}`", axis_name),
                        format!("Enables high-frequency frame-paced updates for `{}`.", axis_name),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "target_budget_us" => (
                        "target_budget_us".into(),
                        format!("`{}` Maximum Frame Time Budget (Microseconds)", axis_name),
                        format!("Target execution budget in microseconds per 240Hz frame (4166us total) for `{}`.", axis_name),
                        SettingValue::Int(850),
                        ValueConstraint::IntRange { min: 50, max: 8000 },
                        None,
                        true,
                    ),
                    "stiffness_coeff" => (
                        "stiffness_coeff".into(),
                        format!("`{}` Spring Physics Stiffness Coefficient", axis_name),
                        format!("Spring constant k for `{}` interpolation.", axis_name),
                        SettingValue::Float(280.0),
                        ValueConstraint::FloatRange { min: 10.0, max: 2000.0 },
                        None,
                        true,
                    ),
                    _ => (
                        "damping_coeff".into(),
                        format!("`{}` Spring Physics Damping Coefficient", axis_name),
                        format!("Viscous damping coefficient c for `{}`.", axis_name),
                        SettingValue::Float(28.0),
                        ValueConstraint::FloatRange { min: 1.0, max: 200.0 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 47 Memory Pressure & Tab Suspension Metrics x 2 controls = 94 settings
    const MEMORY_METRICS: &[&str] = &[
        "v8_old_generation_heap", "v8_young_generation_semi_space", "v8_code_range_executable",
        "v8_wasm_linear_memory", "v8_external_array_buffers", "blink_dom_node_arena",
        "blink_css_style_sheet_pool", "blink_layout_object_tree", "blink_decoded_image_cache",
        "blink_font_glyph_cache", "skia_gr_context_resource_cache", "wgpu_staging_buffer_pool",
        "wgpu_texture_mipmap_atlas", "network_prefetched_body_slab", "media_demuxer_packet_queue",
        "media_decoded_video_frame_pool", "audio_ring_buffer_frames", "web_worker_isolate_heap",
        "service_worker_idle_process", "indexed_db_leveldb_block_cache", "redb_page_cache_mmap",
        "adblocker_aho_corasick_automaton", "dns_record_lru_slab", "wireguard_packet_pool",
        "vault_decrypted_entry_arena", "tab_thumbnail_oled_preview", "history_navigation_bfcache",
        "bfcache_max_pages_per_tab", "subframe_process_reuse_threshold", "spare_renderer_warm_process",
        "gpu_shader_binary_lru", "wayland_dmabuf_surface_pool", "cursor_animated_frame_cache",
        "pdf_disabled_zero_footprint", "webrtc_jitter_buffer_pool", "websocket_frame_reassembly",
        "fetch_stream_backpressure_window", "console_log_ring_buffer", "devtools_protocol_ detached",
        "crashpad_disabled_zero_overhead", "uma_disabled_zero_overhead", "rlz_disabled_zero_overhead",
        "variations_disabled_zero_overhead", "safebrowsing_disabled_zero_overhead",
        "widevine_unloaded_zero_overhead", "extensions_disabled_zero_overhead",
        "zstd_page_compressor_dictionary",
    ];
    for &metric in MEMORY_METRICS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::RenderingGpuPerformance,
            subsystem: TargetSubsystem::GpuCompositor,
            prefix: format!("rendering.memory.{}", metric),
            axes: ["soft_limit_mb", "purge_on_tab_freeze"],
            builder: |axis, _idx| {
                if *axis == "soft_limit_mb" {
                    (
                        "soft_limit_mb".into(),
                        format!("Memory Subsystem `{}` Soft Quota (MiB)", metric),
                        format!("Soft memory ceiling in MiB before triggering compaction for `{}`.", metric),
                        SettingValue::Int(64),
                        ValueConstraint::IntRange { min: 0, max: 4096 },
                        None,
                        true,
                    )
                } else {
                    (
                        "purge_on_tab_freeze".into(),
                        format!("Zeroize & Release `{}` When Tab Suspends", metric),
                        format!("Immediately reclaims OS physical pages for `{}` when a tab enters frozen state.", metric),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                }
            }
        );
    }
}

fn populate_password_manager_crypto(entries: &mut Vec<SettingEntry>) {
    // 24 core Password Manager & Cryptography settings via define_settings!
    define_settings! {
        target: entries,
        category: SettingCategory::PasswordManagerCrypto,
        subsystem: TargetSubsystem::Argon2Vault,
        entries: [
            {
                key: "vault.crypto.kdf_algorithm",
                title: "Master Key Derivation Function (KDF)",
                description: "RFC 9106 Argon2id memory-hard key derivation protecting the local `.singularity-vault`.",
                default: SettingValue::Text("Argon2id_v19".into()),
                constraint: ValueConstraint::AllowedValues(vec!["Argon2id_v19".into()]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.crypto.argon2id_memory_kib",
                title: "Argon2id Memory Cost Parameter (m in KiB)",
                description: "RAM required per master key derivation attempt (65536 KiB = 64 MiB, resistant to GPU/ASIC cracking).",
                default: SettingValue::Int(65536),
                constraint: ValueConstraint::IntRange { min: 19456, max: 1048576 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.crypto.argon2id_iterations_t",
                title: "Argon2id Time Cost / Iterations Parameter (t)",
                description: "Number of memory passes performed during Argon2id key derivation.",
                default: SettingValue::Int(4),
                constraint: ValueConstraint::IntRange { min: 1, max: 32 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.crypto.argon2id_parallelism_p",
                title: "Argon2id Parallelism Lanes Parameter (p)",
                description: "Number of independent parallel memory lanes during Argon2id KDF execution.",
                default: SettingValue::Int(4),
                constraint: ValueConstraint::IntRange { min: 1, max: 16 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.crypto.aead_cipher",
                title: "Authenticated Encryption with Associated Data (AEAD) Cipher",
                description: "Encrypts all credentials, TOTP secrets, and passkey private keys with 192-bit nonce XChaCha20-Poly1305.",
                default: SettingValue::Text("XChaCha20-Poly1305".into()),
                constraint: ValueConstraint::AllowedValues(vec!["XChaCha20-Poly1305".into()]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.lock.idle_auto_lock_seconds",
                title: "Vault Inactivity Auto-Lock & RAM Zeroization Timer (Seconds)",
                description: "Automatically wipes decrypted vault keys from RAM via `zeroize` after user idle period.",
                default: SettingValue::Int(300),
                constraint: ValueConstraint::IntRange { min: 15, max: 86400 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.lock.lock_on_window_minimize_or_suspend",
                title: "Immediate Vault Lock on OS Sleep or Browser Minimize",
                description: "Shreds in-memory master key immediately upon ACPI suspend or window unfocus.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.clipboard.auto_clear_delay_seconds",
                title: "Clipboard Credential & TOTP Auto-Scrub Delay (Seconds)",
                description: "Overwrites system clipboard after copying a password or TOTP code.",
                default: SettingValue::Int(20),
                constraint: ValueConstraint::IntRange { min: 5, max: 300 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.totp.default_digits",
                title: "RFC 6238 TOTP Default Code Length (Digits)",
                description: "Standard 6-digit or 8-digit TOTP token display format.",
                default: SettingValue::Int(6),
                constraint: ValueConstraint::IntRange { min: 6, max: 8 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.totp.default_period_seconds",
                title: "RFC 6238 TOTP Default Time-Step Period (Seconds)",
                description: "Time window in seconds for TOTP counter calculation.",
                default: SettingValue::Int(30),
                constraint: ValueConstraint::IntRange { min: 15, max: 60 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.totp.default_hmac_algorithm",
                title: "RFC 6238 TOTP Default HMAC Hash Algorithm",
                description: "Supports HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512 TOTP tokens.",
                default: SettingValue::Text("SHA1".into()),
                constraint: ValueConstraint::AllowedValues(vec!["SHA1".into(), "SHA256".into(), "SHA512".into()]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.passkey.software_authenticator_enabled",
                title: "Built-In FIDO2 / WebAuthn Passkey Software Authenticator",
                description: "Intercepts `navigator.credentials.create/get` and stores Ed25519/P-256 resident passkeys in the encrypted Rust vault.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.passkey.require_master_unlock_for_uv",
                title: "Require Unlocked Vault Verification for Passkey User Verification (UV)",
                description: "Ensures WebAuthn `userVerification: 'required'` assertions prompt for vault unlock.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.breach.offline_bloom_filter_enabled",
                title: "Offline Zero-Knowledge k-Anonymity Breached Password Bloom Filter",
                description: "Audits credentials locally against an embedded SHA-256 bloom filter with zero network requests.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.breach.minimum_shannon_entropy_bits",
                title: "Minimum Required Password Shannon Entropy Warning Threshold (Bits)",
                description: "Flags stored or generated passwords with less than 80 bits of entropy.",
                default: SettingValue::Float(80.0),
                constraint: ValueConstraint::FloatRange { min: 40.0, max: 256.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.generator.default_length",
                title: "Cryptographic Password Generator Default Character Length",
                description: "Default length of CSPRNG-generated passwords.",
                default: SettingValue::Int(24),
                constraint: ValueConstraint::IntRange { min: 12, max: 128 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.generator.include_uppercase",
                title: "Password Generator Include Uppercase ASCII (`A-Z`)",
                description: "Includes uppercase characters in generated credentials.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.generator.include_lowercase",
                title: "Password Generator Include Lowercase ASCII (`a-z`)",
                description: "Includes lowercase characters in generated credentials.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.generator.include_digits",
                title: "Password Generator Include Numeric Digits (`0-9`)",
                description: "Includes numeric digits in generated credentials.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.generator.include_symbols",
                title: "Password Generator Include High-Entropy Symbols (`!@#$%^&*-_=+`)",
                description: "Includes special punctuation symbols in generated credentials.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.generator.exclude_ambiguous_homoglyphs",
                title: "Exclude Visually Ambiguous Characters (`0O1lI`)",
                description: "Omits easily confused characters from generated passwords.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.autofill.disable_automatic_on_page_load",
                title: "Never Autofill Credentials on Page Load Without Explicit Keybinding",
                description: "Prevents invisible DOM input harvesting attacks by requiring explicit user shortcut (`Ctrl+Shift+L`).",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.autofill.strict_origin_and_port_match",
                title: "Require Exact Scheme + Host + Port Match for Credential Autofill",
                description: "Refuses to autofill HTTPS credentials into HTTP forms or different subdomains.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "vault.storage.file_path",
                title: "Encrypted `.singularity-vault` Local File Path",
                description: "Path to the XChaCha20-Poly1305 encrypted local vault container.",
                default: SettingValue::Text("~/.config/singularity/primary.singularity-vault".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
        ]
    };

    // 24 WebAuthn / Passkey CTAP2.1 Capabilities x 3 controls = 72 settings
    const WEBAUTHN_CAPABILITIES: &[&str] = &[
        "ed25519_eddsa_alg_minus_8", "es256_ecdsa_p256_alg_minus_7", "es384_ecdsa_p384_alg_minus_35",
        "rs256_rsa_pss_alg_minus_257", "resident_key_discoverable", "user_presence_up_flag",
        "user_verification_uv_flag", "backup_eligible_be_flag", "backup_state_bs_flag",
        "hmac_secret_prf_extension", "cred_protect_level_3", "large_blob_storage_ext",
        "min_pin_length_ext", "cred_blob_extension", "appid_u2f_backcompat",
        "attestation_none_anonymize", "attestation_packed_self", "conditional_mediation_ui",
        "cross_origin_iframe_create_block", "rp_id_psl_validation", "sign_counter_zero_privacy",
        "sign_counter_monotonic_increment", "usb_hid_passthrough_yubikey", "hybrid_qr_caBLE_block",
    ];
    for &cap in WEBAUTHN_CAPABILITIES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::PasswordManagerCrypto,
            subsystem: TargetSubsystem::Argon2Vault,
            prefix: format!("vault.webauthn.{}", cap),
            axes: ["enabled", "require_explicit_confirm", "audit_assertion"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("WebAuthn / CTAP2.1 Capability `{}` Enabled", cap),
                        format!("Enables FIDO2 passkey authenticator support for `{}`.", cap),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "require_explicit_confirm" => (
                        "require_explicit_confirm".into(),
                        format!("`{}` Require Explicit Modal Confirmation", cap),
                        format!("Displays OLED confirmation modal before fulfilling `{}` ceremony.", cap),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    _ => (
                        "audit_assertion".into(),
                        format!("`{}` Record Timestamped Usage in Encrypted Vault Log", cap),
                        format!("Appends an encrypted audit record inside the vault when `{}` is exercised.", cap),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 32 Vault Security & Anti-Phishing Guards x 2 controls = 64 settings
    const VAULT_GUARDS: &[&str] = &[
        "mlock_prevent_swap_to_disk", "prctl_set_dumpable_zero", "zeroize_on_drop_ buffers",
        "constant_time_mac_verify", "header_associated_data_bind", "key_rotation_reencrypt",
        "export_require_fresh_argon2", "import_schema_version_check", "hibp_bloom_false_positive_guard",
        "password_reuse_cross_domain_warn", "totp_clock_skew_window_steps", "totp_next_code_preview",
        "diceware_eff_large_wordlist", "diceware_word_count_default", "diceware_separator_symbol",
        "autofill_block_hidden_opacity_inputs", "autofill_block_offscreen_inputs",
        "autofill_block_cross_origin_form_action", "autofill_punycode_idn_homograph_warn",
        "autofill_levenshtein_typosquat_warn", "autofill_fill_totp_automatically",
        "clipboard_wayland_mime_secret", "clipboard_x11_selection_scrub",
        "vault_backup_atomic_rename", "vault_backup_generations_keep",
        "vault_corrupt_header_halt", "vault_canary_hmac_verify",
        "master_password_min_length", "master_password_pwned_check",
        "emergency_duress_wipe_password", "ssh_agent_ed25519_bridge",
        "age_x25519_recipient_export",
    ];
    for &guard in VAULT_GUARDS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::PasswordManagerCrypto,
            subsystem: TargetSubsystem::Argon2Vault,
            prefix: format!("vault.guard.{}", guard),
            axes: ["enabled", "strict_parameter"],
            builder: |axis, _idx| {
                if *axis == "enabled" {
                    (
                        "enabled".into(),
                        format!("Vault Cryptographic Guard `{}` Active", guard),
                        format!("Enforces zero-knowledge vault protection rule `{}`.", guard),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                } else {
                    (
                        "strict_parameter".into(),
                        format!("Vault Guard `{}` Sensitivity / Threshold Parameter", guard),
                        format!("Quantitative security threshold for `{}`.", guard),
                        SettingValue::Int(6),
                        ValueConstraint::IntRange { min: 1, max: 1024 },
                        None,
                        true,
                    )
                }
            }
        );
    }
}

fn populate_media_audio_video(entries: &mut Vec<SettingEntry>) {
    // 30 core Media, Audio & Video Engine settings via define_settings! (including 10-band Parametric EQ!)
    define_settings! {
        target: entries,
        category: SettingCategory::MediaAudioVideo,
        subsystem: TargetSubsystem::MediaPipeline,
        entries: [
            {
                key: "media.player.replace_chromium_default_controls",
                title: "Use Singularity OLED Black Floating/Docked Media Player",
                description: "Replaces Chromium's default HTML5 media controls with Singularity's hardware-accelerated OLED player.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.decoder.hardware_acceleration_backend",
                title: "Hardware Video Decode Acceleration API",
                description: "Selects VAAPI, NVDEC, Vulkan Video, or DXVA2 hardware decoding pipeline.",
                default: SettingValue::Text("vaapi_nvdec_vulkan_auto".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "vaapi_nvdec_vulkan_auto".into(),
                    "vaapi_drm".into(),
                    "nvdec_cuda".into(),
                    "vulkan_video".into(),
                    "dxva2_d3d11".into(),
                    "software_dav1d_ffmpeg".into(),
                ]),
                switch: Some("enable-accelerated-video-decode"),
                hot_reload: true,
            },
            {
                key: "media.audio.volume_boost_percent",
                title: "Audio Pre-Amp Volume Boost (0% to 400%)",
                description: "Boosts audio gain up to 400% (+12 dB) with a zero-distortion soft-knee lookahead limiter.",
                default: SettingValue::Float(100.0),
                constraint: ValueConstraint::FloatRange { min: 0.0, max: 400.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.playback.default_speed_multiplier",
                title: "Playback Speed Multiplier (`0.1x` to `16.0x`)",
                description: "Pitch-corrected WSOLA playback speed control across `0.1x` to `16.0x`.",
                default: SettingValue::Float(1.0),
                constraint: ValueConstraint::FloatRange { min: 0.1, max: 16.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.playback.frame_step_fps_fallback",
                title: "Frame-by-Frame Scrubbing Assumed FPS Fallback",
                description: "Used for exact single-frame (`1/fps` sec) forward/backward stepping when container omits frame duration.",
                default: SettingValue::Float(60.0),
                constraint: ValueConstraint::FloatRange { min: 23.976, max: 240.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.pip.auto_activate_on_tab_switch",
                title: "Automatic Picture-in-Picture (PiP) When Switching Away from Playing Video Tab",
                description: "Automatically floats active video into an OLED borderless PiP window on tab change.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.audio.sample_rate_hz",
                title: "Audio Engine Output Sample Rate (Hz)",
                description: "Target sample rate for the Rust biquad DSP pipeline (48000, 96000, 192000, 384000 Hz).",
                default: SettingValue::Int(96000),
                constraint: ValueConstraint::IntRange { min: 44100, max: 384000 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.enabled",
                title: "Enable 10-Band Parametric Biquad Audio Equalizer",
                description: "Processes all browser audio streams through a 64-bit floating-point 10-band cascaded biquad filter bank.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.active_preset",
                title: "10-Band Parametric Equalizer Active Preset",
                description: "Selects flat reference, Harman target, deep bass, vocal clarity, or custom parametric profile.",
                default: SettingValue::Text("singularity_reference_flat".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "singularity_reference_flat".into(),
                    "event_horizon_sub_bass".into(),
                    "harman_over_ear_2018".into(),
                    "vocal_podcast_clarity".into(),
                    "custom_parametric".into(),
                ]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_1_31hz_gain_db",
                title: "EQ Band 1 (31.25 Hz Sub-Bass Low-Shelf) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 31.25 Hz sub-bass band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_2_62hz_gain_db",
                title: "EQ Band 2 (62.5 Hz Deep Bass Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 62.5 Hz bass band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_3_125hz_gain_db",
                title: "EQ Band 3 (125 Hz Upper Bass Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 125 Hz warmth band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_4_250hz_gain_db",
                title: "EQ Band 4 (250 Hz Low-Mid Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 250 Hz low-midrange band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_5_500hz_gain_db",
                title: "EQ Band 5 (500 Hz Center-Mid Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 500 Hz midrange body band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_6_1khz_gain_db",
                title: "EQ Band 6 (1,000 Hz Vocal Fundamental Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 1 kHz vocal presence band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_7_2khz_gain_db",
                title: "EQ Band 7 (2,000 Hz Upper-Mid Intelligibility Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 2 kHz clarity band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_8_4khz_gain_db",
                title: "EQ Band 8 (4,000 Hz Presence / Attack Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 4 kHz transient definition band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_9_8khz_gain_db",
                title: "EQ Band 9 (8,000 Hz Brilliance / Treble Peak) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 8 kHz treble brilliance band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.band_10_16khz_gain_db",
                title: "EQ Band 10 (16,000 Hz Air High-Shelf) Gain (dB)",
                description: "Gain in decibels (-24.0 dB to +24.0 dB) for the 16 kHz high-shelf air band.",
                default: SettingValue::Float(0.0),
                constraint: ValueConstraint::FloatRange { min: -24.0, max: 24.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.eq.global_q_factor",
                title: "Parametric EQ Default Quality Factor (Q Bandwidth)",
                description: "Bandwidth selectivity Q-factor (`1.414` = 1 octave Butterworth response).",
                default: SettingValue::Float(1.414),
                constraint: ValueConstraint::FloatRange { min: 0.2, max: 12.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.subtitles.font_family",
                title: "Custom Subtitle Overlay Font Family",
                description: "Typography family rendered by Singularity's OLED subtitle engine.",
                default: SettingValue::Text("Inter Variable".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.subtitles.font_size_px",
                title: "Custom Subtitle Font Size (Pixels)",
                description: "Base subtitle glyph size in pixels at 1080p reference resolution.",
                default: SettingValue::Int(26),
                constraint: ValueConstraint::IntRange { min: 12, max: 96 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.subtitles.text_color_hex",
                title: "Custom Subtitle Foreground RGBA Color",
                description: "Hex RGBA color token for subtitle glyphs.",
                default: SettingValue::ColorHex("#FFFFFFFF".into()),
                constraint: ValueConstraint::HexColorFormat,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.subtitles.backdrop_color_hex",
                title: "Custom Subtitle Pill Backdrop RGBA Color",
                description: "Pure OLED black translucent pill backdrop behind subtitle lines.",
                default: SettingValue::ColorHex("#000000D9".into()),
                constraint: ValueConstraint::HexColorFormat,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.recorder.direct_stream_capture_enabled",
                title: "Enable Direct Lossless Stream Downloader & Recorder",
                description: "Allows 1-click remuxing and recording of MSE/HLS/DASH/MP4/WebM streams directly to disk.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.recorder.output_container_format",
                title: "Direct Stream Recorder Container Format",
                description: "Target container for recorded streams without transcoding loss (`mkv`, `mp4`, `webm`).",
                default: SettingValue::Text("mkv_matroska_lossless".into()),
                constraint: ValueConstraint::AllowedValues(vec!["mkv_matroska_lossless".into(), "mp4_fragmented".into(), "webm_opus_vp9".into()]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.autoplay.policy",
                title: "Global HTML5 Media Autoplay Policy",
                description: "Blocks unrequested video/audio autoplay until explicit user click on the media surface.",
                default: SettingValue::Text("require_explicit_user_gesture".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "allow_muted_autoplay".into(),
                    "require_explicit_user_gesture".into(),
                    "block_all_autoplay".into(),
                ]),
                switch: Some("autoplay-policy"),
                hot_reload: true,
            },
            {
                key: "media.drm.widevine_cdm_opt_in",
                title: "Widevine DRM CDM Binary Module (Disabled by Default for Privacy)",
                description: "Stripped by default; enable only if user explicitly opts into proprietary EME DRM playback.",
                default: SettingValue::Bool(false),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-widevine-opt-in"),
                hot_reload: false,
            },
            {
                key: "media.codec.prefer_av1_over_hevc_vp9",
                title: "Prefer Royalty-Free AV1 Codec in MSE / WebRTC Negotiation",
                description: "Prioritizes hardware/dav1d AV1 streams over H.264/HEVC/VP9 when advertised by media servers.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "media.pip.default_window_width_px",
                title: "Floating Picture-in-Picture Default Width (Pixels)",
                description: "Initial width of the borderless OLED PiP overlay window.",
                default: SettingValue::Int(480),
                constraint: ValueConstraint::IntRange { min: 240, max: 1920 },
                switch: None,
                hot_reload: true,
            },
        ]
    };

    // 18 Media Codecs x 4 controls = 72 Codec Priority & Hardware Decode settings
    const MEDIA_CODECS: &[&str] = &[
        "av1_main_8bit", "av1_high_10bit", "hevc_main_8bit", "hevc_main10_hdr10",
        "vp9_profile0", "vp9_profile2_10bit", "h264_high", "vvc_h266_experimental",
        "opus_multichannel", "flac_24bit_lossless", "aac_lc", "aac_he_v2",
        "ac3_dolby", "eac3_atmos", "vorbis_ogg", "pcm_float64",
        "alac_apple_lossless", "mp3_lame",
    ];
    for (rank_idx, &codec) in MEDIA_CODECS.iter().enumerate() {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::MediaAudioVideo,
            subsystem: TargetSubsystem::MediaPipeline,
            prefix: format!("media.codec_profile.{}", codec),
            axes: ["enabled", "hardware_decode_prefer", "priority_rank", "max_bitrate_kbps"],
            builder: |axis, _idx| {
                match *axis {
                    "enabled" => (
                        "enabled".into(),
                        format!("Media Codec Profile `{}` Enabled", codec),
                        format!("Exposes `{}` in `MediaSource.isTypeSupported()` and `navigator.mediaCapabilities`.", codec),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "hardware_decode_prefer" => (
                        "hardware_decode_prefer".into(),
                        format!("`{}` Prefer VAAPI/NVDEC/DXVA2 Hardware Decoder", codec),
                        format!("Routes `{}` bitstreams to GPU fixed-function decode blocks with zero-copy DMABUF output.", codec),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "priority_rank" => (
                        "priority_rank".into(),
                        format!("`{}` Stream Selection Priority Rank", codec),
                        format!("Relative preference rank for `{}` (lower = higher priority).", codec),
                        SettingValue::Int((rank_idx + 1) as i64),
                        ValueConstraint::IntRange { min: 1, max: 100 },
                        None,
                        true,
                    ),
                    _ => (
                        "max_bitrate_kbps".into(),
                        format!("`{}` Maximum Buffer Bitrate Ceiling (kbps)", codec),
                        format!("Maximum stream bitrate in kilobits/sec permitted for `{}`.", codec),
                        SettingValue::Int(120000),
                        ValueConstraint::IntRange { min: 64, max: 500000 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 29 DSP Audio, Subtitle & Stream Recorder Submodules x 2 controls = 58 settings
    const MEDIA_MODULES: &[&str] = &[
        "limiter_soft_knee_brickwall", "limiter_lookahead_delay_ms", "compressor_dynamic_range",
        "loudness_ebu_r128_normalize", "stereo_crossfeed_meier", "binaural_hrtf_spatializer",
        "dc_offset_highpass_blocker", "dither_triangular_tpdf", "resampler_sinc_window_taps",
        "pitch_shift_wsola_window", "silence_skip_vad_detector", "spectrum_analyzer_fft_bins",
        "video_deband_gradfun_shader", "video_sharpen_cas_amd", "video_motion_interpolation_200hz",
        "video_black_bar_auto_crop", "video_ambient_accretion_glow", "video_screenshot_lossless_png",
        "subtitle_ass_libass_renderer", "subtitle_hearing_impaired_sdh_filter",
        "subtitle_auto_sync_offset_ms", "subtitle_outline_stroke_width",
        "recorder_hls_m3u8_segment_merge", "recorder_dash_mpd_decrypt_clear",
        "recorder_ring_buffer_pre_roll_sec", "recorder_split_chapter_markers",
        "pip_snap_corner_magnet_px", "pip_hover_controls_autohide_ms",
        "media_session_mpris_scrub_metadata",
    ];
    for &module in MEDIA_MODULES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::MediaAudioVideo,
            subsystem: TargetSubsystem::MediaPipeline,
            prefix: format!("media.dsp_module.{}", module),
            axes: ["enabled", "intensity_parameter"],
            builder: |axis, _idx| {
                if *axis == "enabled" {
                    (
                        "enabled".into(),
                        format!("Media Engine Module `{}` Active", module),
                        format!("Enables real-time audio/video processing stage `{}`.", module),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                } else {
                    (
                        "intensity_parameter".into(),
                        format!("Media Module `{}` Tuning Parameter", module),
                        format!("Quantitative DSP/shader parameter for `{}`.", module),
                        SettingValue::Float(1.0),
                        ValueConstraint::FloatRange { min: 0.0, max: 100.0 },
                        None,
                        true,
                    )
                }
            }
        );
    }
}

fn populate_themes_cursors_ui_ux(entries: &mut Vec<SettingEntry>) {
    // 25 core Themes, Cursors & UI/UX settings via define_settings!
    define_settings! {
        target: entries,
        category: SettingCategory::ThemesCursorsUiUx,
        subsystem: TargetSubsystem::OledThemeEngine,
        entries: [
            {
                key: "ui.theme.primary_background_hex",
                title: "OLED Pure Black Primary Background Color (`#000000`)",
                description: "True zero-emission `#000000` OLED surface token across the entire browser shell.",
                default: SettingValue::ColorHex("#000000".into()),
                constraint: ValueConstraint::HexColorFormat,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.theme.obsidian_border_hex",
                title: "Subtle Obsidian 1px Structural Border Token (`#141414`)",
                description: "Hairline obsidian divider token separating panels without light bleed.",
                default: SettingValue::ColorHex("#141414".into()),
                constraint: ValueConstraint::HexColorFormat,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.theme.accretion_violet_accent_hex",
                title: "Event-Horizon Accretion Primary Accent (`#6E00FF`)",
                description: "Deep gravitational violet accent glow for active tabs, focus rings, and shader highlights.",
                default: SettingValue::ColorHex("#6E00FF".into()),
                constraint: ValueConstraint::HexColorFormat,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.theme.accretion_cyan_accent_hex",
                title: "Relativistic Jet Cyan Secondary Accent (`#00F0FF`)",
                description: "High-energy cyan telemetry and Mullvad tunnel active indicator accent.",
                default: SettingValue::ColorHex("#00F0FF".into()),
                constraint: ValueConstraint::HexColorFormat,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.theme.hot_reload_toml_path",
                title: "Hot-Reloadable Custom Theme File Path (`.toml` / `.json`)",
                description: "Watches this file via `inotify` for instant 0ms theme and WGSL shader hot-reloading.",
                default: SettingValue::Text("~/.config/singularity/themes/event_horizon_oled.toml".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.ntp.black_hole_gravitational_lensing_shader",
                title: "New Tab Page Interactive Black Hole Gravitational Lensing WGSL Shader",
                description: "Renders a real-time 200Hz Schwarzschild/Kerr black hole geodesic raymarching shader on `singularity://newtab`.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.ntp.black_hole_schwarzschild_radius",
                title: "Black Hole Shader Event Horizon Schwarzschild Radius (Rs)",
                description: "Controls the gravitational lensing radius of the New Tab Page singularity.",
                default: SettingValue::Float(1.0),
                constraint: ValueConstraint::FloatRange { min: 0.2, max: 3.5 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.ntp.black_hole_accretion_disk_spin_kerr",
                title: "Black Hole Shader Kerr Relativistic Frame-Dragging Spin (a*)",
                description: "Dimensionless spin parameter (`0.0` = Schwarzschild, `0.998` = extremal Kerr Doppler beaming).",
                default: SettingValue::Float(0.94),
                constraint: ValueConstraint::FloatRange { min: 0.0, max: 0.998 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.tabs.bar_position",
                title: "Tab Bar Layout & Orientation",
                description: "Positions the tab bar at the top, vertical left, vertical right, or completely hidden (Vim/Command-Palette only).",
                default: SettingValue::Text("vertical_left_collapsible".into()),
                constraint: ValueConstraint::AllowedValues(vec![
                    "top_compact".into(),
                    "vertical_left_collapsible".into(),
                    "vertical_right_collapsible".into(),
                    "hidden_zero_chrome".into(),
                ]),
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.tabs.vertical_sidebar_width_px",
                title: "Vertical Tab Sidebar Expanded Width (Pixels)",
                description: "Width in pixels of the vertical tab bar when expanded.",
                default: SettingValue::Int(240),
                constraint: ValueConstraint::IntRange { min: 44, max: 520 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.tabs.min_tab_width_px",
                title: "Horizontal Tab Minimum Width Bound (Pixels)",
                description: "Minimum horizontal tab width before virtualized scrolling activates.",
                default: SettingValue::Int(96),
                constraint: ValueConstraint::IntRange { min: 36, max: 300 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.tabs.tab_height_px",
                title: "Tab Item Vertical Height (Pixels)",
                description: "Ultra-compact tab row height in pixels.",
                default: SettingValue::Int(32),
                constraint: ValueConstraint::IntRange { min: 22, max: 56 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.cursor.engine_enabled",
                title: "Enable Singularity Custom Cursor & WGPU Shader Trail Engine",
                description: "Supports `.cur`, `.ani`, `.png`, `.svg`, and GPU-accelerated particle/accretion cursor shaders.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.cursor.override_website_css_cursors",
                title: "Override Website-Defined CSS `cursor:` Rules Globally",
                description: "Forces websites to use Singularity's active custom cursor pack rather than page-supplied CSS cursors.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.cursor.scale_multiplier",
                title: "Custom Cursor Scale Multiplier",
                description: "Vector/lanczos scale factor for custom cursor sprites (`0.5x` to `4.0x`).",
                default: SettingValue::Float(1.0),
                constraint: ValueConstraint::FloatRange { min: 0.5, max: 4.0 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.cursor.active_pack_path",
                title: "Active Custom Cursor Pack Directory / Archive",
                description: "Path to loaded `.cur` / `.ani` / `.svg` / WGSL cursor pack.",
                default: SettingValue::Text("builtin://cursors/singularity-event-horizon-svg".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.cursor.wgpu_accretion_trail_enabled",
                title: "Enable 200Hz+ WGPU Relativistic Cursor Glow & Trail Shader",
                description: "Renders a subtle `#6E00FF` -> `#00F0FF` zero-latency particle trail behind pointer movements.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.vim.modal_navigation_enabled",
                title: "Native Rust Vimium-Style Modal Keyboard Navigation",
                description: "Enables `j`/`k`/`d`/`u` scrolling, `f` link hint overlays, `gi` input jump, and `:` command mode natively.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.vim.link_hint_alphabet",
                title: "Vim Link-Hint (`f` / `F`) Home-Row Character Alphabet",
                description: "Ergonomic home-row keys used to generate instant zero-DOM-mutation GPU overlay link badges.",
                default: SettingValue::Text("sadfjklewcmpgh".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.typography.ui_font_family",
                title: "Primary UI Shell Font Family",
                description: "Font family used for tabs, omnibox, Mullvad HUD, and `singularity://settings`.",
                default: SettingValue::Text("Geist Sans".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.typography.monospace_font_family",
                title: "Monospace Telemetry & Flag Inspector Font Family",
                description: "Font family used for setting keys, WireGuard public keys, and network timings.",
                default: SettingValue::Text("JetBrains Mono".into()),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.omnibox.show_instant_load_latency_badge",
                title: "Display Sub-Millisecond Page Load & Pre-Connect Telemetry Badge in Omnibox",
                description: "Shows live DNS/0-RTT/Cache hit timings (e.g., `0.4ms RAM HIT • MULLVAD SE-GOT`) inside the address bar.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.mullvad_hud.show_toolbar_quick_switcher",
                title: "Show 1-Click Mullvad Country/City/Multihop Switcher in Toolbar",
                description: "Embeds live WireGuard tunnel status, DAITA indicator, and kill-switch toggle directly in the top bar.",
                default: SettingValue::Bool(true),
                constraint: ValueConstraint::Unconstrained,
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.settings.virtualized_row_height_px",
                title: "`singularity://settings` Virtualized Scroller Row Height (Pixels)",
                description: "Fixed row height enabling O(1) 240Hz virtualized scrolling across 2,165+ settings.",
                default: SettingValue::Int(54),
                constraint: ValueConstraint::IntRange { min: 36, max: 96 },
                switch: None,
                hot_reload: true,
            },
            {
                key: "ui.website_dark_mode.force_oled_pure_black_css",
                title: "Force OLED Pure Black (`#000000`) Smart Inversion on Web Pages",
                description: "Rewrites website light backgrounds to `#000000` while preserving images, videos, and canvas semantics.",
                default: SettingValue::Bool(false),
                constraint: ValueConstraint::Unconstrained,
                switch: Some("enable-force-dark"),
                hot_reload: true,
            },
        ]
    };

    // 50 UI Components x 2 RGBA Hex Tokens = 100 Granular Theme Token settings
    const UI_COMPONENTS: &[&str] = &[
        "app_root_canvas", "top_titlebar_shell", "vertical_tab_rail", "tab_item_inactive",
        "tab_item_active", "tab_item_hovered", "tab_item_frozen_suspended", "tab_audio_indicator",
        "tab_close_glyph", "tab_pinned_badge", "omnibox_container", "omnibox_focused_ring",
        "omnibox_url_domain_text", "omnibox_url_path_muted", "omnibox_https_lock_icon",
        "omnibox_autocomplete_popover", "omnibox_suggestion_selected", "mullvad_toolbar_pill",
        "mullvad_killswitch_active_led", "mullvad_daita_shield_badge", "mullvad_relay_dropdown",
        "adblocker_counter_badge", "vault_unlock_modal", "vault_totp_countdown_ring",
        "vault_entropy_meter_bar", "media_floating_dock", "media_timeline_scrubber",
        "media_eq_band_slider", "media_volume_boost_warning", "pip_window_border",
        "settings_sidebar_nav", "settings_search_input", "settings_category_pill",
        "settings_row_card", "settings_row_modified_dot", "settings_toggle_switch_on",
        "settings_toggle_switch_off", "vim_link_hint_badge", "vim_command_bar_bottom",
        "find_in_page_floating_bar", "context_menu_surface", "tooltip_surface",
        "scrollbar_thumb_minimal", "scrollbar_track_invisible", "status_bar_hover_url",
        "download_shelf_progress", "permission_prompt_card", "certificate_inspector_modal",
        "letterbox_margin_matte", "ntp_clock_typography",
    ];
    for &comp in UI_COMPONENTS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::ThemesCursorsUiUx,
            subsystem: TargetSubsystem::OledThemeEngine,
            prefix: format!("ui.token.{}", comp),
            axes: ["surface_rgba_hex", "accent_glow_rgba_hex"],
            builder: |axis, _idx| {
                if *axis == "surface_rgba_hex" {
                    (
                        "surface_rgba_hex".into(),
                        format!("UI Token `{}` Primary Surface/Text RGBA Hex", comp),
                        format!("Granular RGBA hex color override for UI component `{}`.", comp),
                        SettingValue::ColorHex("#000000FF".into()),
                        ValueConstraint::HexColorFormat,
                        None,
                        true,
                    )
                } else {
                    (
                        "accent_glow_rgba_hex".into(),
                        format!("UI Token `{}` Border / Accretion Glow RGBA Hex", comp),
                        format!("Border or event-horizon glow RGBA hex override for `{}`.", comp),
                        SettingValue::ColorHex("#6E00FFFF".into()),
                        ValueConstraint::HexColorFormat,
                        None,
                        true,
                    )
                }
            }
        );
    }

    // 18 CSS Cursor Roles x 4 controls = 72 Custom Cursor Engine settings
    const CURSOR_ROLES: &[&str] = &[
        "default_arrow", "pointer_hand", "text_ibeam", "wait_singularity",
        "progress_accretion", "crosshair_precision", "move_drag", "grab_open",
        "grabbing_closed", "not_allowed_horizon", "zoom_in_lens", "zoom_out_lens",
        "ew_resize", "ns_resize", "nesw_resize", "nwse_resize",
        "col_resize", "context_menu",
    ];
    for &role in CURSOR_ROLES {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::ThemesCursorsUiUx,
            subsystem: TargetSubsystem::CustomCursorEngine,
            prefix: format!("ui.cursor_role.{}", role),
            axes: ["asset_path", "hotspot_x_px", "hotspot_y_px", "shader_trail_intensity"],
            builder: |axis, _idx| {
                match *axis {
                    "asset_path" => (
                        "asset_path".into(),
                        format!("Custom Cursor `{}` Asset File (`.cur`/`.ani`/`.png`/`.svg`/`.wgsl`)", role),
                        format!("Path to custom cursor asset overriding the `{}` cursor state.", role),
                        SettingValue::Text(format!("builtin://cursors/event_horizon/{}.svg", role)),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    ),
                    "hotspot_x_px" => (
                        "hotspot_x_px".into(),
                        format!("Custom Cursor `{}` Hotspot X Coordinate (Pixels)", role),
                        format!("Horizontal active click hotspot offset for `{}` cursor.", role),
                        SettingValue::Int(4),
                        ValueConstraint::IntRange { min: 0, max: 128 },
                        None,
                        true,
                    ),
                    "hotspot_y_px" => (
                        "hotspot_y_px".into(),
                        format!("Custom Cursor `{}` Hotspot Y Coordinate (Pixels)", role),
                        format!("Vertical active click hotspot offset for `{}` cursor.", role),
                        SettingValue::Int(4),
                        ValueConstraint::IntRange { min: 0, max: 128 },
                        None,
                        true,
                    ),
                    _ => (
                        "shader_trail_intensity".into(),
                        format!("Custom Cursor `{}` WGPU Accretion Glow Intensity", role),
                        format!("Shader bloom and particle trail intensity when pointer is in `{}` state.", role),
                        SettingValue::Float(0.75),
                        ValueConstraint::FloatRange { min: 0.0, max: 2.0 },
                        None,
                        true,
                    ),
                }
            }
        );
    }

    // 34 Vimium-Style Modal Keybindings x 2 controls = 68 Keyboard Shortcut settings
    const VIM_COMMANDS: &[(&str, &str)] = &[
        ("scroll_down_line", "j"),
        ("scroll_up_line", "k"),
        ("scroll_half_page_down", "d"),
        ("scroll_half_page_up", "u"),
        ("scroll_to_top", "gg"),
        ("scroll_to_bottom", "G"),
        ("link_hints_current_tab", "f"),
        ("link_hints_new_tab", "F"),
        ("focus_first_text_input", "gi"),
        ("history_back", "H"),
        ("history_forward", "L"),
        ("tab_previous", "J"),
        ("tab_next", "K"),
        ("tab_close_current", "x"),
        ("tab_restore_closed", "X"),
        ("tab_new_black_hole_ntp", "t"),
        ("tab_duplicate", "yt"),
        ("tab_pin_toggle", "Alt+p"),
        ("tab_freeze_suspend_now", "zf"),
        ("omnibox_focus_open", "o"),
        ("omnibox_search_tabs", "T"),
        ("yank_current_url", "yy"),
        ("open_clipboard_url", "p"),
        ("mullvad_quick_hop_country", "Alt+m"),
        ("mullvad_emergency_killswitch", "Alt+Shift+k"),
        ("vault_autofill_credentials", "Ctrl+Shift+l"),
        ("vault_copy_totp_code", "Ctrl+Shift+u"),
        ("vault_lock_immediately", "Ctrl+Shift+0"),
        ("media_pip_toggle", "Alt+v"),
        ("media_eq_overlay_toggle", "Alt+e"),
        ("media_record_stream_toggle", "Alt+r"),
        ("settings_open_registry", "Ctrl+,"),
        ("flags_open_inspector", "Ctrl+Shift+;"),
        ("toggle_vertical_tab_bar", "Ctrl+b"),
    ];
    for &(cmd, default_bind) in VIM_COMMANDS {
        define_parameter_matrix!(
            target: entries,
            category: SettingCategory::ThemesCursorsUiUx,
            subsystem: TargetSubsystem::OledThemeEngine,
            prefix: format!("ui.keybind.{}", cmd),
            axes: ["key_sequence", "enabled_in_normal_mode"],
            builder: |axis, _idx| {
                if *axis == "key_sequence" {
                    (
                        "key_sequence".into(),
                        format!("Keyboard Shortcut for `{}`", cmd),
                        format!("Custom key chord or Vim modal sequence triggering `{}`.", cmd),
                        SettingValue::Text(default_bind.into()),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                } else {
                    (
                        "enabled_in_normal_mode".into(),
                        format!("Enable `{}` Binding in Vim Normal Mode", cmd),
                        format!("Permits triggering `{}` without modifier keys when not focused in a text input.", cmd),
                        SettingValue::Bool(true),
                        ValueConstraint::Unconstrained,
                        None,
                        true,
                    )
                }
            }
        );
    }
}
