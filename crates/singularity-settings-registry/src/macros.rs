//! Declarative & procedural-style macro (`define_settings!`) for registering typed,
//! bounded, hot-reloadable Singularity browser settings and Chromium FFI flag bindings.

/// Defines a batch of strongly-typed Singularity configuration entries and pushes them
/// into a target `Vec<SettingEntry>` with automatic sequential ID assignment.
#[macro_export]
macro_rules! define_settings {
    (
        target: $vec:ident,
        category: $category:expr,
        subsystem: $subsystem:expr,
        entries: [
            $(
                {
                    key: $key:expr,
                    title: $title:expr,
                    description: $desc:expr,
                    default: $default:expr,
                    constraint: $constraint:expr,
                    switch: $switch:expr,
                    hot_reload: $hot:expr $(,)?
                }
            ),* $(,)?
        ]
    ) => {
        $(
            {
                let id = $vec.len() + 1;
                let default_val = $default;
                $vec.push($crate::schema::SettingEntry {
                    id,
                    key: ($key).to_string(),
                    category: $category,
                    subsystem: $subsystem,
                    title: ($title).to_string(),
                    description: ($desc).to_string(),
                    current_value: default_val.clone(),
                    default_value: default_val,
                    constraint: $constraint,
                    chromium_switch: ($switch).map(|s: &str| s.to_string()),
                    hot_reloadable: $hot,
                });
            }
        )*
    };
}

/// Matrix-expansion macro (`define_parameter_matrix!`) for generating families of real,
/// distinct, per-directive / per-syscall / per-API / per-region / per-token settings.
#[macro_export]
macro_rules! define_parameter_matrix {
    (
        target: $vec:ident,
        category: $category:expr,
        subsystem: $subsystem:expr,
        prefix: $prefix:expr,
        axes: $axes:expr,
        builder: |$item:ident, $idx:ident| $body:block
    ) => {
        for ($idx, $item) in ($axes).iter().enumerate() {
            let (suffix, title, desc, default_val, constraint, switch, hot): (
                String,
                String,
                String,
                $crate::schema::SettingValue,
                $crate::schema::ValueConstraint,
                Option<String>,
                bool,
            ) = $body;
            let id = $vec.len() + 1;
            $vec.push($crate::schema::SettingEntry {
                id,
                key: format!("{}.{}", $prefix, suffix),
                category: $category,
                subsystem: $subsystem,
                title,
                description: desc,
                current_value: default_val.clone(),
                default_value: default_val,
                constraint,
                chromium_switch: switch,
                hot_reloadable: hot,
            });
        }
    };
}
