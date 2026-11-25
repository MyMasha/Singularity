//! Hardware-Accelerated WGPU / WGSL Shaders:
//! 1. Interactive Schwarzschild Gargantua Gravitational Lensing Geodesic Raymarching Shader (`singularity://newtab`)
//! 2. 200Hz+ Custom Cursor Relativistic Accretion Particle Trail Shader

/// WGSL Fragment Shader for the `singularity://newtab` Schwarzschild Gargantua
/// Black Hole Gravitational Lensing background on an OLED Pure Black (`#000000`) canvas.
pub const BLACK_HOLE_LENSING_WGSL_SHADER: &str = r#"
struct SingularityUniforms {
    resolution: vec2<f32>,
    cursor_uv: vec2<f32>,
    time_seconds: f32,
    schwarzschild_radius: f32,
    kerr_spin: f32,
    accretion_intensity: f32,
};

@group(0) @binding(0)
var<uniform> u: SingularityUniforms;

fn geodesic_accel(p: vec3<f32>, h2: f32) -> vec3<f32> {
    let r2 = max(dot(p, p), 0.04);
    let r = sqrt(r2);
    return (-1.5 * h2 / (r2 * r2 * r)) * p;
}

@fragment
fn fs_main(@builtin(position) frag_coord: vec4<f32>) -> @location(0) vec4<f32> {
    let min_dim = max(min(u.resolution.x, u.resolution.y), 1.0);
    var uv = (frag_coord.xy - 0.5 * u.resolution) / min_dim;
    uv.x = uv.x - 0.14;

    let cam_dist = 15.6 / max(u.schwarzschild_radius, 0.25);
    let elev = 0.176 + (u.cursor_uv.y - 0.5) * 0.08;
    let azim = u.time_seconds * 0.032 + (u.cursor_uv.x - 0.5) * 0.14;

    let ro = vec3<f32>(
        cam_dist * cos(elev) * sin(azim),
        cam_dist * sin(elev),
        cam_dist * cos(elev) * cos(azim),
    );
    let forward = normalize(-ro);
    let right0 = normalize(cross(forward, vec3<f32>(0.0, 1.0, 0.0)));
    let up0 = cross(right0, forward);
    let roll = -0.155;
    let right = right0 * cos(roll) + up0 * sin(roll);
    let up = -right0 * sin(roll) + up0 * cos(roll);
    let rd = normalize(forward * 1.56 + uv.x * right + uv.y * up);

    var pos = ro;
    var vel = rd;
    let h_vec = cross(pos, vel);
    let h2 = dot(h_vec, h_vec);

    var accum = vec3<f32>(0.0);
    var trans = 1.0;
    var captured = false;
    var closest_r = 100.0;

    let c_hot = vec3<f32>(1.44, 1.28, 0.98);
    let c_gold = vec3<f32>(1.08, 0.65, 0.22);
    let c_copper = vec3<f32>(0.58, 0.18, 0.04);

    for (var i: i32 = 0; i < 48; i = i + 1) {
        let r = length(pos);
        closest_r = min(closest_r, r);
        if (r <= 1.015) {
            captured = true;
            break;
        }
        if (r > 26.0 && i > 8) {
            break;
        }

        let dt = clamp(0.165 * (r - 0.90), 0.055, 0.95);
        let a1 = geodesic_accel(pos, h2);
        let mid_pos = pos + vel * (0.5 * dt);
        let mid_vel = vel + a1 * (0.5 * dt);
        let a2 = geodesic_accel(mid_pos, h2);

        let prev_pos = pos;
        pos = pos + mid_vel * dt;
        vel = normalize(vel + a2 * dt);

        if (prev_pos.y * pos.y <= 0.0) {
            let frac = abs(prev_pos.y) / (abs(prev_pos.y) + abs(pos.y) + 1e-6);
            let hit = mix(prev_pos, pos, frac);
            let hr = length(hit.xz);
            if (hr >= 1.82 && hr <= 9.60) {
                let norm_r = clamp((hr - 1.82) / 7.78, 0.0, 1.0);
                let tangent = normalize(vec3<f32>(-hit.z, 0.0, hit.x));
                let beta = clamp(0.66 / sqrt(max(hr - 0.85, 0.40)), 0.0, 0.78);
                let cos_t = dot(tangent, -vel);
                let gamma = inverseSqrt(max(1.0 - beta * beta, 0.12));
                let doppler = 1.0 / max(gamma * (1.0 - beta * cos_t), 0.24);
                let beaming = pow(clamp(doppler, 0.28, 2.35), 2.50);

                let rings = 0.55 + 0.45 * sin(hr * 11.5 - u.time_seconds * 0.6);
                let density = smoothstep(1.82, 2.38, hr) * pow(1.0 - norm_r, 1.95) * rings;
                var base_col = mix(c_hot, c_gold, smoothstep(0.0, 0.35, norm_r));
                base_col = mix(base_col, c_copper, smoothstep(0.33, 0.94, norm_r));

                let alpha = clamp(density * (0.42 + 0.50 * beaming), 0.0, 0.96);
                accum = accum + base_col * density * beaming * 1.10 * trans * u.accretion_intensity;
                trans = trans * (1.0 - alpha);
                if (trans < 0.025) {
                    break;
                }
            }
        }
    }

    if (!captured) {
        let photon_glow = exp(-max(closest_r - 1.50, 0.0) * 8.4);
        accum = accum + vec3<f32>(1.18, 0.88, 0.52) * photon_glow * 0.42 * trans;
    }

    let x = max(vec3<f32>(0.0), accum);
    let mapped = (x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14);
    return vec4<f32>(pow(clamp(mapped, vec3<f32>(0.0), vec3<f32>(1.0)), vec3<f32>(0.92)), 1.0);
}
"#;

/// WGSL Shader for the 200Hz+ Custom Cursor Accretion Glow & Trail renderer.
pub const CURSOR_ACCRETION_TRAIL_WGSL_SHADER: &str = r#"
struct CursorTrailPoint {
    pos_px: vec2<f32>,
    age_norm: f32,
    scale: f32,
};

@fragment
fn fs_cursor_glow(@location(0) local_uv: vec2<f32>, @location(1) age_norm: f32) -> @location(0) vec4<f32> {
    let dist = length(local_uv - vec2<f32>(0.5, 0.5)) * 2.0;
    let alpha = (1.0 - smoothstep(0.0, 1.0, dist)) * (1.0 - age_norm);
    let cream = vec3<f32>(1.0, 0.92, 0.74);
    let amber = vec3<f32>(0.94, 0.62, 0.24);
    let color = mix(cream, amber, age_norm);
    return vec4<f32>(color * alpha, alpha);
}
"#;
