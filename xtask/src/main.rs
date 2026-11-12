use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const CRATES_IN_PUBLISH_ORDER: &[&str] = &[
    "uni-auth-proto",
    "uni-auth-core",
    "uni-auth-sqlx",
    "uni-auth-axum",
    "uni-auth-client",
    "uni-auth",
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum BumpType {
    Patch,
    Minor,
    Major,
}

struct ReleaseOptions {
    bump_override: Option<String>,
    dry_run: bool,
    publish: bool,
    push: bool,
    allow_dirty: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "help" || args[0] == "--help" {
        print_help();
        return;
    }

    match args[0].as_str() {
        "release" => {
            let opts = parse_release_args(&args[1..]);
            run_release(opts);
        }
        "check" => {
            run_check();
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!(
        r#"uni-auth workspace release automation tool

USAGE:
    cargo xtask release [BUMP] [OPTIONS]
    cargo release-workspace [BUMP] [OPTIONS]

ARGUMENTS:
    [BUMP]           Optional version bump: 'patch', 'minor', 'major', or exact version 'X.Y.Z'.
                     If omitted, automatically determines bump from conventional commit messages!

OPTIONS:
    --dry-run        Simulate release: inspect commits, calculate version, and run 'cargo publish --dry-run'
    --publish        Publish crates directly to crates.io sequentially in dependency order
    --push           Push committed release and git tag to remote repository (triggers GitHub Actions CI)
    --allow-dirty    Allow releasing even if uncommitted git changes exist
    --help, -h       Display this help message

EXAMPLES:
    cargo xtask release                   # Auto-increments from commits, updates files, commits & tags
    cargo xtask release --dry-run         # Dry-run test of auto-increment & publishing
    cargo xtask release minor             # Manually bump minor version
    cargo xtask release --push            # Bump, tag, commit, and push to GitHub to trigger CI
    cargo xtask release --publish         # Bump, tag, commit, and publish directly to crates.io
"#
    );
}

fn parse_release_args(args: &[String]) -> ReleaseOptions {
    let mut opts = ReleaseOptions {
        bump_override: None,
        dry_run: false,
        publish: false,
        push: false,
        allow_dirty: false,
    };

    for arg in args {
        match arg.as_str() {
            "--dry-run" => opts.dry_run = true,
            "--publish" => opts.publish = true,
            "--push" => opts.push = true,
            "--allow-dirty" => opts.allow_dirty = true,
            val if !val.starts_with('-') && opts.bump_override.is_none() => {
                opts.bump_override = Some(val.to_string());
            }
            other => {
                eprintln!("Unrecognized option: {}", other);
                std::process::exit(1);
            }
        }
    }

    opts
}

fn workspace_root() -> PathBuf {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format", "plain"])
        .output()
        .expect("Failed to locate cargo workspace root");
    let manifest_path = String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 from cargo locate-project");
    let root = Path::new(manifest_path.trim())
        .parent()
        .expect("Workspace root directory not found");
    root.to_path_buf()
}

fn run_check() {
    println!("Checking entire workspace...");
    let status = Command::new("cargo")
        .args(["check", "--workspace", "--all-targets"])
        .status()
        .expect("Failed to execute cargo check");
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn run_release(opts: ReleaseOptions) {
    let root = workspace_root();
    println!("==> Working directory: {}", root.display());

    // 1. Git cleanliness check
    if !opts.allow_dirty && !opts.dry_run {
        let status = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&root)
            .output()
            .expect("Failed to check git status");
        if !status.stdout.is_empty() {
            eprintln!("Error: Working directory has uncommitted changes.");
            eprintln!("Please commit or stash your changes, or pass --allow-dirty.");
            std::process::exit(1);
        }
    }

    // 2. Read current workspace version
    let cargo_toml_path = root.join("Cargo.toml");
    let content = fs::read_to_string(&cargo_toml_path).expect("Failed to read root Cargo.toml");
    let current_version = extract_workspace_version(&content)
        .expect("Could not find [workspace.package].version in root Cargo.toml");
    println!("==> Current workspace version: v{}", current_version);

    // 3. Find latest tag and commits
    let latest_tag = get_latest_git_tag(&root);
    let commits = get_commits_since_tag(&root, latest_tag.as_deref());

    println!(
        "==> Previous release tag: {}",
        latest_tag.as_deref().unwrap_or("(none, full repository history)")
    );
    println!("==> Commits analyzed: {}", commits.len());
    for (i, c) in commits.iter().take(5).enumerate() {
        println!("    [{}] {}", i + 1, c);
    }
    if commits.len() > 5 {
        println!("    ... and {} more commits", commits.len() - 5);
    }

    // 4. Determine next version
    let (next_version, bump_type) = calculate_next_version(&current_version, &commits, opts.bump_override.as_deref());
    println!("==> Determined next version: v{} (bump: {:?})", next_version, bump_type);

    if opts.dry_run {
        println!("\n*** DRY RUN MODE ENABLED - No files or git state will be modified ***\n");
    }

    // 5. Update Cargo.toml manifests
    if !opts.dry_run {
        println!("==> Updating root Cargo.toml with version {}...", next_version);
        let updated_content = update_cargo_toml_version(&content, &current_version, &next_version);
        fs::write(&cargo_toml_path, updated_content).expect("Failed to write updated root Cargo.toml");

        // 6. Generate/update CHANGELOG.md
        println!("==> Updating CHANGELOG.md...");
        update_changelog(&root, &next_version, &commits);

        // 7. Update Cargo.lock via cargo check
        println!("==> Updating Cargo.lock...");
        let check_status = Command::new("cargo")
            .args(["check", "--workspace"])
            .current_dir(&root)
            .status()
            .expect("Failed to run cargo check to sync Cargo.lock");
        if !check_status.success() {
            eprintln!("Error: 'cargo check' failed after updating Cargo.toml");
            std::process::exit(1);
        }

        // 8. Git Commit & Tag
        let tag_name = format!("v{}", next_version);
        let commit_msg = format!("chore(release): {}", tag_name);
        println!("==> Creating release commit: '{}'", commit_msg);

        let add_status = Command::new("git")
            .args(["add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md"])
            .current_dir(&root)
            .status()
            .expect("Failed to git add");
        if !add_status.success() {
            eprintln!("Failed to git add files");
            std::process::exit(1);
        }

        let commit_status = Command::new("git")
            .args(["commit", "-m", &commit_msg])
            .current_dir(&root)
            .status()
            .expect("Failed to git commit");
        if !commit_status.success() {
            eprintln!("Failed to git commit release");
            std::process::exit(1);
        }

        println!("==> Creating git tag: '{}'", tag_name);
        let tag_status = Command::new("git")
            .args(["tag", "-a", &tag_name, "-m", &format!("Release {}", tag_name)])
            .current_dir(&root)
            .status()
            .expect("Failed to git tag");
        if !tag_status.success() {
            eprintln!("Failed to git tag release");
            std::process::exit(1);
        }

        // 9. Git Push if requested
        if opts.push {
            println!("==> Pushing release commit and tags to origin...");
            let push_status = Command::new("git")
                .args(["push", "origin", "HEAD", "--tags"])
                .current_dir(&root)
                .status()
                .expect("Failed to git push");
            if !push_status.success() {
                eprintln!("Warning: Failed to push commit and tags to origin.");
            } else {
                println!("==> Successfully pushed to origin. GitHub Actions release workflow triggered!");
            }
        }
    }

    // 10. Publishing
    if opts.publish || opts.dry_run {
        println!("\n==> Processing crates in topological publish order:");
        for &crate_name in CRATES_IN_PUBLISH_ORDER {
            println!("\n---> Package: {} (v{})", crate_name, next_version);
            let mut cmd = Command::new("cargo");
            cmd.args(["publish", "-p", crate_name]).current_dir(&root);

            if opts.dry_run {
                cmd.arg("--dry-run");
            }
            if opts.allow_dirty || opts.dry_run {
                cmd.arg("--allow-dirty");
            }

            let status = cmd.status().expect("Failed to execute cargo publish");
            if !status.success() {
                if opts.dry_run {
                    println!("    [Note] Sibling dependencies are not yet published to crates.io index.");
                    println!("    In actual release, earlier crates are published first and become available in the index.");
                } else {
                    eprintln!("Failed to publish package '{}'", crate_name);
                    std::process::exit(1);
                }
            }

            if opts.publish && !opts.dry_run {
                println!("Waiting 15 seconds for crates.io registry index propagation...");
                thread::sleep(Duration::from_secs(15));
            }
        }
    }

    println!("\n=======================================================");
    if opts.dry_run {
        println!("DRY RUN COMPLETE: Next version would be v{}", next_version);
    } else {
        println!("RELEASE v{} COMPLETED SUCCESSFULLY!", next_version);
        if !opts.push && !opts.publish {
            println!("\nNext steps:");
            println!("  1. Push release commit and tag to GitHub to trigger CI publication:");
            println!("       git push origin HEAD --tags");
            println!("  2. Or publish directly from local machine:");
            println!("       cargo release-workspace --publish");
        }
    }
    println!("=======================================================\n");
}

fn extract_workspace_version(content: &str) -> Option<String> {
    let mut in_workspace_package = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_workspace_package = true;
            continue;
        }
        if trimmed.starts_with('[') && in_workspace_package {
            break;
        }
        if in_workspace_package && trimmed.starts_with("version") {
            if let Some((_, val)) = trimmed.split_once('=') {
                return Some(val.trim().trim_matches('"').trim().to_string());
            }
        }
    }
    None
}

fn update_cargo_toml_version(content: &str, old_version: &str, new_version: &str) -> String {
    let mut output = String::new();
    let mut in_workspace_package = false;
    let mut in_workspace_deps = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_workspace_package = true;
            in_workspace_deps = false;
            output.push_str(line);
            output.push('\n');
            continue;
        } else if trimmed == "[workspace.dependencies]" {
            in_workspace_deps = true;
            in_workspace_package = false;
            output.push_str(line);
            output.push('\n');
            continue;
        } else if trimmed.starts_with('[') {
            in_workspace_package = false;
            in_workspace_deps = false;
        }

        if in_workspace_package && trimmed.starts_with("version") {
            output.push_str(&format!("version = \"{}\"\n", new_version));
            continue;
        }

        if in_workspace_deps {
            if trimmed.starts_with("uni-auth") && line.contains(&format!("version = \"{}\"", old_version)) {
                let replaced = line.replace(
                    &format!("version = \"{}\"", old_version),
                    &format!("version = \"{}\"", new_version),
                );
                output.push_str(&replaced);
                output.push('\n');
                continue;
            }
        }

        output.push_str(line);
        output.push('\n');
    }

    output
}

fn get_latest_git_tag(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0", "--match", "v*"])
        .current_dir(root)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if output.status.success() {
        let tag = String::from_utf8(output.stdout).ok()?;
        let trimmed = tag.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn get_commits_since_tag(root: &Path, tag: Option<&str>) -> Vec<String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(root);
    if let Some(t) = tag {
        cmd.args(["log", &format!("{}..HEAD", t), "--pretty=format:%B%x1f"]);
    } else {
        cmd.args(["log", "--pretty=format:%B%x1f"]);
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    text.split('\x1f')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn calculate_next_version(
    current: &str,
    commits: &[String],
    override_bump: Option<&str>,
) -> (String, BumpType) {
    let parts: Vec<u64> = current
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    let (mut major, mut minor, mut patch) = if parts.len() == 3 {
        (parts[0], parts[1], parts[2])
    } else {
        (0, 1, 0)
    };

    if let Some(arg) = override_bump {
        match arg.to_lowercase().as_str() {
            "patch" => {
                patch += 1;
                return (format!("{}.{}.{}", major, minor, patch), BumpType::Patch);
            }
            "minor" => {
                minor += 1;
                patch = 0;
                return (format!("{}.{}.{}", major, minor, patch), BumpType::Minor);
            }
            "major" => {
                major += 1;
                minor = 0;
                patch = 0;
                return (format!("{}.{}.{}", major, minor, patch), BumpType::Major);
            }
            exact if exact.contains('.') => {
                return (exact.trim_start_matches('v').to_string(), BumpType::Minor);
            }
            other => {
                eprintln!("Invalid bump specification '{}'. Use patch, minor, major, or X.Y.Z", other);
                std::process::exit(1);
            }
        }
    }

    // Auto-detect from conventional commits
    let mut has_breaking = false;
    let mut has_feat = false;

    for msg in commits {
        let lower = msg.to_lowercase();
        if lower.contains("breaking change") || lower.contains("!:") {
            has_breaking = true;
            break;
        }
        if lower.starts_with("feat:") || lower.starts_with("feat(") {
            has_feat = true;
        }
    }

    if has_breaking {
        if major == 0 {
            // For 0.x.y semver, breaking changes bump minor
            minor += 1;
            patch = 0;
        } else {
            major += 1;
            minor = 0;
            patch = 0;
        }
        (format!("{}.{}.{}", major, minor, patch), BumpType::Major)
    } else if has_feat {
        if major == 0 {
            // For initial 0.1.x development, features bump minor or patch; bumping minor is conventional
            minor += 1;
            patch = 0;
        } else {
            minor += 1;
            patch = 0;
        }
        (format!("{}.{}.{}", major, minor, patch), BumpType::Minor)
    } else {
        patch += 1;
        (format!("{}.{}.{}", major, minor, patch), BumpType::Patch)
    }
}

fn update_changelog(root: &Path, version: &str, commits: &[String]) {
    let changelog_path = root.join("CHANGELOG.md");
    let existing = if changelog_path.exists() {
        fs::read_to_string(&changelog_path).unwrap_or_default()
    } else {
        "# Changelog\n\nAll notable changes to this project are documented in this file.\n".to_string()
    };

    let today = get_current_date();
    let mut new_entry = format!("\n## [{}] - {}\n\n", version, today);

    let mut feats = Vec::new();
    let mut fixes = Vec::new();
    let mut others = Vec::new();

    for c in commits {
        let trimmed = c.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("feat") {
            feats.push(trimmed);
        } else if trimmed.starts_with("fix") {
            fixes.push(trimmed);
        } else {
            others.push(trimmed);
        }
    }

    if !feats.is_empty() {
        new_entry.push_str("### Features\n");
        for f in feats {
            new_entry.push_str(&format!("- {}\n", f));
        }
        new_entry.push('\n');
    }

    if !fixes.is_empty() {
        new_entry.push_str("### Bug Fixes\n");
        for f in fixes {
            new_entry.push_str(&format!("- {}\n", f));
        }
        new_entry.push('\n');
    }

    if !others.is_empty() {
        new_entry.push_str("### Other Changes\n");
        for o in others {
            new_entry.push_str(&format!("- {}\n", o));
        }
        new_entry.push('\n');
    }

    // Insert new entry after main header
    let updated = if let Some(idx) = existing.find("## [") {
        let (header, rest) = existing.split_at(idx);
        format!("{}{}{}", header, new_entry, rest)
    } else {
        format!("{}{}", existing, new_entry)
    };

    fs::write(changelog_path, updated).expect("Failed to write CHANGELOG.md");
}

fn get_current_date() -> String {
    let output = Command::new("git")
        .args(["log", "-1", "--format=%cs"])
        .output();
    if let Ok(out) = output {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    "2026-11-12".to_string()
}
