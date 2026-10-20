use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    package: String,
    certificate_size: u32,
    certificate_hash: String,
    strict: bool,
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if self.package.len() >= 256
            || !self.package.contains('.')
            || !self.package.split('.').all(|part| {
                part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                    && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
        {
            return Err("Invalid Android package name".into());
        }
        if !(1..=1024).contains(&self.certificate_size) {
            return Err("Certificate size must be between 1 and 1024 bytes".into());
        }
        if self.certificate_hash.len() != 64
            || !self
                .certificate_hash
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("Certificate hash must be 64 lowercase hexadecimal characters".into());
        }
        Ok(())
    }

    fn encode(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n",
            self.package, self.certificate_size, self.certificate_hash, self.strict
        )
    }

    fn decode(input: &str) -> Result<Self, String> {
        let mut lines = input.lines();
        let config = Self {
            package: lines.next().ok_or("Missing package name")?.into(),
            certificate_size: lines
                .next()
                .ok_or("Missing certificate size")?
                .parse()
                .map_err(|_| "Invalid certificate size")?,
            certificate_hash: lines.next().ok_or("Missing certificate hash")?.into(),
            strict: lines
                .next()
                .ok_or("Missing strict mode")?
                .parse()
                .map_err(|_| "Invalid strict mode")?,
        };
        if lines.next().is_some() {
            return Err("Unexpected data in manager setting".into());
        }
        config.validate()?;
        Ok(config)
    }
}

fn base_apk_path(pm_path_output: &str) -> Option<PathBuf> {
    pm_path_output
        .lines()
        .filter_map(|line| line.strip_prefix("package:"))
        .map(PathBuf::from)
        .find(|path| path.file_name().is_some_and(|name| name == "base.apk"))
}

#[cfg(target_os = "android")]
pub use android::{get, reapply, reset, set};

#[cfg(target_os = "android")]
mod android {
    use super::{Config, base_apk_path};
    use crate::{apk_sign, defs, ksu_uapi, ksucalls};
    use anyhow::{Context, Result, anyhow, ensure};
    use std::fs::{self, File};
    use std::io::{ErrorKind, Write};
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const CONFIG_PATH: &str = const_format::concatcp!(defs::WORKING_DIR, "manager");

    fn lock() -> Result<File> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "Manager configuration requires root"
        );
        fs::create_dir_all(defs::WORKING_DIR)?;
        let dir = File::open(defs::WORKING_DIR)?;
        ensure!(
            unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } == 0,
            "Cannot lock manager configuration: {}",
            std::io::Error::last_os_error()
        );
        Ok(dir)
    }

    fn from_kernel(config: &ksu_uapi::ksu_manager_config) -> Result<Config> {
        fn text(bytes: &[std::ffi::c_char]) -> Result<String> {
            let bytes: Vec<u8> = bytes
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| c.to_ne_bytes()[0])
                .collect();
            Ok(String::from_utf8(bytes)?)
        }
        let config = Config {
            package: text(&config.package)?,
            certificate_size: config.certificate_size,
            certificate_hash: text(&config.certificate_hash)?,
            strict: config.strict != 0,
        };
        config.validate().map_err(|error| anyhow!(error))?;
        Ok(config)
    }

    fn apply(config: &Config) -> Result<ksu_uapi::ksu_manager_config_cmd> {
        config.validate().map_err(|error| anyhow!(error))?;
        let mut request: ksu_uapi::ksu_manager_config_cmd = unsafe { std::mem::zeroed() };
        for (to, from) in request
            .config
            .package
            .iter_mut()
            .zip(config.package.bytes())
        {
            *to = from as std::ffi::c_char;
        }
        for (to, from) in request
            .config
            .certificate_hash
            .iter_mut()
            .zip(config.certificate_hash.bytes())
        {
            *to = from as std::ffi::c_char;
        }
        request.config.certificate_size = config.certificate_size;
        request.config.strict = u8::from(config.strict);
        ksucalls::manager_config(ksu_uapi::KSU_MANAGER_CONFIG_SET, &mut request)?;
        Ok(request)
    }

    fn current() -> Result<ksu_uapi::ksu_manager_config_cmd> {
        let mut request: ksu_uapi::ksu_manager_config_cmd = unsafe { std::mem::zeroed() };
        ksucalls::manager_config(ksu_uapi::KSU_MANAGER_CONFIG_GET, &mut request)?;
        Ok(request)
    }

    fn save_and_apply(config: &Config, previous: &Config) -> Result<()> {
        let mut temporary = tempfile::NamedTempFile::new_in(defs::WORKING_DIR)?;
        temporary.write_all(config.encode().as_bytes())?;
        temporary.as_file().sync_all()?;
        apply(config)?;
        if let Err(error) = temporary.persist(CONFIG_PATH) {
            apply(previous)
                .context("Saving failed and the previous manager could not be restored")?;
            return Err(error.into());
        }
        Ok(())
    }

    fn print_status(request: &ksu_uapi::ksu_manager_config_cmd) -> Result<()> {
        let config = from_kernel(&request.config)?;
        println!("package: {}", config.package);
        println!("certificate size: {}", config.certificate_size);
        println!("certificate SHA-256: {}", config.certificate_hash);
        println!("strict: {}", config.strict);
        println!("installed: {}", request.installed != 0);
        println!("matching manager: {}", request.matches != 0);
        if request.manager_appid == u32::MAX {
            println!("active manager: none");
        } else {
            println!("active manager appid: {}", request.manager_appid);
        }
        if request.installed == 0 && !config.strict {
            println!(
                "fallback package: {}",
                from_kernel(&request.default_config)?.package
            );
        }
        Ok(())
    }

    pub fn get() -> Result<()> {
        let _lock = lock()?;
        print_status(&current()?)
    }

    fn installed_apk(package: &str) -> Result<Option<PathBuf>> {
        let output = Command::new("pm").args(["path", package]).output()?;
        Ok(base_apk_path(&String::from_utf8(output.stdout)?))
    }

    fn signature_of(apk: &Path) -> Result<(u32, String)> {
        apk_sign::get_apk_signature(apk.to_str().context("APK path must be UTF-8")?)
    }

    pub fn set(package: String, apk: Option<&Path>, strict: bool) -> Result<()> {
        let dir = lock()?;
        let request = current()?;
        let previous = from_kernel(&request.config)?;
        let mut config = from_kernel(&request.default_config)?;
        if let Some(installed) = installed_apk(&package)? {
            let signature = signature_of(&installed)?;
            if let Some(apk) = apk {
                ensure!(
                    signature == signature_of(apk)?,
                    "{} does not match the certificate of the installed {package}",
                    apk.display()
                );
            }
            (config.certificate_size, config.certificate_hash) = signature;
        } else if let Some(apk) = apk {
            (config.certificate_size, config.certificate_hash) = signature_of(apk)?;
        }
        config.package = package;
        config.strict = strict;
        save_and_apply(&config, &previous)?;
        dir.sync_all()?;
        print_status(&current()?)
    }

    pub fn reset() -> Result<()> {
        let dir = lock()?;
        let mut request = current()?;
        let previous = from_kernel(&request.config)?;
        ksucalls::manager_config(ksu_uapi::KSU_MANAGER_CONFIG_RESET, &mut request)?;
        if let Err(error) = fs::remove_file(CONFIG_PATH)
            && error.kind() != ErrorKind::NotFound
        {
            apply(&previous)
                .context("Reset failed and the previous manager could not be restored")?;
            return Err(error.into());
        }
        dir.sync_all()?;
        print_status(&current()?)
    }

    pub fn reapply(safe_mode: bool) -> Result<()> {
        let _lock = lock()?;
        if !safe_mode {
            match fs::read_to_string(CONFIG_PATH) {
                Ok(contents) => {
                    let config = Config::decode(&contents).map_err(|error| anyhow!(error))?;
                    apply(&config)?;
                    return Ok(());
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut request: ksu_uapi::ksu_manager_config_cmd = unsafe { std::mem::zeroed() };
        ksucalls::manager_config(ksu_uapi::KSU_MANAGER_CONFIG_RESET, &mut request)
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, base_apk_path};
    use std::path::PathBuf;

    fn example_config() -> Config {
        Config {
            package: "com.example.manager".into(),
            certificate_size: 850,
            certificate_hash: "ab".repeat(32),
            strict: true,
        }
    }

    #[test]
    fn saved_identity_round_trips() {
        let config = example_config();
        assert_eq!(Config::decode(&config.encode()).unwrap(), config);
    }

    #[test]
    fn rejects_invalid_identities() {
        for package in [
            "",
            "manager",
            "com..manager",
            "com.1manager",
            "com.manager/evil",
            "com.man\nager",
        ] {
            let mut config = example_config();
            config.package = package.into();
            assert!(config.validate().is_err(), "{package:?}");
        }
        let mut config = example_config();
        config.package = format!("com.{}", "a".repeat(252));
        assert!(config.validate().is_err());
        config = example_config();
        config.certificate_size = 0;
        assert!(config.validate().is_err());
        config.certificate_size = 850;
        for hash in ["a".repeat(63), "g".repeat(64), "AB".repeat(32)] {
            config.certificate_hash = hash;
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn picks_the_base_apk_from_pm_path() {
        let output = "package:/data/app/~~abc==/com.example-xyz==/base.apk\n\
                      package:/data/app/~~abc==/com.example-xyz==/split_config.arm64_v8a.apk\n";
        assert_eq!(
            base_apk_path(output),
            Some(PathBuf::from(
                "/data/app/~~abc==/com.example-xyz==/base.apk"
            ))
        );
        assert_eq!(base_apk_path(""), None);
        assert_eq!(base_apk_path("package:/data/app/x/split_a.apk"), None);
    }

    #[test]
    fn rejects_truncated_or_ambiguous_settings() {
        let encoded = example_config().encode();
        assert!(Config::decode(&encoded.replace("true", "yes")).is_err());
        assert!(Config::decode(&format!("{encoded}extra\n")).is_err());
        assert!(Config::decode("com.example.manager\n850\n").is_err());
    }
}
