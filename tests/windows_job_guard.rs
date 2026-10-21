#![cfg(windows)]

use rappct::{
    AppContainerProfile, KnownCapability, SecurityCapabilitiesBuilder, launch::JobLimits,
    launch::LaunchOptions, launch::StdioConfig, launch::launch_in_container_with_io,
};

#[test]
#[ignore]
fn job_guard_kills_on_drop() {
    if std::env::var_os("RAPPCT_ALLOW_JOB_TESTS").is_none() {
        return;
    }
    use std::path::PathBuf;
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::WaitForSingleObject;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    let name = format!("rappct.job.guard.{}", std::process::id());
    let profile = AppContainerProfile::ensure(&name, "JobGuard", None).expect("ensure profile");
    let caps = SecurityCapabilitiesBuilder::new(&profile.sid)
        .with_known(&[KnownCapability::InternetClient])
        .build()
        .expect("build caps");

    // Long-running command
    let opts = LaunchOptions {
        exe: PathBuf::from("C:/Windows/System32/cmd.exe"),
        cmdline: Some("/C ping -n 60 127.0.0.1 >NUL".into()),
        stdio: StdioConfig::Inherit,
        join_job: Some(JobLimits {
            memory_bytes: None,
            cpu_rate_percent: None,
            kill_on_job_close: true,
        }),
        ..Default::default()
    };

    let child = launch_in_container_with_io(&caps, &opts).expect("launch with job guard");
    let pid = child.pid;
    // Drop without waiting -> should kill due to JobGuard in LaunchedIo
    drop(child);

    // Verify process is gone
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        // WaitForSingleObject needs SYNCHRONIZE; without it the wait returns WAIT_FAILED.
        let h = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
        .ok();
        if let Some(hproc) = h {
            let r = WaitForSingleObject(hproc, 2000);
            assert_eq!(
                r, WAIT_OBJECT_0,
                "expected process to exit after dropping job guard"
            );
            let _ = CloseHandle(hproc);
        }
    }

    let _ = profile.delete();
}
