fn main() {
    // Delay-load winfsp-x64.dll: binaries must start on machines without the
    // driver so the app can *detect* the missing driver and guide the install.
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
}
