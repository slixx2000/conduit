fn main() {
    // The winfsp DLL lives outside the loader's search path, so the binary must
    // delay-load it (winfsp_init() then resolves it from the registry). Link-arg
    // directives do not propagate from library dependencies — every binary that
    // links conduit-fs needs this.
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
}
