fn main() {
    if let Some(code) = secreq::exec::run_pty_supervisor_from_env() {
        std::process::exit(code);
    }
    if let Some(code) = secreq::exec::run_io_guardian_from_env() {
        std::process::exit(code);
    }
    std::process::exit(secreq::cli::run());
}
