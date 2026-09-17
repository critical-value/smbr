# smbr

[![R-CMD-check](https://github.com/critical-value/smbr/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/critical-value/smbr/actions/workflows/R-CMD-check.yaml)

`smbr` is a focused, R-native interface to SMB/CIFS file shares. It uses the pure-Rust `smb2` library through a small Rcpp bridge and does not require Python, `reticulate`, Samba, or `libsmbclient`.

## Installation

Normal installs use a precompiled backend for supported macOS and Linux
architectures, so users do not need Rust. The matching backend archive is
downloaded from the GitHub release tagged for the package backend version and
verified against its published SHA-256 checksum.

For source builds, install Rust and Cargo. Rust 1.85 or newer is required to
compile the backend. For example, with `rustup`:

```sh
rustup toolchain install stable
```

Then install `remotes` and use it to install the package from GitHub:

```r
install.packages("remotes")
remotes::install_github("critical-value/smbr")
```

The package's `configure` script uses the precompiled backend when Cargo is
not available. Developers and continuous integration can force a local build
with `SMBR_BACKEND_MODE=cargo`; `SMBR_BACKEND_MODE=prebuilt` forces the binary
path. A Cargo build downloads the Rust dependency source from crates.io on the
first build and then reuses its local cache.

Private mirrors can be selected with `SMBR_BACKEND_BINARY_URL` or
`SMBR_BACKEND_BASE_URL`; custom archives must provide
`SMBR_BACKEND_BINARY_SHA256`.

## Usage

```r
library(smbr)

smb_connect(
  username = Sys.getenv("SMB_USER"),
  password = Sys.getenv("SMB_PASSWORD"),
  workgroup = Sys.getenv("SMB_WORKGROUP")
)

files <- smb_dir("smb://server/share/data")

csv <- smb_read("smb://server/share/data/input.csv")
writeBin(csv, "input.csv")

smb_upload("results.csv", "smb://server/share/data/results.csv")
smb_download("smb://server/share/data/results.csv", "downloaded.csv")

smb_disconnect()
```

`smbr` returns directory listings and metadata as tibbles, making operations such as `dplyr::filter(type == "file")` straightforward. File reads return raw vectors so callers can choose `readr`, `readxl`, or another parser appropriate to the file format.

## Scope

The initial release intentionally focuses on common file operations: connecting, listing, stat-ing, reading, writing, uploading, downloading, creating directories, deleting files, testing existence, and renaming. It does not attempt to reproduce every low-level option in Python's `smbclient` package.

Authentication and protocol capabilities are provided by the bundled `smb2`
version. The current context is process-local and should be disconnected
explicitly with `smb_disconnect()`.

## Continuous integration

GitHub Actions runs `R CMD check` on Linux with R release and development versions and on macOS with the Rust toolchain. A separate Linux integration job builds the Samba fixture in `.github/samba`, starts it with Docker host networking, waits for SMB port 445 to accept authenticated connections, and runs the integration test with `SMB_TEST_*` environment variables. The test credentials and share exist only inside the ephemeral CI container.

## License

MIT.
