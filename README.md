# smbr

[![R-CMD-check](https://github.com/critical-value/smbr/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/critical-value/smbr/actions/workflows/R-CMD-check.yaml)

`smbr` is a focused, R-native interface to SMB/CIFS file shares. It uses Samba's `libsmbclient` library through Rcpp and does not require Python, `reticulate`, or a Python environment.

## Installation

Install the Samba development files first. On Debian or Ubuntu:

```sh
sudo apt install libsmbclient-dev pkg-config
```

Then install the package from a local checkout:

```r
install.packages("Rcpp")
install.packages("tibble")
system("R CMD INSTALL /path/to/smbr")
```

The package's `configure` script detects `libsmbclient` with `pkg-config` and produces a platform-specific `src/Makevars` file.

### User-local installation without `sudo`

`configure` also accepts a user-writable Samba installation through
`SMBR_SAMBA_PREFIX`. For example, if Samba was installed by Homebrew:

```sh
export SMBR_SAMBA_PREFIX="$(brew --prefix samba)"
R CMD INSTALL /path/to/smbr
```

For another local prefix, point the variable at the directory containing
`include/libsmbclient.h` and `lib` (or `lib64`):

```sh
export SMBR_SAMBA_PREFIX="$HOME/.local/samba"
R CMD INSTALL /path/to/smbr
```

This package does not download or build Samba automatically. The prefix must
already contain the Samba development headers and libraries.

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

Authentication and protocol capabilities are provided by the installed Samba `libsmbclient` version and its configuration. The current context is process-local and should be disconnected explicitly with `smb_disconnect()`.

## Continuous integration

GitHub Actions runs `R CMD check` on Linux with R release and development versions and on macOS with the Homebrew Samba development files. A separate Linux integration job builds the fixture in `.github/samba`, starts it with Docker host networking, waits for SMB port 445 to accept authenticated connections, and runs the integration test with `SMB_TEST_*` environment variables. The test credentials and share exist only inside the ephemeral CI container.

## License

MIT.
