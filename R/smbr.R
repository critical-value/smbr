#' Connect to an SMB server
#'
#' Creates the process-local native SMB context. Credentials are held only in
#' the native context and are not written to disk.
#' @param username SMB username. Defaults to `SMB_USER`.
#' @param password SMB password. Defaults to `SMB_PASSWORD`.
#' @param workgroup Optional Windows workgroup or domain.
#' @param debug Reserved for backend diagnostics.
#' @return Invisibly, `TRUE`.
#' @export
smb_connect <- function(username = Sys.getenv("SMB_USER"),
                        password = Sys.getenv("SMB_PASSWORD"),
                        workgroup = Sys.getenv("SMB_WORKGROUP"), debug = 0L) {
  if (!is.character(username) || length(username) != 1L || is.na(username) ||
      !is.character(password) || length(password) != 1L || is.na(password) ||
      !is.character(workgroup) || length(workgroup) != 1L || is.na(workgroup) ||
      length(debug) != 1L || is.na(debug) || !is.numeric(debug)) {
    stop("username, password, and workgroup must be scalar character values; debug must be a scalar number")
  }
  smbr_connect_cpp(username, password, workgroup, as.integer(debug))
  invisible(TRUE)
}

#' Disconnect the current SMB context
#' @return Invisibly, `TRUE`.
#' @export
smb_disconnect <- function() { smbr_disconnect_cpp(); invisible(TRUE) }

#' Construct and validate an SMB URL
#' @param path A path beginning with `smb://` or a server-relative path.
#' @param server Optional server used when `path` is relative.
#' @param share Optional share used when `path` is relative.
#' @return A normalized SMB URL.
#' @export
smb_url <- function(path, server = NULL, share = NULL) {
  if (!is.character(path) || length(path) != 1L || is.na(path)) {
    stop("path must be a single, non-missing character value")
  }
  if (grepl("^smb://", path, ignore.case = TRUE)) return(path)
  if (!is.character(server) || length(server) != 1L || is.na(server) ||
      !nzchar(server) || !is.character(share) || length(share) != 1L ||
      is.na(share) || !nzchar(share)) {
    stop("path must be an smb:// URL or server and share must be supplied")
  }
  if (grepl("[/\\\\]", server) || grepl("[/\\\\]", share)) {
    stop("server and share must not contain path separators")
  }
  paste0("smb://", server, "/", share, "/", sub("^[/\\\\]+", "", path))
}

#' List an SMB directory as a tibble
#' @param path SMB URL.
#' @return A tibble with `name`, `type`, `smbc_type`, and `comment` columns.
#' @export
smb_dir <- function(path) {
  tibble::as_tibble(smbr_dir_cpp(smb_url(path)))
}

#' Return metadata for an SMB path
#' @param path SMB URL.
#' @return A one-row tibble.
#' @export
smb_stat <- function(path) tibble::as_tibble(smbr_stat_cpp(smb_url(path)))

#' Test whether an SMB path exists
#' @param path SMB URL.
#' @return A single logical value.
#' @export
smb_exists <- function(path) {
  smbr_exists_cpp(smb_url(path))
}

#' Read an SMB file into a raw vector
#' @param path SMB URL.
#' @return A raw vector.
#' @export
smb_read <- function(path) smbr_read_cpp(smb_url(path))

#' Write raw data to an SMB file
#' @param path SMB URL.
#' @param data A raw vector, character vector, or object coercible to raw text.
#' @param mode File mode, normally `wb` or `ab`.
#' @return Invisibly, the path.
#' @export
smb_write <- function(path, data, mode = "wb") {
  if (is.character(data)) data <- charToRaw(paste(data, collapse = ""))
  if (!is.raw(data)) stop("data must be raw or character")
  if (!is.character(mode) || length(mode) != 1L || is.na(mode)) {
    stop("mode must be a single, non-missing character value")
  }
  if (!grepl("^[rwa](b\\+|\\+b|b|\\+)?$", mode)) {
    stop("mode must be r, w, or a with optional b and +")
  }
  smbr_write_cpp(smb_url(path), data, mode)
  invisible(path)
}

#' Copy a local file to an SMB share
#' @param local Local file path.
#' @param remote Destination SMB URL.
#' @param overwrite Whether to replace an existing remote file.
#' @export
smb_upload <- function(local, remote, overwrite = TRUE) {
  if (!is.character(local) || length(local) != 1L || is.na(local) ||
      !is.logical(overwrite) || length(overwrite) != 1L || is.na(overwrite)) {
    stop("local must be a single path and overwrite must be a single logical value")
  }
  info <- file.info(local)
  if (is.na(info$size)) stop("local file does not exist or is not readable")
  if (!overwrite && smb_exists(remote)) stop("remote path already exists")
  smb_write(remote, readBin(local, "raw", n = info$size), "wb")
}

#' Copy an SMB file to the local filesystem
#' @param remote Source SMB URL.
#' @param local Destination local file path.
#' @param overwrite Whether to replace an existing local file.
#' @export
smb_download <- function(remote, local, overwrite = FALSE) {
  if (!is.character(local) || length(local) != 1L || is.na(local) ||
      !is.logical(overwrite) || length(overwrite) != 1L || is.na(overwrite)) {
    stop("local must be a single path and overwrite must be a single logical value")
  }
  if (file.exists(local) && !overwrite) stop("local path already exists")
  writeBin(smb_read(remote), local)
  invisible(local)
}

#' Create an SMB directory
#' @param path SMB URL.
#' @param mode Directory mode.
#' @export
smb_mkdir <- function(path, mode = 0777L) { smbr_mkdir_cpp(smb_url(path), mode); invisible(path) }

#' Delete an SMB file
#' @param path SMB URL.
#' @export
smb_delete <- function(path) { smbr_delete_cpp(smb_url(path)); invisible(path) }

#' Rename an SMB file or directory
#' @param from Existing SMB URL.
#' @param to Destination SMB URL.
#' @export
smb_rename <- function(from, to) { smbr_rename_cpp(smb_url(from), smb_url(to)); invisible(to) }
