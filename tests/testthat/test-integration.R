test_that("smbr can list and transfer files over SMB", {
  host <- Sys.getenv("SMB_TEST_HOST", "")
  skip_if(host == "", "SMB_TEST_HOST is not set")

  user <- Sys.getenv("SMB_TEST_USER", "smbr")
  password <- Sys.getenv("SMB_TEST_PASSWORD", "smbrpass")
  share <- Sys.getenv("SMB_TEST_SHARE", "share")
  root <- smb_url("", host, share)
  remote <- smb_url("smbr-integration.txt", host, share)
  renamed <- smb_url("smbr-integration-renamed.txt", host, share)
  local <- tempfile("smbr-download-")
  on.exit({
    try(smb_delete(remote), silent = TRUE)
    try(smb_delete(renamed), silent = TRUE)
    try(smb_disconnect(), silent = TRUE)
    unlink(local)
  }, add = TRUE)

  smb_connect(user, password)
  expect_true(smb_exists(root))
  smb_write(remote, "hello from smbr\n")

  expect_true(smb_exists(remote))
  expect_equal(rawToChar(smb_read(remote)), "hello from smbr\n")
  smb_write(remote, "appended\n", mode = "ab")
  expect_equal(rawToChar(smb_read(remote)), "hello from smbr\nappended\n")
  expect_equal(smb_stat(remote)$size, as.double(nchar("hello from smbr\nappended\n", type = "bytes")))
  expect_true(any(smb_dir(root)$name == "smbr-integration.txt"))

  smb_rename(remote, renamed)
  expect_false(smb_exists(remote))
  expect_true(smb_exists(renamed))
  smb_rename(renamed, remote)

  smb_download(remote, local)
  expect_identical(readLines(local), c("hello from smbr", "appended"))
})
