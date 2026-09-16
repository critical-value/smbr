test_that("native operations require an active connection", {
  smb_disconnect()
  expect_error(smb_exists("smb://server/share/file"), "No active SMB context")
})

test_that("local transfer arguments fail before contacting SMB", {
  expect_error(
    smb_upload("does-not-exist", "smb://server/share/file"),
    "does not exist"
  )

  destination <- tempfile("smbr-existing-")
  writeBin(charToRaw("existing"), destination)
  on.exit(unlink(destination), add = TRUE)
  expect_error(
    smb_download("smb://server/share/file", destination),
    "already exists"
  )
})
