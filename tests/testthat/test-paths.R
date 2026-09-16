test_that("smb_url normalizes relative paths", {
  expect_equal(smb_url("folder/file.csv", "server", "share"),
               "smb://server/share/folder/file.csv")
  expect_equal(smb_url("smb://server/share/file.csv"),
               "smb://server/share/file.csv")
})

test_that("smb_url validates incomplete relative paths", {
  expect_error(smb_url("file.csv"), "server and share")
})

test_that("smb_url rejects non-scalar or missing paths", {
  expect_error(smb_url(character()), "single")
  expect_error(smb_url(c("one", "two"), "server", "share"), "single")
  expect_error(smb_url(NA_character_, "server", "share"), "single")
  expect_error(smb_url("file.csv", NA_character_, "share"), "server and share")
  expect_error(smb_url("file.csv", "server/name", "share"), "path separators")
})

test_that("smb_write validates mode before using the native layer", {
  expect_error(smb_write("smb://server/share/file", raw(), mode = character()), "mode")
  expect_error(smb_write("smb://server/share/file", raw(), mode = NA_character_), "mode")
})
