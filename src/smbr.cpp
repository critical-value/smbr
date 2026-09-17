#include <Rcpp.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>

using namespace Rcpp;

extern "C" {
struct smbr_context;

struct smbr_entry {
  char* name;
  int type_code;
  std::uint64_t size;
  double created;
  double modified;
};

struct smbr_dir_result {
  smbr_entry* entries;
  std::size_t len;
};

struct smbr_stat_result {
  std::uint64_t size;
  int is_directory;
  double created;
  double modified;
  double accessed;
};

struct smbr_bytes_result {
  unsigned char* data;
  std::size_t len;
};

int smbr_connect(const char*, const char*, const char*, const char*, const char*,
                 int, smbr_context**, char**);
void smbr_disconnect(smbr_context*);
void smbr_free_error(char*);
int smbr_dir(smbr_context*, const char*, smbr_dir_result*, char**);
void smbr_free_dir(smbr_dir_result*);
int smbr_stat(smbr_context*, const char*, smbr_stat_result*, char**);
int smbr_exists(smbr_context*, const char*, int*, char**);
int smbr_read(smbr_context*, const char*, smbr_bytes_result*, char**);
void smbr_free_bytes(smbr_bytes_result*);
int smbr_write(smbr_context*, const char*, const unsigned char*, std::size_t,
               const char*, char**);
int smbr_mkdir(smbr_context*, const char*, int, char**);
int smbr_delete(smbr_context*, const char*, char**);
int smbr_rename(smbr_context*, const char*, const char*, char**);
}

static smbr_context* g_ctx = nullptr;

static void require_context() {
  if (!g_ctx) stop("No active SMB context. Call smb_connect() first.");
}

static std::string take_error(char* error) {
  if (!error) return "unknown smb2 error";
  std::string message(error);
  smbr_free_error(error);
  return message;
}

static void check_status(int status, char* error, const std::string& operation) {
  if (status != 0) stop(operation + " failed: " + take_error(error));
}

static double r_time(double value) {
  return std::isnan(value) ? NA_REAL : value;
}

// [[Rcpp::export]]
void smbr_connect_cpp(std::string username, std::string password,
                      std::string workgroup = "", int debug = 0) {
  if (g_ctx) {
    smbr_disconnect(g_ctx);
    g_ctx = nullptr;
  }
  char* error = nullptr;
  smbr_context* candidate = nullptr;
  check_status(smbr_connect(username.c_str(), password.c_str(), workgroup.c_str(),
                            "", "", debug, &candidate, &error), error,
               "connect");
  g_ctx = candidate;
}

// [[Rcpp::export]]
void smbr_disconnect_cpp() {
  if (g_ctx) {
    smbr_disconnect(g_ctx);
    g_ctx = nullptr;
  }
}

// [[Rcpp::export]]
DataFrame smbr_dir_cpp(std::string url) {
  require_context();
  char* error = nullptr;
  smbr_dir_result result{nullptr, 0};
  check_status(smbr_dir(g_ctx, url.c_str(), &result, &error), error, "directory listing");

  CharacterVector name, type, comment;
  IntegerVector code;
  for (std::size_t i = 0; i < result.len; ++i) {
    const smbr_entry& entry = result.entries[i];
    name.push_back(entry.name ? entry.name : "");
    type.push_back(entry.type_code == 1 ? "directory" : "file");
    code.push_back(entry.type_code);
    comment.push_back("");
  }
  smbr_free_dir(&result);
  return DataFrame::create(_["name"] = name, _["type"] = type,
                           _["smbc_type"] = code, _["comment"] = comment);
}

// [[Rcpp::export]]
List smbr_stat_cpp(std::string url) {
  require_context();
  char* error = nullptr;
  smbr_stat_result result{};
  check_status(smbr_stat(g_ctx, url.c_str(), &result, &error), error, "stat");
  return List::create(_["size"] = static_cast<double>(result.size),
                      _["mode"] = 0,
                      _["is_directory"] = result.is_directory != 0,
                      _["mtime"] = r_time(result.modified),
                      _["atime"] = r_time(result.accessed),
                      _["ctime"] = r_time(result.created));
}

// [[Rcpp::export]]
bool smbr_exists_cpp(std::string url) {
  require_context();
  char* error = nullptr;
  int exists = 0;
  check_status(smbr_exists(g_ctx, url.c_str(), &exists, &error), error, "exists");
  return exists != 0;
}

// [[Rcpp::export]]
RawVector smbr_read_cpp(std::string url) {
  require_context();
  char* error = nullptr;
  smbr_bytes_result result{nullptr, 0};
  check_status(smbr_read(g_ctx, url.c_str(), &result, &error), error, "read");
  RawVector output(result.len);
  if (result.len > 0) {
    std::copy(result.data, result.data + result.len, output.begin());
  }
  smbr_free_bytes(&result);
  return output;
}

// [[Rcpp::export]]
void smbr_write_cpp(std::string url, RawVector data, std::string mode = "wb") {
  require_context();
  char* error = nullptr;
  const unsigned char* bytes = data.size() > 0 ? data.begin() : nullptr;
  check_status(smbr_write(g_ctx, url.c_str(), bytes, data.size(), mode.c_str(), &error),
               error, "write");
}

// [[Rcpp::export]]
void smbr_mkdir_cpp(std::string url, int mode = 0777) {
  require_context();
  char* error = nullptr;
  check_status(smbr_mkdir(g_ctx, url.c_str(), mode, &error), error, "mkdir");
}

// [[Rcpp::export]]
void smbr_delete_cpp(std::string url) {
  require_context();
  char* error = nullptr;
  check_status(smbr_delete(g_ctx, url.c_str(), &error), error, "delete");
}

// [[Rcpp::export]]
void smbr_rename_cpp(std::string from, std::string to) {
  require_context();
  char* error = nullptr;
  check_status(smbr_rename(g_ctx, from.c_str(), to.c_str(), &error), error, "rename");
}
