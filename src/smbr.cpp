#include <Rcpp.h>
#include <libsmbclient.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace Rcpp;

static std::string g_user;
static std::string g_password;
static std::string g_workgroup;
static SMBCCTX* g_ctx = nullptr;

static void clear_string(std::string& value) {
  std::fill(value.begin(), value.end(), '\0');
  value.clear();
  value.shrink_to_fit();
}

static void clear_credentials() {
  clear_string(g_user);
  clear_string(g_password);
  clear_string(g_workgroup);
}

static void copy_auth_value(char* destination, int capacity,
                            const std::string& value) {
  if (!destination || capacity <= 0) return;
  const size_t count = std::min(value.size(), static_cast<size_t>(capacity - 1));
  std::memcpy(destination, value.data(), count);
  destination[count] = '\0';
}

static void auth_cb(const char* srv, const char* shr, char* wg, int wglen,
                    char* un, int unlen, char* pw, int pwlen) {
  (void)srv;
  (void)shr;
  copy_auth_value(wg, wglen, g_workgroup);
  copy_auth_value(un, unlen, g_user);
  copy_auth_value(pw, pwlen, g_password);
}

static SMBCCTX* context() {
  if (!g_ctx) stop("No active SMB context. Call smb_connect() first.");
  return g_ctx;
}

static void check(int result, const std::string& operation) {
  if (result < 0) {
    const int error = errno;
    stop(operation + " failed: " + std::strerror(error));
  }
}

// [[Rcpp::export]]
void smbr_connect_cpp(std::string username, std::string password,
                      std::string workgroup = "", int debug = 0) {
  if (g_ctx) { smbc_free_context(g_ctx, 1); g_ctx = nullptr; }
  clear_credentials();
  g_user = username; g_password = password; g_workgroup = workgroup;
  SMBCCTX* candidate = smbc_new_context();
  if (!candidate) {
    clear_credentials();
    stop("Unable to allocate libsmbclient context.");
  }
  g_ctx = candidate;
  smbc_setDebug(g_ctx, debug);
  smbc_setFunctionAuthData(g_ctx, auth_cb);
  if (!smbc_init_context(g_ctx)) {
    smbc_free_context(g_ctx, 1);
    g_ctx = nullptr;
    clear_credentials();
    stop("Unable to initialize libsmbclient context.");
  }
}

// [[Rcpp::export]]
void smbr_disconnect_cpp() {
  if (g_ctx) { smbc_free_context(g_ctx, 1); g_ctx = nullptr; }
  clear_credentials();
}

// [[Rcpp::export]]
DataFrame smbr_dir_cpp(std::string url) {
  SMBCCTX* c = context();
  SMBCFILE* d = smbc_getFunctionOpendir(c)(c, url.c_str());
  if (!d) stop("Unable to open directory: " + std::string(std::strerror(errno)));
  CharacterVector name, type, comment;
  IntegerVector code;
  int read_error = 0;
  while (true) {
    errno = 0;
    struct smbc_dirent* e = smbc_getFunctionReaddir(c)(c, d);
    if (!e) { read_error = errno; break; }
    std::string n(e->name);
    if (n == "." || n == "..") continue;
    std::string t = "other";
    if (e->smbc_type == SMBC_DIR) t = "directory";
    else if (e->smbc_type == SMBC_FILE) t = "file";
    else if (e->smbc_type == SMBC_LINK) t = "link";
    name.push_back(n); type.push_back(t); code.push_back((int)e->smbc_type);
    comment.push_back(e->comment ? std::string(e->comment) : "");
  }
  const int close_result = smbc_getFunctionClosedir(c)(c, d);
  const int close_error = errno;
  if (read_error != 0) {
    stop("readdir failed: " + std::string(std::strerror(read_error)));
  }
  if (close_result < 0) {
    stop("closedir failed: " + std::string(std::strerror(close_error)));
  }
  return DataFrame::create(_["name"] = name, _["type"] = type,
                           _["smbc_type"] = code, _["comment"] = comment);
}

// [[Rcpp::export]]
List smbr_stat_cpp(std::string url) {
  SMBCCTX* c = context(); struct stat st;
  check(smbc_getFunctionStat(c)(c, url.c_str(), &st), "stat");
  return List::create(_["size"] = (double)st.st_size,
                      _["mode"] = (int)st.st_mode,
                      _["is_directory"] = (bool)S_ISDIR(st.st_mode),
                      _["mtime"] = (double)st.st_mtime,
                      _["atime"] = (double)st.st_atime,
                      _["ctime"] = (double)st.st_ctime);
}

// [[Rcpp::export]]
bool smbr_exists_cpp(std::string url) {
  SMBCCTX* c = context(); struct stat st;
  if (smbc_getFunctionStat(c)(c, url.c_str(), &st) == 0) return true;
  const int error = errno;
  if (error == ENOENT) return false;
  stop("exists failed: " + std::string(std::strerror(error)));
  return false;
}

static int flags_for_mode(const std::string& mode) {
  if (mode.empty()) {
    stop("mode must be a non-empty combination of r, w, or a with optional b and +");
  }

  const char operation = mode[0];
  if (operation != 'r' && operation != 'w' && operation != 'a') {
    stop("mode must start with r, w, or a");
  }

  bool plus = false;
  bool binary = false;
  for (size_t i = 1; i < mode.size(); ++i) {
    if (mode[i] == '+') {
      if (plus) stop("mode contains '+' more than once");
      plus = true;
    } else if (mode[i] == 'b') {
      if (binary) stop("mode contains 'b' more than once");
      binary = true;
    } else {
      stop("mode must use only r, w, a, b, and +");
    }
  }

  if (operation == 'r') return plus ? O_RDWR : O_RDONLY;
  if (operation == 'w') return (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
  return (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
}

// [[Rcpp::export]]
RawVector smbr_read_cpp(std::string url) {
  SMBCCTX* c = context(); SMBCFILE* f = smbc_getFunctionOpen(c)(c, url.c_str(), O_RDONLY, 0);
  if (!f) stop("Unable to open file: " + std::string(std::strerror(errno)));
  std::vector<Rbyte> bytes; char buf[65536]; ssize_t n;
  while ((n = smbc_getFunctionRead(c)(c, f, buf, sizeof(buf))) > 0) {
    bytes.insert(bytes.end(), (Rbyte*)buf, (Rbyte*)buf + n);
  }
  if (n < 0) {
    const int error = errno;
    smbc_getFunctionClose(c)(c, f);
    stop("Read failed: " + std::string(std::strerror(error)));
  }
  const int close_result = smbc_getFunctionClose(c)(c, f);
  const int close_error = errno;
  if (close_result < 0) {
    stop("Read close failed: " + std::string(std::strerror(close_error)));
  }
  RawVector out(bytes.size());
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

// [[Rcpp::export]]
void smbr_write_cpp(std::string url, RawVector data, std::string mode = "wb") {
  SMBCCTX* c = context(); SMBCFILE* f = smbc_getFunctionOpen(c)(c, url.c_str(), flags_for_mode(mode), 0666);
  if (!f) stop("Unable to open file: " + std::string(std::strerror(errno)));
  R_xlen_t pos = 0;
  while (pos < data.size()) {
    ssize_t n = smbc_getFunctionWrite(c)(c, f, (const char*)data.begin() + pos, data.size() - pos);
    if (n < 0) {
      const int error = errno;
      smbc_getFunctionClose(c)(c, f);
      stop("Write failed: " + std::string(std::strerror(error)));
    }
    if (n == 0) {
      smbc_getFunctionClose(c)(c, f);
      stop("Write returned zero bytes before the buffer was exhausted");
    }
    pos += n;
  }
  const int close_result = smbc_getFunctionClose(c)(c, f);
  const int close_error = errno;
  if (close_result < 0) {
    stop("Write close failed: " + std::string(std::strerror(close_error)));
  }
}

// [[Rcpp::export]]
void smbr_mkdir_cpp(std::string url, int mode = 0777) {
  SMBCCTX* c = context();
  check(smbc_getFunctionMkdir(c)(c, url.c_str(), mode), "mkdir");
}
// [[Rcpp::export]]
void smbr_delete_cpp(std::string url) {
  SMBCCTX* c = context();
  check(smbc_getFunctionUnlink(c)(c, url.c_str()), "delete");
}
// [[Rcpp::export]]
void smbr_rename_cpp(std::string from, std::string to) {
  SMBCCTX* c = context();
  check(smbc_getFunctionRename(c)(c, from.c_str(), c, to.c_str()), "rename");
}
