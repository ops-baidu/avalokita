#define _XOPEN_SOURCE 800
#define _BSD_SOURCE
#define _GNU_SOURCE

#include <getopt.h>
#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/prctl.h>

#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <curl/curl.h>

#include "config.h"
#include "macros.h"

#define USER_AGENT "Avalokita/1.0"
#define MAX_KILL_TIMEOUT 30
#define MAX_URL_LENGTH 4096
#define MAX_SIGNATURE_LENGTH 131072
#define MAX_CERTIFICATE_LENGTH 131072
#define DOWNLOAD_RETRIES 5
#define DOWNLOAD_RETRY_INTERVAL 30

struct {
    int restart_interval;
    int update_interval;
    char update_url[MAX_URL_LENGTH];
    char signature_url[MAX_URL_LENGTH];
    char certificate[PATH_MAX];
    int max_executable_size;
    char file_lock[PATH_MAX];
    char command_stdout_file[PATH_MAX];
    char command_stderr_file[PATH_MAX];
    char *command_path;
    char **command_arguments;
} arguments = {
        .restart_interval = 1,
        .update_interval = 600,
        .update_url = "",
        .signature_url = "",
        .certificate = "",
        .max_executable_size = 10485760,
        .file_lock = "daemon.pid",
        .command_stdout_file = "command.out",
        .command_stderr_file = "command.err",
        .command_path = NULL,
        .command_arguments = NULL,
};

struct ProcessRuntime {
    pid_t pid;
    ev_timer bear_delay;
    ev_timer kill_delay;

    int (*bear)(void);
};

static int bear_executor(void);

struct {
    struct ProcessRuntime runtime;
    int executable_existed;
    int stdout_fd;
    int stderr_fd;
} executor = {
        .runtime.pid = 0,
        .runtime.bear_delay = {0},
        .runtime.kill_delay = {0},
        .runtime.bear = bear_executor,
        .executable_existed = 0,
        .stdout_fd = -1,
        .stderr_fd = -1,
};

static int bear_downloader(void);

struct {
    struct ProcessRuntime runtime;
    char signature[MAX_SIGNATURE_LENGTH];
    int slen;
    char cert[MAX_CERTIFICATE_LENGTH];
    int clen;
    char new_executable[PATH_MAX];
} downloader = {
        .runtime.pid = 0,
        .runtime.bear_delay = {0},
        .runtime.kill_delay = {0},
        .runtime.bear = bear_downloader,
        .signature = {0},
        .slen = 0,
        .cert = {0},
        .clen = 0,
        .new_executable = {0},
};

enum DownloaderExitReason {
    DOWNLOADER_EXIT_REASON_NO_NEW_VERSION = 0,
    DOWNLOADER_EXIT_REASON_NEW_VERSION_FOUND,
    DOWNLOADER_EXIT_REASON_ERROR
};

static int quit_all = 0;

static size_t
write_signature(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;

    memcpy(downloader.signature + downloader.slen, contents, realsize);
    downloader.slen += realsize;
    downloader.signature[downloader.slen] = 0;

    return realsize;
}

static size_t
write_executable(void *contents, size_t size, size_t nmemb, void *userp) {
    int ret = -1;
    FILE *fp = (FILE *) userp;

    ret = fwrite(contents, size, nmemb, fp);
    if (ret < 0) {
        ERROR_LIBC("fwrite");
        return -1;
    }

    return ret;
}

static int
download(const char *url, size_t writer(void *, size_t, size_t, void *), void *writer_data,
         size_t max_file_size) {
    int i = 0;
    long status = 0;
    CURL *curl = NULL;
    CURLcode ret = CURLE_OK;

    curl = curl_easy_init();
    if (!curl) {
        ERROR("curl initialize failed!");
        return -1;
    }

    ret = curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 60);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, max_file_size);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, writer_data);
    if (ret != CURLE_OK) {
        ERROR("curl_easy_setopt(): %s", curl_easy_strerror(ret));
        goto fail;
    }

    for (i = 0; i < DOWNLOAD_RETRIES; i++) {
        ret = curl_easy_perform(curl);
        if (ret != CURLE_OK) {
            ERROR("curl_easy_perform(): %s", curl_easy_strerror(ret));
            goto sleep_and_continue;
        }

        ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (ret < 0) {
            ERROR("curl_easy_getinfo(): %s", curl_easy_strerror(ret));
            goto sleep_and_continue;
        }

        if (status != 200 && status != 0) {
            ERROR("download url %s failed with response code %ld", url, status);
            goto sleep_and_continue;
        }

        break;

        sleep_and_continue:
        sleep(DOWNLOAD_RETRY_INTERVAL);
    }

    if (i >= DOWNLOAD_RETRIES) {
        goto fail;
    }

    curl_easy_cleanup(curl);
    return 0;

    fail:
    curl_easy_cleanup(curl);
    return -1;
}

static int
verify_signature(const char *path, char signature[], int slen, char cert[], int clen) {
    int ret = -1;
    BIO *data_bio = NULL;
    BIO *sig_bio = NULL;
    BIO *cert_bio = NULL;
    PKCS7 *p7 = NULL;
    X509 *x509_cert = NULL;
    STACK_OF(X509) *x509_stack = NULL;

    data_bio = BIO_new_file(path, "r");
    if (!data_bio) {
        ERROR("BIO_new_file() data bio");
        ret = -1;
        goto exit;
    }

    sig_bio = BIO_new_mem_buf(signature, slen);
    if (!sig_bio) {
        ERROR("BIO_new_mem_buf() sig bio");
        ret = -1;
        goto exit;
    }

    cert_bio = BIO_new_mem_buf(cert, clen);
    if (!cert_bio) {
        ERROR("BIO_new_mem_buf() cert bio");
        ret = -1;
        goto exit;
    }

    p7 = PEM_read_bio_PKCS7(sig_bio, NULL, NULL, NULL);
    if (!p7) {
        ERROR("PEM_read_bio_PKCS7()");
        ret = -1;
        goto exit;
    }

    x509_cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!x509_cert) {
        ERROR("PEM_read_bio_X509()");
        ret = -1;
        goto exit;
    }

    x509_stack = sk_X509_new_null();
    if (!x509_stack) {
        ERROR("sk_X509_new_null()");
        ret = -1;
        goto exit;
    }

    if (!sk_X509_push(x509_stack, x509_cert)) {
        ERROR("sk_X509_push()");
        ret = -1;
        goto exit;
    }

    //the cert was in stack now, it's life cycle was associate to the stack.
    x509_cert = NULL;

    // clean previous error numbers;
    while (ERR_get_error() != 0);

    ret = PKCS7_verify(p7, x509_stack, NULL, data_bio, NULL, PKCS7_NOINTERN | PKCS7_NOVERIFY);
    if (ret == 1) {
        ret = 0;
        goto exit;
    } else {
        ERROR("PKCS7_verify(): %s", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto exit;
    }

    exit:
    if (data_bio) {
        BIO_vfree(data_bio);
    }

    if (sig_bio) {
        BIO_vfree(sig_bio);
    }

    if (cert_bio) {
        BIO_vfree(cert_bio);
    }

    if (p7) {
        PKCS7_free(p7);
    }

    if (x509_cert) {
        X509_free(x509_cert);
    }

    if (x509_stack) {
        sk_X509_pop_free(x509_stack, X509_free);
    }

    return ret;
}

static int
downloader_process(void) {
    int ret = -1;
    FILE *fp = NULL;

    // initialize openssl library.
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // rename() is not a atomic operation even both old path and new path are in one device. While
    // overwrite case, rename() cause a intermediate state just like ln(). So unlink() files at
    // first is necessary.
    ret = unlink(downloader.new_executable);
    if (ret < 0 && errno != ENOENT) {
        ERROR_LIBC("unlink %s", downloader.new_executable);
        return DOWNLOADER_EXIT_REASON_ERROR;
    }

    downloader.slen = 0;
    ret = download(arguments.signature_url, write_signature, NULL, sizeof arguments.signature_url);
    if (ret < 0) {
        ERROR("download signature failed.");
        return DOWNLOADER_EXIT_REASON_ERROR;
    }

    ret = verify_signature(arguments.command_path, downloader.signature, downloader.slen,
                           downloader.cert, downloader.clen);
    if (ret == 0) {
        // verify success, don't need any upgrade.
        INFO("the command executable is newest already.");
        return DOWNLOADER_EXIT_REASON_NO_NEW_VERSION;
    }

    INFO("verify signature failed, downloading new executable.");

    fp = fopen(downloader.new_executable, "wb");
    if (!fp) {
        ERROR_LIBC("fopen %s", arguments.command_path);
        return DOWNLOADER_EXIT_REASON_ERROR;
    }

    ret = download(arguments.update_url, write_executable, fp, arguments.max_executable_size);
    fclose(fp);
    if (ret < 0) {
        ERROR("download executable failed.");
        return DOWNLOADER_EXIT_REASON_ERROR;
    }

    ret = verify_signature(downloader.new_executable, downloader.signature, downloader.slen,
                           downloader.cert, downloader.clen);
    if (ret < 0) {
        ERROR("verify downloaded executable failed.");
        return DOWNLOADER_EXIT_REASON_ERROR;
    }

    ret = rename(downloader.new_executable, arguments.command_path);
    if (ret < 0) {
        ERROR_LIBC("rename %s to %s", downloader.new_executable, arguments.command_path);
        return DOWNLOADER_EXIT_REASON_ERROR;
    }

    ret = chmod(arguments.command_path, 0755);
    if (ret < 0) {
        ERROR_LIBC("chmod %s", arguments.command_path);
        return DOWNLOADER_EXIT_REASON_ERROR;
    }

    INFO("download newest executable success!");
    return DOWNLOADER_EXIT_REASON_NEW_VERSION_FOUND;
}

static void
tell_child_do_not_live_alone(void) {
    int ret = -1;

    ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (ret < 0) {
        ERROR_LIBC("prctl");
        exit(127);
    }

    if (getppid() == 1) {
        // The parent was exited before prctl(), do not live alone. This case is rare but should
        // prevent.
        ERROR("parent already exited.");
        exit(127);
    }
}

static int
bear_downloader(void) {
    int ret = -1;

    assert(downloader.runtime.pid == 0);

    ret = fork();
    if (ret < 0) {
        ERROR_LIBC("fork");
        return -1;
    } else if (ret == 0) {
        tell_child_do_not_live_alone();
        exit(downloader_process());
    }

    downloader.runtime.pid = ret;
    return 0;
}

static int
bear_executor(void) {
    int ret = -1;

    assert(executor.runtime.pid == 0);
    INFO("run command %s", arguments.command_path);

    ret = fork();
    if (ret < 0) {
        ERROR_LIBC("fork");
        return -1;
    } else if (ret == 0) {
        tell_child_do_not_live_alone();

        ret = dup2(executor.stdout_fd, 1);
        if (ret < 0) {
            ERROR_LIBC("dup2 executor stdout");
            exit(127);
        }

        ret = dup2(executor.stderr_fd, 2);
        if (ret < 0) {
            ERROR_LIBC("dup2 executor stderr");
            exit(127);
        }

        execv(arguments.command_path, arguments.command_arguments);
        exit(127);
    }

    executor.runtime.pid = ret;
    return 0;
}

static void
bear_child(EV_P_ ev_timer *w, int revents) {
    int ret = -1;
    struct ProcessRuntime *proc = container_of(w, struct ProcessRuntime, bear_delay);

    ret = proc->bear();
    if (ret < 0) {
        ERROR("bear child failed.");
        ev_timer_again(EV_A_ w);
    } else {
        ev_timer_stop(EV_A_ w);
    }
}

static void
kill_child(EV_P_ ev_timer *w, int revents) {
    struct ProcessRuntime *proc = container_of(w, struct ProcessRuntime, kill_delay);

    INFO("stop process %d timeout, force kill it now!", proc->pid);
    kill(proc->pid, SIGKILL);
    ev_timer_stop(EV_A_ w);
}

static void
bear_children(EV_P_ ev_idle *w, int revents) {
    if (arguments.update_url[0] != 0) {
        bear_child(EV_A_ &downloader.runtime.bear_delay, revents);
    }

    if (executor.executable_existed) {
        bear_child(EV_A_ &executor.runtime.bear_delay, revents);
    }

    ev_idle_stop(EV_A_ w);
}

static void
dispose_zombies(EV_P_ ev_child *w, int revents) {
    if (w->rpid == executor.runtime.pid) {
        executor.runtime.pid = 0;

        if (WIFEXITED(w->rstatus)) {
            INFO("command %s exit with status %d.", arguments.command_path, WEXITSTATUS(w->rstatus));
        } else if (WIFSIGNALED(w->rstatus)) {
            INFO("command %s exit because a signal %s.", arguments.command_path,
                 strsignal(WTERMSIG(w->rstatus)));
        }

        if (quit_all) {
            ev_break(EV_A_ EVBREAK_ALL);
        } else {
            // Ensure no one threat me. If executor was exited because SIGTERM, kill_delay always
            // active, should stop it.
            ev_timer_stop(EV_A_ &executor.runtime.kill_delay);
            // Wait if restart interval is not 0.
            ev_timer_again(EV_A_ &executor.runtime.bear_delay);
        }
    } else if (w->rpid == downloader.runtime.pid) {
        downloader.runtime.pid = 0;

        if (quit_all) {
            // Everything will quit soon, nothing to be done.
            return;
        } else if (WIFSIGNALED(w->rstatus)) {
            ERROR("downloader process exit because a signal %s.", strsignal(WTERMSIG(w->rstatus)));
        } else if (WIFEXITED(w->rstatus)) {
            INFO("downloader process exit with status %d", WEXITSTATUS(w->rstatus));
            // New version executable was ready, restart the command.
            if (WEXITSTATUS(w->rstatus) == DOWNLOADER_EXIT_REASON_NEW_VERSION_FOUND) {
                if (executor.runtime.pid != 0 && !ev_is_active(&executor.runtime.kill_delay)) {
                    // executor is running and no one killing it, kill it now.
                    INFO("stopping command %s pid %d ...", arguments.command_path,
                         executor.runtime.pid);
                    kill(executor.runtime.pid, SIGTERM);
                    ev_timer_again(EV_A_ &executor.runtime.kill_delay);
                } else if (executor.runtime.pid == 0 && !ev_is_active(&executor.runtime.bear_delay)) {
                    // executor is not running and no one bearing it, bear it now.
                    bear_child(EV_A_ &executor.runtime.bear_delay, revents);
                }
            }
        }

        // trigger downloader after update interval.
        ev_timer_again(EV_A_ &downloader.runtime.bear_delay);
    } else {
        ERROR("unknown child process exited: %d", w->rpid);
    }
}

static void
kill_executor(EV_P_ ev_signal *w, int revents) {
    if (executor.runtime.pid == 0) {
        return;
    }

    // kill the command.
    INFO("sending SIGTERM to command %s ...", arguments.command_path);
    kill(executor.runtime.pid, SIGTERM);
    ev_timer_again(EV_A_ &executor.runtime.kill_delay);
}

static void
quit(EV_P_ ev_signal *w, int revents) {
    if (executor.runtime.pid == 0) {
        // command is not running, just break loop.
        ev_break(EV_A_ EVBREAK_ALL);
    } else if (!quit_all) {
        kill_executor(EV_A_ w, revents);
        quit_all = 1;
    }
}

static int
run_main_loop() {
    ev_signal sigterm_watcher;
    ev_signal_init(&sigterm_watcher, quit, SIGTERM);
    ev_signal_start(EV_DEFAULT_ &sigterm_watcher);

    ev_signal sigint_watcher;
    ev_signal_init(&sigint_watcher, kill_executor, SIGINT);
    ev_signal_start(EV_DEFAULT_ &sigint_watcher);

    ev_child child_watcher;
    ev_child_init(&child_watcher, dispose_zombies, 0, 0);
    ev_child_start(EV_DEFAULT_ &child_watcher);

    // child processes should bear in the idle watcher callback (which will be called after the
    // event loop is running). Otherwise child processes maybe exit before the event loop running,
    // then leading to child process events lose.
    ev_idle idle_watcher;
    ev_idle_init(&idle_watcher, bear_children);
    ev_idle_start(EV_DEFAULT_ &idle_watcher);

    ev_timer_init(&executor.runtime.bear_delay, bear_child, 0, arguments.restart_interval);
    ev_timer_init(&executor.runtime.kill_delay, kill_child, 0, MAX_KILL_TIMEOUT);
    ev_timer_init(&downloader.runtime.bear_delay, bear_child, 0, arguments.update_interval);
    ev_timer_init(&downloader.runtime.kill_delay, kill_child, 0, MAX_KILL_TIMEOUT);

    if (ev_run(EV_DEFAULT_ 0)) {
        // ev_break() cause exit, it is normal.
        INFO("BYE!");
        return 0;
    } else {
        // all watchers stopped, something wrong?
        ERROR("No more active watchers!");
        return 1;
    }
}

static int
get_file_lock(void) {
    int fd = -1;
    int ret = -1;
    char buf[16] = {0};
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};

    fd = open(arguments.file_lock, O_RDWR | O_CREAT, 0640);
    if (fd < 0) {
        ERROR_LIBC("open %s", arguments.file_lock);
        return -1;
    }

    ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (ret < 0) {
        ERROR_LIBC("fcntl F_SETFD FD_CLOEXEC");
        return -1;
    }

    ret = fcntl(fd, F_SETLK, &lock);
    if (ret < 0) {
        ERROR_LIBC("fcntl F_SETLK");
        return -1;
    }

    ret = ftruncate(fd, 0);
    if (ret < 0) {
        ERROR_LIBC("ftruncate");
        return -1;
    }

    snprintf(buf, sizeof(buf), "%d\n", getpid());
    ret = (int) write(fd, buf, strlen(buf));
    if (ret < 0) {
        ERROR_LIBC("write");
        return -1;
    }

    return 0;
}

static int
daemonize(void) {
    pid_t pid = 0;
    int i = 0;
    int max_fd = 0;

    pid = fork();
    if (pid < 0) {
        ERROR_LIBC("fork");
        return -1;
    } else if (pid > 0) {
        exit(0);
    }

    setsid();
    umask(022);

    close(0);
    max_fd = getdtablesize();
    for (i = 3; i < max_fd; i++) {
        close(i);
    }

    return 0;
}

static int
set_std_fds_append_mode(void) {
    int ret = -1, fd = 1;
    unsigned int ftype = 0;
    struct stat st = {0};

    for (fd = 1; fd <= 2; fd++) {
        ret = fstat(fd, &st);
        if (ret < 0) {
            ERROR_LIBC("fstat fd %d", fd);
            return -1;
        }

        ftype = st.st_mode & (uint) S_IFMT;
        if (ftype != S_IFREG && ftype != S_IFBLK) {
            // only regular file and block device need set O_APPEND flag.
            continue;
        }

        ret = fcntl(fd, F_GETFL);
        if (ret < 0) {
            ERROR_LIBC("fcntl F_GETFL fd %d", fd);
            return -1;
        }

        ret = fcntl(fd, F_SETFL, ret | O_APPEND);
        if (ret < 0) {
            ERROR_LIBC("fcntl F_SETFL fd %d", fd);
            return -1;
        }
    }

    return 0;
}

static int
is_valid_url(const char *url) {
    return strncasecmp(url, "https:", strlen("https:")) == 0 ||
           strncasecmp(url, "http:", strlen("http:")) == 0 ||
           strncasecmp(url, "file:", strlen("file:")) == 0 ||
           strncasecmp(url, "ftp:", strlen("ftp:")) == 0;
}

static void
print_usage(void) {
    const char *usage =
            "\n"
            "Usage: avalokita [options] command_path [command options]\n"
            "\n"
            "Options:\n"
            "\n"
            "  --restart-interval [seconds]\n"
            "\n"
            "    Interval of command restart. Can not less than 1. Default is 1.\n"
            "\n"
            "  --update-interval [seconds]\n"
            "\n"
            "    Interval of update URL check. Can not less than 1. Default is 300.\n"
            "\n"
            "  --update-url [URL]\n"
            "\n"
            "    Automatically fetch the newest version executable of the command from URL\n"
            "    and restart the command. This implies the argument --signature-url will\n"
            "    get a default value [URL + \".sig\"] if --signature-url was not specified.\n"
            "\n"
            "    Thus, use --update-url without --signature-url is impossible.\n"
            "\n"
            "  --signature-url [URL]\n"
            "\n"
            "    Signature file for verify the executable which fetched from --update-url.\n"
            "    The certificate is specify by --certificate. Default is the URL specified\n"
            "    by --update-url and append \".sig\".\n"
            "\n"
            "    The signature file was in PKCS#7 encoding and PEM format.\n"
            "\n"
            "  --certificate [filename]\n"
            "\n"
            "    Certificate(in PEM format) used for verify the signature. If this argument\n"
            "    absent, --signature-url and --update-url is ignored.\n"
            "\n"
            "  --max-executable-size [size]\n"
            "\n"
            "    The maximum executable size. If beyond the size, download will failed.\n"
            "    Default is 10485760(10MiB).\n"
            "\n"
            "  --file-lock [filename]\n"
            "\n"
            "    Singletonize the daemon by a file lock. If the file lock is locked, the\n"
            "    daemon will exit immediately. Default is \"./daemon.pid\".\n"
            "\n"
            "  --command-stdout-file [filename]\n"
            "\n"
            "    Redirect command's stdout to a file. Default is \"./command.out\".\n"
            "\n"
            "  --command-stderr-file [filename]\n"
            "\n"
            "    Redirect command's stderr to a file. Default is \"./command.err\".\n"
            "\n"
            "  --help\n"
            "\n"
            "    Print usage.\n"
            "\n"
            "  --version\n"
            "\n"
            "    Print version number.\n"
            "\n"
            "Signals:\n"
            "\n"
            "  SIGTERM\n"
            "\n"
            "    kill command at first(first SIGTERM, then SIGKILL if command not exit in\n"
            "    several seconds), then quit.\n"
            "\n"
            "  SIGINT\n"
            "\n"
            "    just kill command(SIGTERM, after several seconds then SIGKILL), then\n"
            "    avalokita will run the command again.\n"
            "\n";

    fprintf(stderr, "%s", usage);
}

static void
print_version(void) {
    fprintf(stderr, "%s\n", VERSION);
}

int
main(int argc, char *argv[]) {
    const struct option long_opts[] = {
            {"restart-interval",    required_argument, 0, 0},
            {"update-interval",     required_argument, 0, 0},
            {"update-url",          required_argument, 0, 0},
            {"signature-url",       required_argument, 0, 0},
            {"certificate",         required_argument, 0, 0},
            {"max-executable-size", required_argument, 0, 0},
            {"file-lock",           required_argument, 0, 0},
            {"command-stdout-file", required_argument, 0, 0},
            {"command-stderr-file", required_argument, 0, 0},
            {"help",                no_argument,       0, 0},
            {"version",             no_argument,       0, 0},
            {0},
    };

    int long_opt_idx = 0;
    int ret = -1;
    int fd = -1;
    int i = 0;

    ret = set_std_fds_append_mode();
    if (ret < 0) {
        ERROR("set std fds append mode failed.");
        return 1;
    }

    while (1) {
        ret = getopt_long(argc, argv, "", long_opts, &long_opt_idx);
        if (ret < 0) {
            break;
        } else if (ret == '?') {
            print_usage();
            return 1;
        } else if (strcmp(long_opts[long_opt_idx].name, "restart-interval") == 0) {
            arguments.restart_interval = atoi(optarg);
            if (arguments.restart_interval <= 0) {
                ERROR("--restart-interval seconds should big than 0");
                return 1;
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "update-interval") == 0) {
            arguments.update_interval = atoi(optarg);
            if (arguments.update_interval <= 0) {
                ERROR("--update-interval seconds should big than 0");
                return 1;
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "update-url") == 0) {
            if (strlen(optarg) >= sizeof arguments.update_url) {
                ERROR("--update-url length should short than %lu.\n", sizeof arguments.update_url);
                return 1;
            } else if (!is_valid_url(optarg)) {
                ERROR("--update-url should be a http, https, file or ftp URL.");
                return 1;
            } else {
                strcpy(arguments.update_url, optarg);
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "signature-url") == 0) {
            if (strlen(optarg) >= sizeof arguments.signature_url) {
                ERROR("--signature-url length should short than %lu.\n",
                      sizeof arguments.signature_url);
                return 1;
            } else if (!is_valid_url(optarg)) {
                ERROR("--signature-url should be a http, https, file or ftp URL.");
                return 1;
            } else {
                strcpy(arguments.signature_url, optarg);
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "certificate") == 0) {
            if (strlen(optarg) >= sizeof arguments.certificate) {
                ERROR("--certificate length should short than %lu", sizeof arguments.certificate);
                return 1;
            } else {
                strcpy(arguments.certificate, optarg);
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "max-executable-size") == 0) {
            arguments.max_executable_size = atoi(optarg);
            if (arguments.max_executable_size <= 0) {
                ERROR("--max-executable-size size should big than 0");
                return 1;
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "file-lock") == 0) {
            if (strlen(optarg) >= sizeof arguments.file_lock) {
                ERROR("--file-lock length should short than %lu", sizeof arguments.file_lock);
                return 1;
            } else {
                strcpy(arguments.file_lock, optarg);
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "command-stdout-file") == 0) {
            if (strlen(optarg) >= sizeof arguments.command_stdout_file) {
                ERROR("--command-stdout-file length should short than %lu", sizeof arguments.command_stdout_file);
                return 1;
            } else {
                strcpy(arguments.command_stdout_file, optarg);
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "command-stderr-file") == 0) {
            if (strlen(optarg) >= sizeof arguments.command_stderr_file) {
                ERROR("--command-stderr-file length should short than %lu", sizeof arguments.command_stderr_file);
                return 1;
            } else {
                strcpy(arguments.command_stderr_file, optarg);
            }
        } else if (strcmp(long_opts[long_opt_idx].name, "help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(long_opts[long_opt_idx].name, "version") == 0) {
            print_version();
            return 0;
        }
    }

    if (optind >= argc) {
        ERROR("you must specify a command path.");
        return 1;
    }

    arguments.command_path = argv[optind];

    // according to execv(), we need a NULL pointer to indicate arguments end.
    int cmd_arg_count = argc - optind;
    arguments.command_arguments = malloc(sizeof(char *) * (cmd_arg_count + 1));
    arguments.command_arguments[cmd_arg_count] = NULL;
    for (i = 0; i < cmd_arg_count; i++) {
        arguments.command_arguments[i] = argv[optind + i];
    }

    if (arguments.update_url[0] != 0 && arguments.certificate[0] == 0) {
        // disable update_url if certificate is absent.
        INFO("WARNING: --update-url can not work without --certificate, so ignored it.");
        arguments.signature_url[0] = 0;
        arguments.certificate[0] = 0;
        arguments.update_url[0] = 0;
    }

    if (arguments.update_url[0] != 0 && arguments.signature_url[0] == 0) {
        snprintf(arguments.signature_url, sizeof arguments.signature_url, "%s.sig",
                 arguments.update_url);
    }

    // all arguments are initialized. do real works.
    ret = daemonize();
    if (ret < 0) {
        ERROR("daemonize failed.");
        return 1;
    }

    ret = get_file_lock();
    if (ret < 0) {
        ERROR("get file lock failed, maybe the daemon already running?");
        return 1;
    }

    // check executable exist.
    if (access(arguments.command_path, X_OK) == 0) {
        executor.executable_existed = 1;
    } else if (arguments.update_url[0] == 0) {
        // neither local path nor remote URL had a executable, can not work.
        ERROR("the command %s is not exist!", arguments.command_path);
        return 1;
    }

    // initialize file descriptors for commands.
    ret = open(arguments.command_stdout_file, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (ret < 0) {
        ERROR_LIBC("open %s", arguments.command_stdout_file);
        return 1;
    }

    executor.stdout_fd = ret;

    ret = open(arguments.command_stderr_file, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (ret < 0) {
        ERROR_LIBC("open %s", arguments.command_stderr_file);
        return 1;
    }

    executor.stderr_fd = ret;

    // Put downloaded new executable to the directory that the command live's in. Because rename()
    // in same device is atomic.
    snprintf(downloader.new_executable, sizeof downloader.new_executable, "%s.new",
             arguments.command_path);

    if (arguments.certificate[0] != 0) {
        // read certificate into memory, it is safer.
        fd = open(arguments.certificate, O_RDONLY);
        if (fd < 0) {
            ERROR_LIBC("open %s", arguments.certificate);
            return 1;
        }

        // the buffer size is big enough for common PEM format certificates.
        ret = (int)read(fd, downloader.cert, sizeof downloader.cert);
        if (ret < 0) {
            ERROR_LIBC("read");
            return 1;
        }

        downloader.clen = ret;
        close(fd);
    }

    return run_main_loop();
}
