/*!
 *
 * @brief       Administrator Hook System
 *
 * @ingroup     susshid
 *
 * @copyright   Copyright (C) 2026 Wasabi Elements GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-06-19
 *
 * @defgroup    hooks Administrator Hook System
 * @brief       Discovers and executes administrator-supplied hook executables.
 *
 * Hook executables placed in PATH_SUSSHI_HOOKS are called asynchronously via a
 * double-fork so susshid is never blocked by a slow or hanging hook script.
 * The intermediate child captures the hook's stdout/stderr line by line and
 * forwards each line to syslog; it exits as soon as the hook process exits,
 * after which the OS reaps it automatically.  The master process has a
 * SIGCHLD handler that calls waitpid; session processes set SIGCHLD to
 * SIG_IGN so the kernel auto-reaps without creating zombie processes.
 *
 * Hook executables receive a clean environment containing only the variables
 * listed below.  The susshid process environment is not inherited.
 *
 * The following variables are always present (mandatory):
 *
 *   PATH                    — safe minimal search path
 *   LANG                    — locale, taken from the daemon environment or "C.UTF-8"
 *   SUSSHI_HOOK             — name of the hook (e.g. "session-start", "session-auth-failed")
 *   SUSSHI_VERSION          — suSSHi gateway version string (e.g. "2.1.0")
 *
 * The following variables are present only when a value is available in the
 * current execution context; they are omitted rather than set to empty strings:
 *
 *   SUSSHI_GATEWAY_HOSTNAME  — hostname of the gateway
 *   SUSSHI_UNIQID            — unique session identifier (session context only)
 *   SUSSHI_USER              — gateway username (session context only)
 *   SUSSHI_CLIENT_IP         — IP address of the connecting client (session context only)
 *   SUSSHI_CLIENT_PORT       — TCP source port of the connecting client (session context only)
 *   SUSSHI_GATEWAY_MODE      — operation mode: "gateway", "bastion", "shell", or "chef-remote"
 *                              (session-* hooks only; omitted for gateway-start, gateway-stop, client-connect)
 *   SUSSHI_BASTION           — bastion proxy realm name (OP_MODE_BASTION only)
 *
 * The following variables are only set in OP_MODE_GATEWAY:
 *
 *   SUSSHI_TARGET_USER       — target username
 *   SUSSHI_TARGET_HOST       — target hostname
 *   SUSSHI_TARGET_PORT       — target port number
 *   SUSSHI_TARGET_IP         — resolved IP address of the target
 *
 * Session log variables (present when a session log exists):
 *
 *   SUSSHI_SESSION_LOG       — absolute path to the session log file
 *   SUSSHI_AUDIT_LOG_PATTERN — glob pattern matching all audit log files for the session
 *
 * @{
 */

#include <susshid/common.h>


static bool susshi_env_append(char **envp, int *idx, const char *fmt, ...) __attribute__((format(printf, 3, 4)));


/* Maximum number of environment entries (must cover all SUSSHI_* vars + PATH + NULL) */
#define HOOK_ENV_MAX    19

/* Safe PATH passed to hook executables instead of the daemon's own PATH */
#define HOOK_SAFE_PATH  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

static const char * const op_mode_names[] = {
    [OP_MODE_GATEWAY]     = "gateway",
    [OP_MODE_BASTION]     = "bastion",
    [OP_MODE_SHELL]       = "shell",
    [OP_MODE_CHEF_REMOTE] = "chef-remote",
};

static const char *hook_names[HOOK_COUNT] = {
	[HOOK_SESSION_FAILED] = "session-failed",
	[HOOK_SESSION_AUTH_FAILED] = "session-auth-failed",
	[HOOK_SESSION_TARGET_CONNECT_FAILED] = "session-target-connect-failed",
	[HOOK_SESSION_TARGET_AUTH_FAILED] = "session-target-auth-failed",
	[HOOK_SESSION_START] = "session-start",
	[HOOK_GATEWAY_START] = "gateway-start",
	[HOOK_GATEWAY_STOP] = "gateway-stop",
	[HOOK_CLIENT_CONNECT] = "client-connect",
	[HOOK_SESSION_FINISHED] = "session-finished",
};

static char hook_paths[HOOK_COUNT][PATH_MAX];
static bool hook_available[HOOK_COUNT];


/*!
 * @brief   Append a formatted env entry to the env array.
 *
 * @param   envp    Pointer into the env array where the new entry is written.
 * @param   idx     Current write index; incremented on success.
 * @param   fmt     printf-style format string.
 * @param   ...     Format arguments.
 *
 * @return  true on success, false if snprintf truncated or strdup failed.
 */

static bool
susshi_env_append(char **envp, int *idx, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    int n;
    char *entry;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t) n >= sizeof(buf))
        return false;

    entry = strdup(buf);
    if (!entry)
        return false;

    envp[(*idx)++] = entry;
    return true;
}


/*!
 * @brief   Free a NULL-terminated env array built by susshi_build_hook_env().
 */

static void
susshi_free_hook_env(char **envp) {
    if (!envp)
        return;
    for (int i = 0; envp[i]; i++)
        free(envp[i]);
    free(envp);
}


/*!
 * @brief   Build a clean environment array for hook execution.
 *
 * @param   hook    Hook type whose name is written to SUSSHI_HOOK.
 *
 * @return  NULL-terminated env array, or NULL on allocation failure.
 *          Caller must free with susshi_free_hook_env().
 */

static char **
susshi_build_hook_env(HookType hook) {
    char **envp;
    const char *lang;
    int idx = 0;

    envp = calloc(HOOK_ENV_MAX, sizeof(char *));
    if (!envp)
        return NULL;

    /* PATH, LANG, and SUSSHI_HOOK are mandatory; abort if any cannot be allocated. */
    lang = getenv("LANG");
    if (!lang)
        lang = "C.UTF-8";

    if (!susshi_env_append(envp, &idx, "%s", HOOK_SAFE_PATH)                 ||
        !susshi_env_append(envp, &idx, "LANG=%s", lang)                      ||
        !susshi_env_append(envp, &idx, "SUSSHI_HOOK=%s", hook_names[hook])   ||
        !susshi_env_append(envp, &idx, "SUSSHI_VERSION=%s", SUSSHI_VERSION)) {
        susshi_free_hook_env(envp);
        return NULL;
    }

    /* All remaining variables are optional: if the value is absent or the
     * allocation fails the entry is simply omitted from the array. */

    /* SUSSHI_GATEWAY_MODE is only meaningful in session context where the mode
     * has been determined from the login string. */
    if (hook != HOOK_GATEWAY_START && hook != HOOK_GATEWAY_STOP && hook != HOOK_CLIENT_CONNECT)
        susshi_env_append(envp, &idx, "SUSSHI_GATEWAY_MODE=%s",
                          op_mode_names[susshi_session.operation_mode]);
    if (susshi_session.hostname && blength(susshi_session.hostname) > 0)
        susshi_env_append(envp, &idx, "SUSSHI_GATEWAY_HOSTNAME=%s",
                   bdata(susshi_session.hostname));

    if (susshi_session.susshi_uniqid && blength(susshi_session.susshi_uniqid) > 0)
        susshi_env_append(envp, &idx, "SUSSHI_UNIQID=%s",
                   bdata(susshi_session.susshi_uniqid));

    if (susshi_session.susshi_user && blength(susshi_session.susshi_user) > 0)
        susshi_env_append(envp, &idx, "SUSSHI_USER=%s",
                   bdata(susshi_session.susshi_user));

    if (susshi_session.client_ip && blength(susshi_session.client_ip) > 0)
        susshi_env_append(envp, &idx, "SUSSHI_CLIENT_IP=%s",
                   bdata(susshi_session.client_ip));

    if (susshi_session.client_port > 0)
        susshi_env_append(envp, &idx, "SUSSHI_CLIENT_PORT=%d",
                   susshi_session.client_port);

    if (susshi_session.operation_mode == OP_MODE_BASTION &&
        susshi_session.target_proxy_realm && blength(susshi_session.target_proxy_realm) > 0)
        susshi_env_append(envp, &idx, "SUSSHI_BASTION=%s",
                   bdata(susshi_session.target_proxy_realm));

    if (susshi_session.operation_mode == OP_MODE_GATEWAY) {
        if (susshi_session.target_user && blength(susshi_session.target_user) > 0)
            susshi_env_append(envp, &idx, "SUSSHI_TARGET_USER=%s",
                       bdata(susshi_session.target_user));

        if (susshi_session.target_host && blength(susshi_session.target_host) > 0)
            susshi_env_append(envp, &idx, "SUSSHI_TARGET_HOST=%s",
                       bdata(susshi_session.target_host));

        if (susshi_session.target_port > 0)
            susshi_env_append(envp, &idx, "SUSSHI_TARGET_PORT=%d",
                       susshi_session.target_port);

        if (susshi_session.target_ip && blength(susshi_session.target_ip) > 0)
            susshi_env_append(envp, &idx, "SUSSHI_TARGET_IP=%s",
                       bdata(susshi_session.target_ip));
    }

    if (susshi_session.log_session.filename &&
        blength(susshi_session.log_session.filename) > 0) {

    	bstring audit_path = NULL, file_type = NULL;

    	susshi_env_append(envp, &idx, "SUSSHI_SESSION_LOG=%s",
    		bdata(susshi_session.log_session.filename));

    	log_filename_expand(&audit_path, susshi_cfg.logfile_audit, file_type = bfromcstr("*"), -2);

    	susshi_env_append(envp, &idx, "SUSSHI_AUDIT_LOG_PATTERN=%s",
				   bdata(audit_path));

    	bdestroy(file_type);
    	bdestroy(audit_path);
    }

    /* idx < HOOK_ENV_MAX - 1 is guaranteed by the count above; calloc zeroed the rest */
    return envp;
}


/*!
 * @brief   Read from fd line by line and forward each line to syslog.
 *
 * Called in the intermediate child after the hook process has been launched.
 * Reads until EOF (pipe write-end closed by hook exit).
 *
 * @param   hook_name   Used as tag in the syslog message.
 * @param   fd          Read end of the pipe connected to hook stdout/stderr.
 */

static void
susshi_log_hook_output(const char *hook_name, int fd) {
    char buf[4096];
    char line[1024];
    int line_len = 0;
    ssize_t nread;

    while ((nread = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < nread; i++) {
            if (buf[i] == '\n' || line_len >= (int) sizeof(line) - 1) {
                line[line_len] = '\0';
                if (line_len > 0)
                    log_system(LOG_LEVEL_INFO, "hooks/%s: %s", hook_name, line);
                line_len = 0;
            } else {
                line[line_len++] = buf[i];
            }
        }
    }

    if (line_len > 0) {
        line[line_len] = '\0';
        log_system(LOG_LEVEL_INFO, "hook [%s]: %s", hook_name, line);
    }
}


/*!
 * @brief   Scan PATH_SUSSHI_HOOKS for present and executable hook files.
 *
 * Must be called once during daemon initialisation.  The result is cached in
 * the static hook_available[] / hook_paths[] arrays and does not change for
 * the lifetime of the process.  To pick up newly installed hooks a daemon
 * restart is required.
 */

void
susshi_hooks_init(void) {
    for (int i = 0; i < HOOK_COUNT; i++) {
        snprintf(hook_paths[i], sizeof(hook_paths[i]),
                 "%s/%s", PATH_SUSSHI_HOOKS, hook_names[i]);

        hook_available[i] = (access(hook_paths[i], X_OK) == 0);

        if (hook_available[i])
            log_system(LOG_LEVEL_INFO, "Hook registered: %s", hook_paths[i]);
        else
            debug1("Hook not available or not executable: %s", hook_paths[i]);
    }
}


/*!
 * @brief   Execute a hook asynchronously via double-fork.
 *
 * If the hook is not available the function returns immediately without any
 * system calls.
 *
 * Execution model:
 *   susshid (grandparent)
 *     └─ intermediate child  — sets up pipe, forks hook, reads output, exits
 *          └─ hook process   — execs the hook binary, stdout/stderr → pipe
 *
 * susshid performs a non-blocking waitpid() on the intermediate child.  In the
 * master process the SIGCHLD handler reaps it; in session children it becomes a
 * brief zombie that is cleaned up when the session exits.
 *
 * @param   hook    Which hook to run.
 */

void
susshi_hooks_run(HookType hook) {
    char **envp;
    pid_t intermediate;
    int pipefd[2];
    pid_t hook_pid;
    int status;

    if (!hook_available[hook])
        return;

    /* session-* hooks must not fire in chef-remote sessions. */
    if (hook != HOOK_GATEWAY_START && hook != HOOK_GATEWAY_STOP &&
        susshi_session.operation_mode == OP_MODE_CHEF_REMOTE)
        return;

    log_system(LOG_LEVEL_INFO, "Running hook: %s", hook_names[hook]);

    envp = susshi_build_hook_env(hook);
    if (!envp) {
        log_system(LOG_LEVEL_ERROR, "Hook %s: failed to build environment, skipping.",
                   hook_names[hook]);
        return;
    }

    intermediate = fork();

    if (intermediate < 0) {
        log_system(LOG_LEVEL_ERROR, "Hook %s: fork() failed: %s",
                   hook_names[hook], strerror(errno));
        susshi_free_hook_env(envp);
        return;
    }

    if (intermediate > 0) {
        /* grandparent: free our copy of the env (child has its own after fork) */
        susshi_free_hook_env(envp);

        /* Non-blocking reap attempt; the SIGCHLD handler handles the rest in the
         * master process.  In session processes SIGCHLD is SIG_IGN, so the
         * kernel auto-reaps the intermediate child when it exits. */
        waitpid(intermediate, NULL, WNOHANG);
        return;
    }

    /* ---- intermediate child ---- */

    SETPROCTITLE("Running hook %s", hook_names[hook]);

    if (pipe(pipefd) == -1) {
        log_system(LOG_LEVEL_ERROR, "hooks/%s: pipe() failed: %s", hook_names[hook], strerror(errno));
        _exit(1);
    }

    hook_pid = fork();

    if (hook_pid < 0) {
        log_system(LOG_LEVEL_ERROR, "hooks/%s: fork() failed: %s", hook_names[hook], strerror(errno));
        _exit(1);
    }

    if (hook_pid == 0) {
        /* ---- hook process (grandchild) ---- */
        char *argv[] = { hook_paths[hook], NULL };
        int devnull;

        /* Redirect stdin to /dev/null so the hook cannot read from the gateway's stdin. */
        devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            if (devnull != STDIN_FILENO)
                close(devnull);
        }

        /* Route stdout and stderr through the pipe to the intermediate child. */
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        /* Close all inherited file descriptors except stdin/stdout/stderr. */
        close(pipefd[0]);
        close(pipefd[1]);
        closefrom(3);

        execve(hook_paths[hook], argv, envp);

        /* execve only returns on failure */
        _exit(127);
    }

    /* ---- intermediate child continues ---- */

    /* Close the write end so we get EOF when the hook process exits. */
    close(pipefd[1]);

    susshi_log_hook_output(hook_names[hook], pipefd[0]);
    close(pipefd[0]);

    if (waitpid(hook_pid, &status, 0) != -1) {
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
            log_system(LOG_LEVEL_WARNING, "hooks/%s: exited with status %d",
                       hook_names[hook], WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            log_system(LOG_LEVEL_WARNING, "hooks/%s: killed by signal %d",
                       hook_names[hook], WTERMSIG(status));
    }

    _exit(0);
}

/*! @} */
