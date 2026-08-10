/*!
 *
 * @brief       Shell Loop
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
 * @date        2026-02-01
 *
 * @defgroup    shell_loop CLI Shell Loop
 * @brief       Functions implementing a basic CLI shell
 * @{
 */

#include "susshid/common.h"


/*! @cond */
static struct {
	ssh_channel channel;
} int_store;
/*! @endcond */


/*!
 * @brief       Open Channel request handler
 *
 * @param       session
 * @param       userdata
 *
 * @return      ssh_channel
 */

static ssh_channel
channel_open_request(ssh_session session, void *userdata) {
	(void) userdata;

	int_store.channel = ssh_channel_new(session);
	return int_store.channel;
}


/*!
 * @brief       Handles incoming data on an SSH channel and writes it to a child process's stdin.
 *
 * This callback is invoked when data arrives on an SSH channel. It forwards
 * the data to the stdin of the associated child process, provided the process
 * is still alive and the data is non-empty.
 *
 * @param[in] session   The SSH session (unused).
 * @param[in] channel   The SSH channel on which data was received (unused).
 * @param[in] data      Pointer to the received data buffer.
 * @param[in] len       Length of the received data in bytes.
 * @param[in] is_stderr Flag indicating whether the data is from stderr (unused).
 * @param[in] userdata  Pointer to a @c shell_channel_data_struct containing
 *                      the child PID and stdin file descriptor.
 *
 * @return      The number of bytes written to the child's stdin on success,
 *              or @c 0 if @p len is zero, the child PID is invalid, or the
 *              child process is no longer running.
 */

static int
channel_data(ssh_session session, ssh_channel channel, void *data,
			 uint32_t len, int is_stderr, void *userdata) {
	struct shell_channel_data_struct *cdata;
	(void) session;
	(void) channel;
	(void) is_stderr;

	cdata = (struct shell_channel_data_struct *) userdata;

	if (len == 0 || cdata->child_pid < 1 || kill(cdata->child_pid, 0) < 0) {
		return 0;
	}

	return (int) write(cdata->child_stdin, (char *) data, len);
}


/*!
 * @brief       Handles a PTY allocation request on an SSH channel.
 *
 * Stores the terminal type and window dimensions from the client's PTY request
 * into @p userdata, then opens a pseudo-terminal via openpty(). The resulting
 * master/slave PTY file descriptors are stored in the channel data struct for
 * later use by the shell.
 *
 * @param[in]  session  The SSH session (unused).
 * @param[in]  channel  The SSH channel (unused).
 * @param[in]  term     The terminal type string (e.g. "xterm-256color"). Stored
 *                      but otherwise unused by this handler.
 * @param[in]  cols     Number of terminal columns.
 * @param[in]  rows     Number of terminal rows.
 * @param[in]  py       Terminal height in pixels.
 * @param[in]  px       Terminal width in pixels.
 * @param[in]  userdata Pointer to a @c shell_channel_data_struct in which the
 *                      terminal dimensions and PTY file descriptors are stored.
 *
 * @return      @c SSH_OK on success, or @c SSH_ERROR if openpty() fails.
 */

static int
channel_pty_request(ssh_session session, ssh_channel channel,
					const char *term, int cols, int rows, int py, int px,
					void *userdata) {
	struct shell_channel_data_struct *cdata;
	(void) session;
	(void) channel;
	(void) term;

	cdata = (struct shell_channel_data_struct *)userdata;

	cdata->term = bfromcstr(term);
	cdata->winsize->ws_row = (unsigned short) rows;
	cdata->winsize->ws_col = (unsigned short) cols;
	cdata->winsize->ws_xpixel = (unsigned short) px;
	cdata->winsize->ws_ypixel = (unsigned short) py;

	if (openpty(&cdata->pty_master, &cdata->pty_slave, NULL, NULL,
		cdata->winsize) != 0) {
		fprintf(stderr, "Failed to open pty\n");
		return SSH_ERROR;
	}
	return SSH_OK;
}


/*!
 * @brief       Handles a PTY window resize event on an SSH channel.
 *
 * Updates the stored window dimensions in @p userdata and, if the PTY master
 * file descriptor is open, propagates the new size to the kernel via
 * TIOCSWINSZ so that the child process receives a SIGWINCH.
 *
 * @param[in]  session  The SSH session (unused).
 * @param[in]  channel  The SSH channel (unused).
 * @param[in]  cols     New number of terminal columns.
 * @param[in]  rows     New number of terminal rows.
 * @param[in]  py       New terminal height in pixels.
 * @param[in]  px       New terminal width in pixels.
 * @param[in]  userdata Pointer to a @c shell_channel_data_struct holding the
 *                      current window size and PTY master file descriptor.
 *
 * @return      The result of ioctl() on success, or @c SSH_ERROR if the PTY master is not open.
 */

static int
channel_pty_window_change(ssh_session session, ssh_channel channel, int cols,
						  int rows, int py, int px, void *userdata) {
	struct shell_channel_data_struct *cdata;
	(void) session;
	(void) channel;

	cdata = (struct shell_channel_data_struct *) userdata;

	cdata->winsize->ws_row = (unsigned short) rows;
	cdata->winsize->ws_col = (unsigned short) cols;
	cdata->winsize->ws_xpixel = (unsigned short) px;
	cdata->winsize->ws_ypixel = (unsigned short) py;

	if (cdata->pty_master != -1) {
		return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
	}

	return SSH_ERROR;
}


/*!
 * @brief       Forks a child process attached to a PTY to run the shell.
 *
 * Called internally to spawn a shell under a previously allocated PTY.
 * The @p mode argument is passed as a shell flag (e.g. @c "-l" for a login
 * shell, @c "-c" for command execution). If @p command is non-NULL, the client
 * is disconnected with @c DISCONNECT_SERVICE_NOT_AVAILABLE, as arbitrary
 * command execution via PTY is not permitted.
 *
 * In the child process, the PTY slave becomes the controlling terminal via
 * login_tty(). The parent retains the PTY master and uses it as the
 * bidirectional stdin/stdout for the child.
 *
 * @param[in]     mode   Shell invocation flag (e.g. @c "-l" or @c "-c").
 * @param[in]     command  Command string; must be @c NULL for PTY-based shell
 *                         invocation. A non-NULL value triggers disconnection.
 * @param[in,out] cdata  Pointer to a @c shell_channel_data_struct. On success,
 *                       @c child_pid is set to the forked PID and both
 *                       @c child_stdin and @c child_stdout are set to the PTY
 *                       master fd.
 *
 * @return      @c SSH_OK on success, or @c SSH_ERROR if fork() fails.
 */

static int
exec_pty(const char *mode, const char *command,
		 struct shell_channel_data_struct *cdata) {

	if (command != NULL)
		susshi_disconnect_standard(CLIENT, DISCONNECT_SERVICE_NOT_AVAILABLE);

	switch(cdata->child_pid = fork()) {

		case -1:
			close(cdata->pty_master);
			close(cdata->pty_slave);
			return SSH_ERROR;

		case 0:
			close(cdata->pty_master);

			if (login_tty(cdata->pty_slave) != 0)
				susshi_disconnect_standard(CLIENT, DISCONNECT_SERVICE_NOT_AVAILABLE);

			susshi_shell(cdata);
			exit(0);
			break;

		default:
			close(cdata->pty_slave);
			/* pty fd is bi-directional */
			cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
	}

	return SSH_OK;
}


/*!
 * @brief       Forks a child process with piped stdin/stdout/stderr for command execution (not yet implemented).
 *
 * Sets up three pipes to communicate with the child process over its standard
 * streams, then forks. In the child, the pipe ends are dup'd onto the standard
 * file descriptors before calling susshi_disconnect_standard(), as non-PTY
 * command execution is not yet implemented. In the parent, the write end of
 * @c in and the read ends of @c out and @c err are stored in @p cdata for use
 * as the child's stdin, stdout, and stderr respectively.
 *
 * Cleans up all pipe file descriptors on any failure before returning.
 *
 * @param[in]     command  The command to execute (currently unused; triggers
 *                         disconnection in the child).
 * @param[in,out] cdata    Pointer to a @c shell_channel_data_struct. On
 *                         success, @c child_pid, @c child_stdin,
 *                         @c child_stdout, and @c child_stderr are populated.
 *
 * @return      @c SSH_OK on success, or @c SSH_ERROR if any pipe() or fork() call fails
 */

static int
exec_nopty(const char *command, struct shell_channel_data_struct *cdata) {

	int in[2], out[2], err[2];

	/* Do the plumbing to be able to talk with the child process. */
	if (pipe(in) != 0) {
		goto stdin_failed;
	}
	if (pipe(out) != 0) {
		goto stdout_failed;
	}
	if (pipe(err) != 0) {
		goto stderr_failed;
	}

	switch(cdata->child_pid = fork()) {
		case -1:
			goto fork_failed;
		case 0:
			/* Finish the plumbing in the child process. */
			close(in[1]);
			close(out[0]);
			close(err[0]);
			dup2(in[0], STDIN_FILENO);
			dup2(out[1], STDOUT_FILENO);
			dup2(err[1], STDERR_FILENO);
			close(in[0]);
			close(out[1]);
			close(err[1]);
			/* exec the requested command. */
			susshi_disconnect_standard(CLIENT, DISCONNECT_SERVICE_NOT_AVAILABLE);
			exit(0);
	}

	close(in[0]);
	close(out[1]);
	close(err[1]);

	cdata->child_stdin = in[1];
	cdata->child_stdout = out[0];
	cdata->child_stderr = err[0];

	return SSH_OK;

	fork_failed:
	close(err[0]);
	close(err[1]);
	stderr_failed:
	close(out[0]);
	close(out[1]);
	stdout_failed:
	close(in[0]);
	close(in[1]);
	stdin_failed:
	return SSH_ERROR;
}


/*!
 * @brief       Handles an exec request on an SSH channel.
 *
 * Dispatches a client exec request to either exec_pty() or exec_nopty()
 * depending on whether a PTY has already been allocated for the channel.
 * Rejects the request if a child process is already running.
 *
 * @param[in]  session  The SSH session (unused).
 * @param[in]  channel  The SSH channel (unused).
 * @param[in]  command  The command string requested by the client.
 * @param[in]  userdata Pointer to a @c shell_channel_data_struct holding the
 *                      current child PID and PTY file descriptors.
 *
 * @return      @c SSH_OK on success, @c SSH_ERROR if a child is already running,
 *              or the return value of exec_pty() / exec_nopty() on failure.
 */

static int
channel_exec_request(ssh_session session, ssh_channel channel,
					const char *command, void *userdata) {

	struct shell_channel_data_struct *cdata;
	(void) session;
	(void) channel;

	cdata = (struct shell_channel_data_struct *) userdata;

	if(cdata->child_pid > 0) {
		return SSH_ERROR;
	}

	if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
		return exec_pty("-c", command, cdata);
	}
	return exec_nopty(command, cdata);
}


/*!
 * @brief       Handles a shell request on an SSH channel.
 *
 * Spawns an interactive login shell via exec_pty() using the @c "-l" flag.
 * Requires that a PTY has already been allocated; if none is present the
 * client is disconnected with an informative message. Also rejects the request
 * if a child process is already running.
 *
 * @param[in]  session  The SSH session (unused).
 * @param[in]  channel  The SSH channel (unused).
 * @param[in]  userdata Pointer to a @c shell_channel_data_struct holding the
 *                      current child PID and PTY file descriptors.
 *
 * @return      @c SSH_OK on success, or @c SSH_ERROR if a child is already running
 *              or no PTY is available
 */

static int
channel_shell_request(ssh_session session, ssh_channel channel,
								 void *userdata) {
	struct shell_channel_data_struct *cdata = (struct shell_channel_data_struct *) userdata;

	(void) session;
	(void) channel;

	if(cdata->child_pid > 0) {
		return SSH_ERROR;
	}

	if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
		return exec_pty("-l", NULL, cdata);
	}

	/* Client requested a shell without a pty */
	susshi_disconnect_individual(CLIENT, SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,
								 SUSSHI_NAME " shell requires pty. Please connect in pty mode.");

	return SSH_ERROR;
}


/*!
 * @brief       Poll callback that reads from a child's stdout and writes to an SSH channel.
 *
 * Invoked by the libssh event loop when @p fd becomes readable. Reads up to
 * @c SHELL_BUF_SIZE bytes and forwards them to the SSH channel via
 * ssh_channel_write().
 *
 * @param[in]  fd       File descriptor to read from (child's stdout).
 * @param[in]  revents  Poll event flags; data is only read when @c POLLIN is set.
 * @param[in]  userdata Pointer to the @c ssh_channel to write output into.
 *
 * @return      The number of bytes read on success, @c 0 if the channel is NULL or
 *              @c POLLIN is not set, or @c -1 on read error.
 */

static int
process_stdout(socket_t fd, int revents, void *userdata) {
	char buf[SHELL_BUF_SIZE];
	int n = -1;
	ssh_channel channel = (ssh_channel) userdata;

	if (channel != NULL && (revents & POLLIN) != 0) {
		n = (int) read(fd, buf, SHELL_BUF_SIZE);
		if (n > 0) {
			ssh_channel_write(channel, buf, n);
		}
	}

	return n;
}


/*!
 * @brief       Poll callback that reads from a child's stderr and writes to an SSH channel's stderr stream.
 *
 * Identical in structure to process_stdout(), but reads from the child's
 * stderr file descriptor and forwards data via ssh_channel_write_stderr().
 *
 * @param[in]  fd       File descriptor to read from (child's stderr).
 * @param[in]  revents  Poll event flags; data is only read when @c POLLIN is set.
 * @param[in]  userdata Pointer to the @c ssh_channel to write stderr output into.
 *
 * @return      The number of bytes read on success, @c 0 if the channel is NULL or
 *              @c POLLIN is not set, or @c -1 on read error.
 */

static int
process_stderr(socket_t fd, int revents, void *userdata) {
	char buf[SHELL_BUF_SIZE];
	int n = -1;
	ssh_channel channel = (ssh_channel) userdata;

	if (channel != NULL && (revents & POLLIN) != 0) {
		n = (int) read(fd, buf, SHELL_BUF_SIZE);
		if (n > 0) {
			ssh_channel_write_stderr(channel, buf, n);
		}
	}

	return n;
}


/*!
 * @brief       Initialises the SSH channel callbacks and runs the shell event loop.
 *
 * This is the main entry point for the interactive shell session. It performs
 * the following steps:
 *
 * -# Initialises a @c shell_channel_data_struct and registers server-level and
 *    channel-level libssh callbacks.
 * -# Polls until the client opens a session channel.
 * -# Polls in a loop, forwarding child stdout/stderr into the SSH channel once
 *    the child process has been spawned, until the channel is closed or the
 *    child exits.
 * -# Cleans up file descriptors and event sources, sends the child's exit
 *    status (or kills it if still running), and closes the channel.
 * -# Waits up to 5 seconds for the client to terminate the session before
 *    freeing the event context.
 *
 * Relies on the global @c int_store.channel and @c susshi_session. Does not
 * return a value; errors are reported to stderr.
 */

void
susshi_shell_loop(void) {

	ssh_event event_ctxt;
	int n, rc;

	/* Structure for storing the pty size. */
	struct winsize wsize = {
			.ws_row = 0,
			.ws_col = 0,
			.ws_xpixel = 0,
			.ws_ypixel = 0
	};

	/* Our struct holding information about the channel. */
	struct shell_channel_data_struct cdata = {
			.child_pid = 0,
			.pty_master = -1,
			.pty_slave = -1,
			.child_stdin = -1,
			.child_stdout = -1,
			.child_stderr = -1,
			.event = NULL,
			.winsize = &wsize
	};

	struct ssh_channel_callbacks_struct channel_cb = {
			.userdata = &cdata,
			.channel_pty_request_function = channel_pty_request,
			.channel_pty_window_change_function = channel_pty_window_change,
			.channel_shell_request_function = channel_shell_request,
			.channel_exec_request_function = channel_exec_request,
			.channel_data_function = channel_data
			// .channel_subsystem_request_function = subsystem_request
	};

	struct ssh_server_callbacks_struct server_cb = {
			.channel_open_request_session_function = channel_open_request,
	};

	int_store.channel = NULL;

	/* Init callbacks */
	ssh_callbacks_init(&server_cb);
	ssh_callbacks_init(&channel_cb);

	/* Wait for channel open request */
	ssh_set_server_callbacks(susshi_session.client_session, &server_cb);

	event_ctxt = ssh_event_new();
	ssh_event_add_session(event_ctxt, susshi_session.client_session);

	while (int_store.channel == NULL) {
		if (ssh_event_dopoll(event_ctxt, -1) == SSH_ERROR) {
			fprintf(stderr, "%s\n", ssh_get_error(susshi_session.client_session));
			return;
		}
	}

	/* We have a channel */

	/* Wait for other requests and loop through data */
	ssh_set_channel_callbacks(int_store.channel, &channel_cb);

	SETPROCTITLE("%s (suSSHi-Shell) %s",
				 bdata(susshi_session.susshi_uniqid),
				 bdata(susshi_session.susshi_user));

	do {
		if (ssh_event_dopoll(event_ctxt, -1) == SSH_ERROR)
			ssh_channel_close(int_store.channel);

		if (cdata.event != NULL || cdata.child_pid == 0)
			continue;

		cdata.event = event_ctxt;

		if (cdata.child_stdout != -1) {
			if (ssh_event_add_fd(event_ctxt, cdata.child_stdout, POLLIN, process_stdout,
								 int_store.channel) != SSH_OK) {
				fprintf(stderr, "Failed to register stdout to poll context\n");
				ssh_channel_close(int_store.channel);
			}
		}

		if (cdata.child_stderr != -1){
			if (ssh_event_add_fd(event_ctxt, cdata.child_stderr, POLLIN, process_stderr,
								 int_store.channel) != SSH_OK) {
				fprintf(stderr, "Failed to register stderr to poll context\n");
				ssh_channel_close(int_store.channel);
			}
		}
	} while(ssh_channel_is_open(int_store.channel) &&
			(cdata.child_pid == 0 || waitpid(cdata.child_pid, &rc, WNOHANG) == 0));


	close(cdata.pty_master);
	close(cdata.child_stdin);
	close(cdata.child_stdout);
	close(cdata.child_stderr);

	ssh_event_remove_fd(event_ctxt, cdata.child_stdout);
	ssh_event_remove_fd(event_ctxt, cdata.child_stderr);

	if (kill(cdata.child_pid, 0) < 0 && WIFEXITED(rc)) {
		rc = WEXITSTATUS(rc);
		ssh_channel_request_send_exit_status(int_store.channel, rc);
	} else if (cdata.child_pid > 0) {
		kill(cdata.child_pid, SIGKILL);
	}

	ssh_channel_send_eof(int_store.channel);
	ssh_channel_close(int_store.channel);

	/* Wait up to 5 seconds for the client to terminate the session. */
	for (n = 0; n < 50 && (ssh_get_status(susshi_session.client_session) & ((SSH_CLOSED | SSH_CLOSED_ERROR))) == 0; n++) {
		ssh_event_dopoll(event_ctxt, 100);
	}

	ssh_event_free(event_ctxt);
}

/*! @} */
