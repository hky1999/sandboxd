// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	contMgrSetNetworkArgs     = "containerManager.SetNetworkArgs"
	contMgrRootContainerStart = "containerManager.StartRoot"
	contMgrRestore            = "containerManager.Restore"
	contMgrWait               = "containerManager.Wait"
)

type controlRPC interface {
	Call(method string, arg, result any) error
	Close() error
}

type interruptibleControlRPC interface {
	Interrupt() error
}

// Client is sandboxd's narrow adapter over upstream gVisor runsc. It avoids
// linking runsc/boot or runsc/container directly because those packages pull in
// the sentry/boot build graph and generated artifacts.
type Client struct {
	Binary  string
	RootDir string
	Options Options

	connectControl      func(string) (controlRPC, error)
	controlPeerObserved func(map[string]any)
}

type Options struct {
	ExtraArgs          []string
	Platform           string
	FilestoreDir       string
	OverlayTmpfsSize   string
	DebugLogPath       string
	IgnoreCgroups      bool
	PlatformDevicePath string
}

type StartArgs struct {
	ID                 string
	ResourceGeneration string
	BundleDir          string
	UserStdout         string
	UserStderr         string
	RootOverlay        string
	Network            NetworkConfig
	// FsRestoreImagePath restores the gVisor writable-layer filestore from a
	// filesystem checkpoint (runsc fscheckpoint artifact directory). Empty
	// keeps the historical behavior of a fresh writable layer.
	FsRestoreImagePath string
}

func NewClient(binary, rootDir string) *Client {
	return NewClientWithOptions(binary, rootDir, Options{})
}

func NewClientWithOptions(binary, rootDir string, options Options) *Client {
	if options.ExtraArgs == nil {
		options.ExtraArgs = []string{"--net-raw=true"}
	}
	return &Client{
		Binary:  binary,
		RootDir: rootDir,
		Options: options,
		connectControl: func(path string) (controlRPC, error) {
			return connectRPC(path)
		},
	}
}

// Create performs the single required runsc binary exec. It intentionally uses
// regular files for stdio so the boot/gofer processes do not inherit pipes held
// by exec.Cmd, which can otherwise make create appear to hang.
func (c *Client) Create(ctx context.Context, args StartArgs) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if args.ID == "" {
		return fmt.Errorf("container id is empty")
	}
	if args.BundleDir == "" {
		return fmt.Errorf("bundle dir is empty for %s", args.ID)
	}
	if c.Options.FilestoreDir == "" {
		return fmt.Errorf("filestore directory is empty for %s", args.ID)
	}
	if args.ResourceGeneration != "" {
		if err := c.verifyManagedCreateInput(args); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(c.RootDir, 0711); err != nil {
		return fmt.Errorf("create runsc root %s: %w", c.RootDir, err)
	}
	if args.ResourceGeneration != "" {
		root, original, err := openRuntimeIdentityDirectory(c.RootDir)
		if err != nil {
			return fmt.Errorf("open managed runtime root before create: %w", err)
		}
		defer root.Close()
		if err := verifyRuntimeIdentityDirectory(c.RootDir, original); err != nil {
			return err
		}
	}

	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer stdin.Close()

	stdout, err := openOutputFile(args.UserStdout)
	if err != nil {
		return fmt.Errorf("open stdout file %q: %w", args.UserStdout, err)
	}
	defer stdout.Close()

	stderr, err := openOutputFile(args.UserStderr)
	if err != nil {
		return fmt.Errorf("open stderr file %q: %w", args.UserStderr, err)
	}
	defer stderr.Close()

	cmdArgs := append(c.globalArgs(),
		"-network=sandbox",
	)
	cmdArgs = append(cmdArgs, c.Options.ExtraArgs...)
	if c.Options.DebugLogPath != "" {
		cmdArgs = append(cmdArgs, "-debug-log="+c.Options.DebugLogPath)
	}
	rootOverlay := args.RootOverlay
	if rootOverlay == "" {
		rootOverlay = RootFileOverlay(c.Options.FilestoreDir, c.Options.OverlayTmpfsSize)
	}
	cmdArgs = append(cmdArgs, "--overlay2="+rootOverlay)
	cmdArgs = append(cmdArgs, "create")
	if args.ResourceGeneration != "" {
		cmdArgs = append(cmdArgs, "--scheduler-resource-generation="+args.ResourceGeneration)
	}
	cmdArgs = append(cmdArgs, "--bundle", args.BundleDir)
	if args.FsRestoreImagePath != "" {
		cmdArgs = append(cmdArgs, "--fs-restore-image-path", args.FsRestoreImagePath)
	}
	cmdArgs = append(cmdArgs, args.ID)
	cmd := exec.CommandContext(ctx, c.Binary, cmdArgs...)
	cmd.Env = os.Environ()
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	start := time.Now()
	logrus.Debugf("runsc create command started, id: %s, args: %v", args.ID, cmdArgs)
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if stderrOutput := readOutputSnippet(args.UserStderr); stderrOutput != "" {
			return fmt.Errorf("runsc create %s failed: %w: %s", args.ID, err, stderrOutput)
		}
		return fmt.Errorf("runsc create %s failed: %w", args.ID, err)
	}
	logrus.Debugf("runsc create command finished, id: %s, cost: %v", args.ID, time.Since(start))
	if args.ResourceGeneration != "" {
		if _, err := c.loadStartState(args); err != nil {
			return fmt.Errorf("created runsc state has unconfirmed ownership: %w", err)
		}
	}
	return nil
}

// RootFileOverlay returns a writable root overlay backed by dir.
func RootFileOverlay(dir, size string) string {
	overlay := "root:dir=" + dir
	if size == "" {
		return overlay
	}
	return overlay + ",size=" + size
}

// Extra arguments are flags, not shell text or runsc subcommands. Require
// --name=value even for booleans, so a flag cannot consume a managed argument.
func validateExtraArgs(args []string) error {
	for _, arg := range args {
		name, _, hasValue := strings.Cut(arg, "=")
		if !hasValue || !strings.HasPrefix(name, "--") || len(name) == 2 || strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("invalid extra_args entry %q: use --name=value (including booleans)", arg)
		}
		switch name {
		case "--root", "--platform", "--network", "--overlay2", "--ignore-cgroups", "--debug-log", "--bundle":
			return fmt.Errorf("extra_args cannot override sandboxd-managed flag %s", name)
		}
	}
	return nil
}

func (c *Client) globalArgs() []string {
	args := []string{"--root", c.RootDir}
	if c.Options.Platform != "" {
		args = append(args, "--platform="+c.Options.Platform)
	}
	if c.Options.IgnoreCgroups {
		args = append(args, "--ignore-cgroups")
	}
	return args
}

func openOutputFile(path string) (*os.File, error) {
	if path == "" {
		return os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
}

func readOutputSnippet(path string) string {
	if path == "" || path == os.DevNull {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	const maxSnippetLen = 4096
	if len(data) > maxSnippetLen {
		data = data[len(data)-maxSnippetLen:]
	}
	return strings.TrimSpace(string(data))
}

// Start configures external networking with a cached TAP FD and starts the root
// container through gVisor's existing control RPCs.
func (c *Client) Start(ctx context.Context, args StartArgs) error {
	if args.Network.Interface == nil {
		return fmt.Errorf("network interface is nil for %s", args.ID)
	}
	logrus.Debugf("runsc start rpc flow started, id: %s", args.ID)
	transition, state, err := c.beginStartTransition(ctx, args)
	if err != nil {
		return fmt.Errorf("load runsc state for %s: %w", args.ID, err)
	}
	defer transition.close()
	conn, err := transition.connect(ctx, state.Sandbox.ControlSocketPath)
	if err != nil {
		return fmt.Errorf("connect runsc control socket for %s: %w", args.ID, err)
	}
	defer conn.Close()
	if err := transition.authenticate(ctx, conn, state, args); err != nil {
		return err
	}
	logrus.Debugf("runsc start loaded state, id: %s, control_socket: %s", args.ID, state.Sandbox.ControlSocketPath)

	logrus.Debugf("runsc start opening TAP, id: %s, interface: %+v", args.ID, args.Network.Interface)
	tap, err := OpenTAP(*args.Network.Interface)
	if err != nil {
		return err
	}
	defer tap.Close()
	logrus.Debugf("runsc start opened TAP, id: %s", args.ID)

	networkArgs, err := BuildNetworkArgs(args.Network, tap)
	if err != nil {
		return err
	}
	logrus.Debugf("runsc start built network args, id: %s", args.ID)

	logrus.Debugf("runsc start connecting control socket, id: %s, socket: %s", args.ID, state.Sandbox.ControlSocketPath)
	logrus.Debugf("runsc start connected control socket, id: %s", args.ID)

	if err := callContextWithTimeout(ctx, conn, contMgrSetNetworkArgs, networkArgs, nil, 30*time.Second); err != nil {
		return fmt.Errorf("set network arguments for %s: %w", args.ID, err)
	}
	if err := transition.check(ctx); err != nil {
		return err
	}
	if err := callContextWithTimeout(ctx, conn, contMgrRootContainerStart, &args.ID, nil, 30*time.Second); err != nil {
		return fmt.Errorf("start root container %s: %w", args.ID, err)
	}
	if err := transition.markRunning(ctx); err != nil {
		return fmt.Errorf("mark runsc state running for %s: %w", args.ID, err)
	}
	return nil
}

// Checkpoint saves a sandbox to imageDir using the stable upstream runsc CLI.
// A non-empty fsCheckpointPaths adds runsc's --fs-checkpoint-paths so ONE
// invocation writes both the sentry state and the filesystem artifact under
// imageDir/fs; runsc then excludes those private memory files from the sentry
// state, which is exactly the split the restore-side duplicate guard requires.
func (c *Client) Checkpoint(
	ctx context.Context, id, imageDir string, compress, leaveRunning bool, fsCheckpointPaths ...string,
) error {
	if id == "" {
		return fmt.Errorf("container id is empty")
	}
	if imageDir == "" {
		return fmt.Errorf("checkpoint image directory is empty for %s", id)
	}
	for _, p := range fsCheckpointPaths {
		if p == "" {
			return fmt.Errorf("empty filesystem checkpoint path for %s", id)
		}
	}

	args := append(c.globalArgs(), "checkpoint")
	compression := "none"
	if compress {
		compression = "flate-best-speed"
	}
	args = append(args, "--compression="+compression)
	if leaveRunning {
		args = append(args, "--leave-running")
	}
	if len(fsCheckpointPaths) > 0 {
		args = append(args, "--fs-checkpoint-paths="+strings.Join(fsCheckpointPaths, ","))
	}
	args = append(args, "--image-path", imageDir, id)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("runsc checkpoint %s failed: %w: %s", id, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// FsCheckpoint saves the gVisor writable-layer filestore to imageDir using
// the upstream runsc fscheckpoint subcommand. The artifact is a raw
// uncompressed directory tree (fscheckpoint.pb + pages.img + ...) that a
// later Create can consume through FsRestoreImagePath.
func (c *Client) FsCheckpoint(ctx context.Context, id, imageDir string, leaveRunning bool) error {
	if id == "" {
		return fmt.Errorf("container id is empty")
	}
	if imageDir == "" {
		return fmt.Errorf("filesystem checkpoint image directory is empty for %s", id)
	}
	args := append(c.globalArgs(), "fscheckpoint")
	if leaveRunning {
		args = append(args, "--leave-running")
	}
	args = append(args, "--image-path", imageDir, id)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("runsc fscheckpoint %s failed: %w: %s", id, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// Pause freezes all container tasks in the sandbox. It is the consistency
// point used when pairing a memory-state checkpoint with a filesystem
// checkpoint.
func (c *Client) Pause(ctx context.Context, id string) error {
	return c.simpleCommand(ctx, "pause", id)
}

// Resume unfreezes previously paused container tasks.
func (c *Client) Resume(ctx context.Context, id string) error {
	return c.simpleCommand(ctx, "resume", id)
}

func (c *Client) simpleCommand(ctx context.Context, subcommand, id string) error {
	if id == "" {
		return fmt.Errorf("container id is empty")
	}
	args := append(c.globalArgs(), subcommand, id)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("runsc %s %s failed: %w: %s", subcommand, id, err, strings.TrimSpace(string(output)))
	}
	return nil
}

type restoreOpts struct {
	payload filePayload `json:"-"`

	HavePagesFile      bool
	HaveDeviceFile     bool
	Background         bool
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`
	// SplitFSRestore mirrors runsc's RestoreOpts.SplitFSRestore (wire name
	// "split_fsrestore"). runsc rejects a Restore whose donated filesystem
	// restore files — handed to the loader by Create through
	// --fs-restore-image-path — disagree with this flag, so it must be
	// derived from the same StartArgs.FsRestoreImagePath Create consumed.
	SplitFSRestore bool `json:"split_fsrestore"`
}

const (
	checkpointPagesMetadataName = "pages_meta.img"
	checkpointPagesName         = "pages.img"
)

func (o *restoreOpts) filePayload() []*os.File {
	return o.payload.Files
}

func (o *restoreOpts) setFilePayload(files []*os.File) {
	o.payload.Files = files
}

// Restore connects a runsc sandbox previously created with Create, installs
// its target networking, and restores the checkpoint files.
//
// The ordering mirrors runsc's own Sandbox.Restore: links and routes are
// configured through the control RPC while the sandbox is still in the
// created state (the post-restore sentry tightens its seccomp policy and
// can no longer create NICs), then the checkpoint files are pushed through
// the containerManager.Restore control RPC. The checkpoint's pages file
// already carries the writable-layer contents — the overlay upper tmpfs is
// part of the saved sentry state, and Create passed a fresh (empty) host
// filestore whose pages are repopulated from the image.
// The Restore RPC has no fixed timeout because loading a large image may take
// arbitrarily long; it remains cancellable through ctx.
func (c *Client) Restore(ctx context.Context, args StartArgs, imagePath string) error {
	if args.ID == "" {
		return fmt.Errorf("container id is empty")
	}
	if imagePath == "" {
		return fmt.Errorf("checkpoint image path is empty for %s", args.ID)
	}
	if args.Network.Interface == nil {
		return fmt.Errorf("network interface is nil for %s", args.ID)
	}

	transition, state, err := c.beginStartTransition(ctx, args)
	if err != nil {
		return fmt.Errorf("load runsc state for %s: %w", args.ID, err)
	}
	defer transition.close()
	conn, err := transition.connect(ctx, state.Sandbox.ControlSocketPath)
	if err != nil {
		return fmt.Errorf("connect runsc control socket for %s: %w", args.ID, err)
	}
	defer conn.Close()
	if err := transition.authenticate(ctx, conn, state, args); err != nil {
		return err
	}
	tap, err := OpenTAP(*args.Network.Interface)
	if err != nil {
		return err
	}
	defer tap.Close()

	networkArgs, err := BuildNetworkArgs(args.Network, tap)
	if err != nil {
		return err
	}

	if err := callContextWithTimeout(ctx, conn, contMgrSetNetworkArgs, networkArgs, nil, 30*time.Second); err != nil {
		return fmt.Errorf("set network arguments for %s: %w", args.ID, err)
	}
	files, havePagesFile, err := openRestoreFiles(imagePath)
	if err != nil {
		return fmt.Errorf("open checkpoint files for %s: %w", args.ID, err)
	}
	defer closeFiles(files)

	opts := newRestoreOpts(args, files, havePagesFile)
	device, err := c.openPlatformDevice()
	if err != nil {
		return fmt.Errorf("open platform device for %s: %w", args.ID, err)
	}
	if device != nil {
		defer device.Close()
		opts.HaveDeviceFile = true
		opts.payload.Files = append(opts.payload.Files, device)
	}
	if err := transition.check(ctx); err != nil {
		return err
	}
	if err := callContext(ctx, conn, contMgrRestore, opts, nil); err != nil {
		return fmt.Errorf("restore root container %s: %w", args.ID, err)
	}
	if err := transition.markRunning(ctx); err != nil {
		return fmt.Errorf("mark runsc state running for %s: %w", args.ID, err)
	}
	return nil
}

// newRestoreOpts assembles the containerManager.Restore payload. SplitFSRestore
// is derived from the same StartArgs.FsRestoreImagePath that Create consumed:
// runsc requires the donated-files fact and the flag to agree, and the handler
// passes one StartArgs to both calls, so deriving here cannot drift.
func newRestoreOpts(args StartArgs, files []*os.File, havePagesFile bool) *restoreOpts {
	return &restoreOpts{
		payload:        filePayload{Files: files},
		HavePagesFile:  havePagesFile,
		SplitFSRestore: args.FsRestoreImagePath != "",
	}
}

func openRestoreFiles(imagePath string) ([]*os.File, bool, error) {
	image, err := os.Open(imagePath)
	if err != nil {
		return nil, false, fmt.Errorf("open checkpoint image: %w", err)
	}
	files := []*os.File{image}

	directory := filepath.Dir(imagePath)
	metadataPath := filepath.Join(directory, checkpointPagesMetadataName)
	pagesPath := filepath.Join(directory, checkpointPagesName)
	metadataExists, err := fileExists(metadataPath)
	if err != nil {
		closeFiles(files)
		return nil, false, err
	}
	pagesExist, err := fileExists(pagesPath)
	if err != nil {
		closeFiles(files)
		return nil, false, err
	}
	if metadataExists != pagesExist {
		closeFiles(files)
		return nil, false, fmt.Errorf(
			"incomplete checkpoint page files: %s exists=%t, %s exists=%t",
			checkpointPagesMetadataName,
			metadataExists,
			checkpointPagesName,
			pagesExist,
		)
	}
	if !metadataExists {
		return files, false, nil
	}

	for _, path := range []string{metadataPath, pagesPath} {
		file, err := os.Open(path)
		if err != nil {
			closeFiles(files)
			return nil, false, fmt.Errorf("open checkpoint page file %s: %w", path, err)
		}
		files = append(files, file)
	}
	return files, true, nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat checkpoint page file %s: %w", path, err)
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func (c *Client) openPlatformDevice() (*os.File, error) {
	if c.Options.Platform != "kvm" {
		return nil, nil
	}
	devicePath := c.Options.PlatformDevicePath
	if devicePath == "" {
		devicePath = "/dev/kvm"
	}
	device, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", devicePath, err)
	}
	return device, nil
}

func callContext(ctx context.Context, conn controlRPC, method string, arg, result any) error {
	done := make(chan error, 1)
	go func() {
		done <- conn.Call(method, arg, result)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if interruptible, ok := conn.(interruptibleControlRPC); ok {
			_ = interruptible.Interrupt()
		} else {
			_ = conn.Close()
		}
		return ctx.Err()
	}
}

func callContextWithTimeout(ctx context.Context, conn controlRPC, method string, arg, result any, timeout time.Duration) error {
	start := time.Now()
	logrus.Debugf("runsc urpc call %s started", method)
	if timeout <= 0 {
		err := callContext(ctx, conn, method, arg, result)
		logrus.Debugf("runsc urpc call %s finished, cost: %v, err: %v", method, time.Since(start), err)
		return err
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := callContext(callCtx, conn, method, arg, result)
	logrus.Debugf("runsc urpc call %s finished, cost: %v, err: %v", method, time.Since(start), err)
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("urpc method %q timed out after %s", method, timeout)
	}
	return err
}

func (c *Client) Wait(ctx context.Context, id string) (int, error) {
	state, err := c.loadState(id)
	if err != nil {
		return 0, fmt.Errorf("load runsc state for %s: %w", id, err)
	}
	conn, err := c.connectControl(state.Sandbox.ControlSocketPath)
	if err != nil {
		return 0, fmt.Errorf("connect runsc control socket for %s: %w", id, err)
	}
	defer conn.Close()

	var status uint32
	if err := callContext(ctx, conn, contMgrWait, &id, &status); err != nil {
		return 0, err
	}
	return waitStatusExitCode(unix.WaitStatus(status)), nil
}

func waitStatusExitCode(status unix.WaitStatus) int {
	if status.Exited() {
		return status.ExitStatus()
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return int(status)
}

// Delete delegates to runsc delete because that path is upstream's host-side
// cleanup boundary and calls Container.Destroy() internally.
func (c *Client) Delete(ctx context.Context, id string, force bool) error {
	args := append(c.globalArgs(), "delete")
	if force {
		args = append(args, "--force")
	}
	args = append(args, id)

	cmd := exec.CommandContext(ctx, c.Binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if force && isRunscNotFound(output) {
			return nil
		}
		return fmt.Errorf("runsc delete %s failed: %w: %s", id, err, string(output))
	}
	return nil
}

func isRunscNotFound(output []byte) bool {
	return bytes.Contains(output, []byte("does not exist")) || bytes.Contains(output, []byte("not found"))
}

func (c *Client) ListJSON(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(c.RootDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open original runtime inventory root: %w", err)
	}
	directory := os.NewFile(uintptr(fd), c.RootDir)
	defer directory.Close()
	var root, current unix.Stat_t
	if err := unix.Fstat(fd, &root); err != nil || root.Mode&0022 != 0 || root.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("runtime inventory root is not owned by this observer")
	}
	before, err := readRuntimeInventory(ctx, directory)
	if err != nil {
		return nil, err
	}
	args := c.globalArgs()
	if len(args) < 2 || args[0] != "--root" || args[1] != c.RootDir {
		return nil, errors.New("runtime inventory root argument is not canonical")
	}
	// Bind the CLI to the same held root as both snapshots. A path exchange
	// during exec must not redirect its observation to another directory.
	args[1] = "/proc/self/fd/3"
	args = append(args, "list", "--format", "json")
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	cmd.ExtraFiles = []*os.File{directory}
	var out boundedRuntimeOutput
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("runsc list failed: %w", err)
	}
	after, err := readRuntimeInventory(ctx, directory)
	if err != nil {
		return nil, err
	}
	if err := unix.Lstat(c.RootDir, &current); err != nil || current.Dev != root.Dev || current.Ino != root.Ino || current.Mode != root.Mode || current.Uid != root.Uid {
		return nil, errors.New("original runtime inventory root changed")
	}
	if err := verifyRuntimeInventory(before, after, out.Bytes()); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type containerState struct {
	ResourceGeneration   string              `json:"resourceGeneration"`
	ProcessBirthVersion  int                 `json:"processBirthVersion"`
	RuntimeDispatched    bool                `json:"runtimeDispatched"`
	GoferRequired        bool                `json:"goferRequired"`
	GoferPID             int                 `json:"goferPid"`
	GoferBirth           *nativeRuntimeBirth `json:"goferBirth"`
	ProcessLaunchVersion int                 `json:"processLaunchVersion"`
	GoferLaunchState     string              `json:"goferLaunchState"`
	SentryLaunchState    string              `json:"sentryLaunchState"`
	ID                   string              `json:"id"`
	Status               string              `json:"status"`
	BundleDir            string              `json:"bundleDir"`
	Spec                 struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"spec"`
	Sandbox struct {
		ResourceGeneration string              `json:"resourceGeneration"`
		ProcessBirth       *nativeRuntimeBirth `json:"processBirth"`
		ID                 string              `json:"id"`
		ControlSocketPath  string              `json:"controlSocketPath"`
		Pid                int                 `json:"pid"`
	} `json:"sandbox"`
}

func (c *Client) loadState(id string) (*containerState, error) {
	return c.loadBoundedNativeState(id)
}

func (c *Client) stateFilePath(id string) string {
	return filepath.Join(c.RootDir, fmt.Sprintf("%s_sandbox:%s.state", id, id))
}

func (c *Client) markStateRunning(id string) error {
	transition, err := c.beginStateTransition(context.Background(), id, false)
	if err != nil {
		return err
	}
	defer transition.close()
	return transition.markRunning(context.Background())
}
