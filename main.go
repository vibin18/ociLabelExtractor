package main

import (
	"context"
	"encoding/json"
	"fmt"
	report "github.com/containers/common/pkg/report"
	retry "github.com/containers/common/pkg/retry"
	docker "github.com/containers/image/v5/docker"
	image "github.com/containers/image/v5/image"
	"strconv"

	//image2 "github.com/opencontainers/image-tools/image"
	// "github.com/opencontainers/go-digest"
	// "github.com/containers/image/manifest"
	alltransports "github.com/containers/image/v5/transports/alltransports"
	types "github.com/containers/image/v5/types"
	"github.com/containers/skopeo/cmd/skopeo/inspect"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"
)



type optionalBool struct {
	present bool
	value   bool
}

type optionalString struct {
	present bool
	value   string
}

type sharedImageOptions struct {
	authFilePath string // Path to a */containers/auth.json
}

type globalOptions struct {
	debug              bool          // Enable debug output
	tlsVerify          optionalBool  // Require HTTPS and verify certificates (for docker: and docker-daemon:)
	policyPath         string        // Path to a signature verification policy file
	insecurePolicy     bool          // Use an "allow everything" signature verification policy
	registriesDirPath  string        // Path to a "registries.d" registry configuration directory
	overrideArch       string        // Architecture to use for choosing images, instead of the runtime one
	overrideOS         string        // OS to use for choosing images, instead of the runtime one
	overrideVariant    string        // Architecture variant to use for choosing images, instead of the runtime one
	commandTimeout     time.Duration // Timeout for the command execution
	registriesConfPath string        // Path to the "registries.conf" file
	tmpDir             string        // Path to use for big temporary files
}

type dockerImageOptions struct {
	global         *globalOptions      // May be shared across several imageOptions instances.
	shared         *sharedImageOptions // May be shared across several imageOptions instances.
	authFilePath   optionalString      // Path to a */containers/auth.json (prefixed version to override shared image option).
	credsOption    optionalString      // username[:password] for accessing a registry
	registryToken  optionalString      // token to be used directly as a Bearer token when accessing the registry
	dockerCertPath string              // A directory using Docker-like *.{crt,cert,key} files for connecting to a registry or a daemon
	tlsVerify      optionalBool        // Require HTTPS and verify certificates (for docker: and docker-daemon:)
	noCreds        bool                // Access the registry anonymously
}

type imageOptions struct {
	dockerImageOptions
	sharedBlobDir    string // A directory to use for OCI blobs, shared across repositories
	dockerDaemonHost string // docker-daemon: host to connect to
}

type inspectOptions struct {
	global    *globalOptions
	image     *imageOptions
	retryOpts *retry.RetryOptions
	format    string
	raw       bool // Output the raw manifest instead of parsing information about the image
	config    bool // Output the raw config blob instead of parsing information about the image
}

func (opts *globalOptions) newSystemContext() *types.SystemContext {
	ctx := &types.SystemContext{
		RegistriesDirPath:        opts.registriesDirPath,
		ArchitectureChoice:       opts.overrideArch,
		OSChoice:                 opts.overrideOS,
		VariantChoice:            opts.overrideVariant,
		SystemRegistriesConfPath: opts.registriesConfPath,
		BigFilesTemporaryDir:     opts.tmpDir,
	}
	// DEPRECATED: We support this for backward compatibility, but override it if a per-image flag is provided.
	if opts.tlsVerify.present {
		ctx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(!opts.tlsVerify.value)
	}
	return ctx
}

func parseCreds(creds string) (string, string, error) {
	if creds == "" {
		return "", "", errors.New("credentials can't be empty")
	}
	up := strings.SplitN(creds, ":", 2)
	if len(up) == 1 {
		return up[0], "", nil
	}
	if up[0] == "" {
		return "", "", errors.New("username can't be empty")
	}
	return up[0], up[1], nil
}


func getDockerAuth(creds string) (*types.DockerAuthConfig, error) {
	username, password, err := parseCreds(creds)
	if err != nil {
		return nil, err
	}
	return &types.DockerAuthConfig{
		Username: username,
		Password: password,
	}, nil
}


func (opts *imageOptions) newSystemContext() (*types.SystemContext, error) {
	// *types.SystemContext instance from globalOptions
	//  imageOptions option overrides the instance if both are present.
	opts.global = &globalOptions{}
	ctx := opts.global.newSystemContext()
	ctx.DockerCertPath = opts.dockerCertPath
	ctx.OCISharedBlobDirPath = opts.sharedBlobDir
	ctx.AuthFilePath = opts.shared.authFilePath
	ctx.DockerDaemonHost = opts.dockerDaemonHost
	ctx.DockerDaemonCertPath = opts.dockerCertPath
	if opts.dockerImageOptions.authFilePath.present {
		ctx.AuthFilePath = opts.dockerImageOptions.authFilePath.value
	}
	if opts.tlsVerify.present {
		ctx.DockerDaemonInsecureSkipTLSVerify = !opts.tlsVerify.value
	}
	if opts.tlsVerify.present {
		ctx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(!opts.tlsVerify.value)
	}
	if opts.credsOption.present && opts.noCreds {
		return nil, errors.New("creds and no-creds cannot be specified at the same time")
	}
	if opts.credsOption.present {
		var err error
		ctx.DockerAuthConfig, err = getDockerAuth(opts.credsOption.value)
		if err != nil {
			return nil, err
		}
	}
	if opts.registryToken.present {
		ctx.DockerBearerRegistryToken = opts.registryToken.value
	}
	if opts.noCreds {
		ctx.DockerAuthConfig = &types.DockerAuthConfig{}
	}

	return ctx, nil
}

func parseImageSource(ctx context.Context, opts *imageOptions, name string) (types.ImageSource, error) {
	ref, err := alltransports.ParseImageName(name)
	if err != nil {
		return nil, err
	}
	sys, err := opts.newSystemContext()
	if err != nil {
		return nil, err
	}
	return ref.NewImageSource(ctx, sys)
}

// commandTimeoutContext returns a context.Context and a cancellation callback based on opts.
// The caller should usually "defer cancel()" immediately after calling this.
func (opts *globalOptions) commandTimeoutContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	var cancel context.CancelFunc = func() {}
	if opts.commandTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.commandTimeout)
	}
	return ctx, cancel
}


func reexecIfNecessaryForImages(inputImageNames ...string) error {
	return nil
}

//
//func inspectNormalize(row string) string {
//	r := strings.NewReplacer(
//		".ImageID", ".Image",
//	)
//	return r.Replace(row)
//}

func printTmpl(row string, data []interface{}) error {
	t, err := template.New("skopeo inspect").Parse(row)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 8, 2, 2, ' ', 0)
	return t.Execute(w, data)
}

func (opts *inspectOptions) run(args []string, stdout io.Writer) (retErr error) {
	var (
		rawManifest []byte
		src         types.ImageSource
		imgInspect  *types.ImageInspectInfo
		data        []interface{}
	)
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 1 {
		return errors.New("Exactly one argument expected")
	}
	if opts.raw && opts.format != "" {
		return errors.New("raw output does not support format option")
	}
	imageName := args[0]

	if err := reexecIfNecessaryForImages(imageName); err != nil {
		return err
	}

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}

	if err := retry.RetryIfNecessary(ctx, func() error {
		src, err = parseImageSource(ctx, opts.image, imageName)
		return err
	}, opts.retryOpts); err != nil {
		return errors.Wrapf(err, "Error parsing image name %q", imageName)
	}

	defer func() {
		if err := src.Close(); err != nil {
			retErr = errors.Wrapf(retErr, fmt.Sprintf("(could not close image: %v) ", err))
		}
	}()

	if err := retry.RetryIfNecessary(ctx, func() error {
		rawManifest, _, err = src.GetManifest(ctx, nil)
		return err
	}, opts.retryOpts); err != nil {
		return errors.Wrapf(err, "Error retrieving manifest for image")
	}

	if opts.raw && !opts.config {
		_, err := stdout.Write(rawManifest)
		if err != nil {
			return fmt.Errorf("Error writing manifest to standard output: %v", err)
		}

		return nil
	}


	img, err := image.FromUnparsedImage(ctx, sys, image.UnparsedInstance(src, nil))
	if err != nil {
		return errors.Wrapf(err, "Error parsing manifest for image")
	}

	if opts.config && opts.raw {
		var configBlob []byte
		if err := retry.RetryIfNecessary(ctx, func() error {
			configBlob, err = img.ConfigBlob(ctx)
			return err
		}, opts.retryOpts); err != nil {
			return errors.Wrapf(err, "Error reading configuration blob")
		}
		_, err = stdout.Write(configBlob)
		if err != nil {
			return errors.Wrapf(err, "Error writing configuration blob to standard output")
		}
		return nil
	} else if opts.config {
		var config *v1.Image
		if err := retry.RetryIfNecessary(ctx, func() error {
			config, err = img.OCIConfig(ctx)
			return err
		}, opts.retryOpts); err != nil {
			return errors.Wrapf(err, "Error reading OCI-formatted configuration data")
		}
		if report.IsJSON(opts.format) || opts.format == "" {
			var out []byte
			out, err = json.MarshalIndent(config, "", "    ")
			if err == nil {
				fmt.Fprintf(stdout, "%s\n", string(out))
			}
		} else {
			row := "{{range . }}" + report.NormalizeFormat(opts.format) + "{{end}}"
			data = append(data, config)
			err = printTmpl(row, data)
		}
		if err != nil {
			return errors.Wrapf(err, "Error writing OCI-formatted configuration data to standard output")
		}
		return nil
	}

	if err := retry.RetryIfNecessary(ctx, func() error {
		imgInspect, err = img.Inspect(ctx)
		return err
	}, opts.retryOpts); err != nil {
		return err
	}

	outputData := inspect.Output{
		Name: "", // Set below if DockerReference() is known
		Tag:  imgInspect.Tag,
		// Digest is set below.
		RepoTags:      []string{}, // Possibly overridden for docker.Transport.
		Created:       imgInspect.Created,
		DockerVersion: imgInspect.DockerVersion,
		Labels:        imgInspect.Labels,
		Architecture:  imgInspect.Architecture,
		Os:            imgInspect.Os,
		Layers:        imgInspect.Layers,
		Env:           imgInspect.Env,
	}
	// outputData.Digest, err = manifest.Digest(rawManifest)
	if err != nil {
		return errors.Wrapf(err, "Error computing manifest digest")
	}
	if dockerRef := img.Reference().DockerReference(); dockerRef != nil {
		outputData.Name = dockerRef.Name()
	}
	if img.Reference().Transport() == docker.Transport {
		sys, err := opts.image.newSystemContext()
		if err != nil {
			return err
		}
		outputData.RepoTags, err = docker.GetRepositoryTags(ctx, sys, img.Reference())
		if err != nil {
			// some registries may decide to block the "list all tags" endpoint
			// gracefully allow the inspect to continue in this case. Currently
			// the IBM Bluemix container registry has this restriction.
			// In addition, AWS ECR rejects it with 403 (Forbidden) if the "ecr:ListImages"
			// action is not allowed.
			if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "403") {
				return errors.Wrapf(err, "Error determining repository tags")
			}
			logrus.Warnf("Registry disallows tag list retrieval; skipping")
		}
	}
	if report.IsJSON(opts.format) || opts.format == "" {
		out, err := json.MarshalIndent(outputData, "", "    ")
		if err == nil {
			fmt.Fprintf(stdout, "%s\n", string(out))
		}
		return err
	}
	row := "{{range . }}" + report.NormalizeFormat(opts.format) + "{{end}}"
	data = append(data, outputData)
	return printTmpl(row, data)
}

func sharedImageFlags() (pflag.FlagSet, *sharedImageOptions) {
	opts := sharedImageOptions{}
	fs := pflag.FlagSet{}
	fs.StringVar(&opts.authFilePath, "authfile", os.Getenv("REGISTRY_AUTH_FILE"), "path of the authentication file. Default is ${XDG_RUNTIME_DIR}/containers/auth.json")
	return fs, &opts
}



// optionalBool is a cli.Generic == flag.Value implementation equivalent to
// the one underlying flag.Bool, except that it records whether the flag has been set.
// This is distinct from optionalBool to (pretend to) force callers to use
// optionalBoolFlag
type optionalBoolValue optionalBool

func optionalBoolFlag(fs *pflag.FlagSet, p *optionalBool, name, usage string) *pflag.Flag {
	flag := fs.VarPF(internalNewOptionalBoolValue(p), name, "", usage)
	flag.NoOptDefVal = "true"
	return flag
}

// WARNING: Do not directly use this method to define optionalBool flag.
// Caller should use optionalBoolFlag
func internalNewOptionalBoolValue(p *optionalBool) pflag.Value {
	p.present = false
	return (*optionalBoolValue)(p)
}

func (ob *optionalBoolValue) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	ob.value = v
	ob.present = true
	return nil
}

func (ob *optionalBoolValue) String() string {
	if !ob.present {
		return "" // This is, sadly, not round-trip safe: --flag is interpreted as --flag=true
	}
	return strconv.FormatBool(ob.value)
}

func (ob *optionalBoolValue) Type() string {
	return "bool"
}

func (ob *optionalBoolValue) IsBoolFlag() bool {
	return true
}


// optionalString is a cli.Generic == flag.Value implementation equivalent to
// the one underlying flag.String, except that it records whether the flag has been set.
// This is distinct from optionalString to (pretend to) force callers to use
// newoptionalString
type optionalStringValue optionalString

func newOptionalStringValue(p *optionalString) pflag.Value {
	p.present = false
	return (*optionalStringValue)(p)
}

func (ob *optionalStringValue) Set(s string) error {
	ob.value = s
	ob.present = true
	return nil
}

func (ob *optionalStringValue) String() string {
	if !ob.present {
		return "" // This is, sadly, not round-trip safe: --flag= is interpreted as {present:true, value:""}
	}
	return ob.value
}

func (ob *optionalStringValue) Type() string {
	return "string"
}

func dockerImageFlags(global *globalOptions, shared *sharedImageOptions, flagPrefix, credsOptionAlias string) (pflag.FlagSet, *imageOptions) {
	flags := imageOptions{
		dockerImageOptions: dockerImageOptions{
			global: global,
			shared: shared,
		},
	}

	fs := pflag.FlagSet{}
	if flagPrefix != "" {
		// the non-prefixed flag is handled by a shared flag.
		fs.Var(newOptionalStringValue(&flags.authFilePath), flagPrefix+"authfile", "path of the authentication file. Default is ${XDG_RUNTIME_DIR}/containers/auth.json")
	}
	fs.Var(newOptionalStringValue(&flags.credsOption), flagPrefix+"creds", "Use `USERNAME[:PASSWORD]` for accessing the registry")
	if credsOptionAlias != "" {
		// This is horribly ugly, but we need to support the old option forms of (skopeo copy) for compatibility.
		// Don't add any more cases like this.
		f := fs.VarPF(newOptionalStringValue(&flags.credsOption), credsOptionAlias, "", "Use `USERNAME[:PASSWORD]` for accessing the registry")
		f.Hidden = true
	}
	fs.Var(newOptionalStringValue(&flags.registryToken), flagPrefix+"registry-token", "Provide a Bearer token for accessing the registry")
	fs.StringVar(&flags.dockerCertPath, flagPrefix+"cert-dir", "", "use certificates at `PATH` (*.crt, *.cert, *.key) to connect to the registry or daemon")
	optionalBoolFlag(&fs, &flags.tlsVerify, flagPrefix+"tls-verify", "require HTTPS and verify certificates when talking to the container registry or daemon (defaults to true)")
	fs.BoolVar(&flags.noCreds, flagPrefix+"no-creds", false, "Access the registry anonymously")
	return fs, &flags
}

// imageFlags prepares a collection of CLI flags writing into imageOptions, and the managed imageOptions structure.
func imageFlags(global *globalOptions, shared *sharedImageOptions, flagPrefix, credsOptionAlias string) (pflag.FlagSet, *imageOptions) {
	dockerFlags, opts := dockerImageFlags(global, shared, flagPrefix, credsOptionAlias)

	fs := pflag.FlagSet{}
	fs.StringVar(&opts.sharedBlobDir, flagPrefix+"shared-blob-dir", "", "`DIRECTORY` to use to share blobs across OCI repositories")
	fs.StringVar(&opts.dockerDaemonHost, flagPrefix+"daemon-host", "", "use docker daemon host at `HOST` (docker-daemon: only)")
	fs.AddFlagSet(&dockerFlags)
	return fs, opts
}

type retryOptions struct {
	maxRetry int // The number of times to possibly retry
}

func retryFlags() (pflag.FlagSet, *retry.RetryOptions) {
	opts := retry.RetryOptions{}
	fs := pflag.FlagSet{}
	fs.IntVar(&opts.MaxRetry, "retry-times", 0, "the number of times to possibly retry")
	return fs, &opts
}




func main () {


	var (
		//rawManifest []byte
		src types.ImageSource
		//imgInspect  *types.ImageInspectInfo
		//data        []interface{}
	)
	ctx := context.Background()
	var opts *inspectOptions
	var global *globalOptions
	_, sharedOpts := sharedImageFlags()
	_, imageOpts := imageFlags(global, sharedOpts, "", "")
	_, retryOpts := retryFlags()
	opts = &inspectOptions{
		global:    global,
		image:     imageOpts,
		retryOpts: retryOpts,
	}
	//opts.global.commandTimeout = 0
	//opts.global.policyPath = ""
	//opts.global.insecurePolicy = false
	//opts.global.registriesDirPath = ""
	//opts.global.overrideArch = ""
	//opts.global.overrideOS = ""
	//opts.global.overrideVariant = ""
	//opts.global.registriesConfPath = ""
	//opts.global.tmpDir = ""
	//opts.format = ""
	imageName := "docker://izakmarais/grafana-reporter:latest"
	//ctx, cancel := opts.global.commandTimeoutContext()
	//defer cancel()

	sys, err := imageOpts.newSystemContext()
	if err != nil {
		logrus.Error(err)
	}
	if err := retry.RetryIfNecessary(ctx, func() error {
		fmt.Println("parseImageSource")
		src, err = parseImageSource(ctx, imageOpts, imageName)
		fmt.Println(src)
		fmt.Println(err)
		return err
	}, opts.retryOpts); err == nil {

		fmt.Println("FromUnparsedImage")
		img, err := image.FromUnparsedImage(ctx, sys, image.UnparsedInstance(src, nil))
		if err != nil {
			logrus.Error(err)
		}
		manifestData, _, _ := img.Manifest(ctx)
		fmt.Println(string(manifestData))
		fmt.Println(err)

	}
}