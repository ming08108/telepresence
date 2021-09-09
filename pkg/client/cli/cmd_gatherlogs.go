package cli

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/datawire/ambassador/pkg/kates"
	"github.com/telepresenceio/telepresence/v2/pkg/client/actions"
	"github.com/telepresenceio/telepresence/v2/pkg/filelocation"
)

func gatherLogsCommand() *cobra.Command {
	var args struct {
		outputFile     string
		daemons        string
		trafficAgents  string
		trafficManager bool
	}
	cmd := &cobra.Command{
		Use:   "gather-logs",
		Args:  cobra.NoArgs,
		Short: "Gather logs from traffic-manager, traffic-agent, user and root daemons, and export them into a zip file.",
		Long: `Gather logs from traffic-manager, traffic-agent, user and root daemons,
and export them into a zip file. Useful if you are opening a Github issue or asking
someone to help you debug Telepresence.`,
		Example: `Here are a few examples of how you can use this command:
# Get all logs and export to a given file
telepresence gather-logs -o /tmp/telepresence_logs.zip

# Get all logs for the daemons only
telepresence gather-logs --traffic-agents=False --traffic-manager=False

# Get all logs for pods that have "echo-easy" in the name, useful if you have multiple replicas
telepresence gather-logs --traffic-manager=False --traffic-agents=echo-easy

# Get all logs for a specific pod
telepresence gather-logs --traffic-manager=False --traffic-agents=echo-easy-6848967857-tw4jw     

# Get logs from everything except the daemons
telepresence gather-logs --daemons=False
`,

		RunE: func(cmd *cobra.Command, _ []string) error {
			return gatherLogs(cmd.Context(), cmd.OutOrStdout(), args.outputFile, args.daemons, args.trafficAgents, args.trafficManager)
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&args.outputFile, "output-file", "o", "", "The file you want to output the logs to.")
	flags.StringVar(&args.daemons, "daemons", "all", "The daemons you want logs from: all, root, user, False")
	flags.BoolVar(&args.trafficManager, "traffic-manager", true, "If you want to collect logs from the traffic-manager")
	flags.StringVar(&args.trafficAgents, "traffic-agents", "all", "Traffic-agents to collect logs from: all, name substring, False")
	return cmd
}

// gatherLogs gets the logs from the daemons (daemon + connector) and creates a zip
// file with their contents.
func gatherLogs(ctx context.Context, stdout io.Writer, outputFile, daemons, trafficAgents string, trafficManager bool) error {
	// Get the log directory and return the error if we can't get it
	logDir, err := filelocation.AppUserLogDir(ctx)
	if err != nil {
		return err
	}

	// If the user did not provide an outputFile, we'll use their current working directory
	if outputFile == "" {
		pwd, err := os.Getwd()
		if err != nil {
			return err
		}
		outputFile = fmt.Sprintf("%s/telepresence_logs.zip", pwd)
	} else if !strings.HasSuffix(outputFile, ".zip") {
		return errors.New("output file must end in .zip")
	}

	// Create a temporary directory where we will store the logs before we zip
	// them for export
	exportDir, err := os.MkdirTemp("", "logexp-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(exportDir); err != nil {
			fmt.Fprintf(stdout, "Failed to remove temp directory %s: %s", exportDir, err)
		}
	}()

	// First we add the daemonLogs to the export directory
	var daemonLogs []string
	switch daemons {
	case "all":
		daemonLogs = []string{"connector.log", "daemon.log"}
	case "root":
		daemonLogs = []string{"daemon.log"}
	case "user":
		daemonLogs = []string{"connector.log"}
	case "False":
	default:
		return errors.New("Options for --daemons are: all, root, or user")
	}

	for _, log := range daemonLogs {
		logFile := fmt.Sprintf("%s/%s", logDir, log)
		if _, err := os.Stat(logFile); err != nil {
			fmt.Fprintf(stdout, "log file does not exist: %s\n", logFile)
			continue
		}
		dstLogFile := fmt.Sprintf("%s/%s", exportDir, log)
		// For now we'll just copy the files, once we add anonymization of the
		// logs, we likely will want to change this so we can edit the files
		// before we write them
		if err := copyFiles(dstLogFile, logFile); err != nil {
			fmt.Fprintf(stdout, "failed exporting %s: %s\n", logFile, err)
			continue
		}
	}

	client, err := kates.NewClientFromConfigFlags(kubeConfig)
	if err != nil {
		return nil
	}

	// Get all the pods a user has permissions to get only if
	// they are trying to get logs for the manager and/or agents
	var pods []*kates.Pod
	if trafficManager || trafficAgents != "False" {
		pods, err = actions.GetAllPods(ctx, client)
		if err != nil {
			fmt.Fprintf(stdout, "failed getting all pods: %s\n", err)
		}
		if len(pods) == 0 {
			ambPods, err := actions.GetNamespacePods(ctx, client, "ambassador")
			if err != nil {
				fmt.Fprintf(stdout, "failed getting pods in ambassador namespace: %s\n", err)
			} else {
				pods = append(pods, ambPods...)
			}

			curNSPods, err := actions.GetNamespacePods(ctx, client, "default")
			if err != nil {
				fmt.Fprintf(stdout, "failed getting pods in current namespace: %s\n", err)
			} else {
				pods = append(pods, curNSPods...)
			}
		}
	}

	// PodContainer allows us to annotate the pod with extra information we care
	// about, such as which container to get logs from.
	type PodContainer struct {
		pod       *kates.Pod
		container string
	}
	// Now we parse the pods we care about
	foundTM, foundTA := false, false
	var zipPods []PodContainer
	for _, pod := range pods {
		if trafficManager && strings.Contains(pod.Name, "traffic-manager") {
			pc := PodContainer{pod: pod, container: "traffic-manager"}
			zipPods = append(zipPods, pc)
			foundTM = true
			continue
		}
		switch trafficAgents {
		case "all":
			for _, container := range pod.Spec.Containers {
				if container.Name == "traffic-agent" {
					pc := PodContainer{pod: pod, container: "traffic-agent"}
					zipPods = append(zipPods, pc)
					foundTA = true
				}
			}
		// do nothing since "False" means don't get logs from the agents
		case "False":
		// the default case assumes someone passed in the name of the pod,
		// so we try to get that pod
		default:
			if strings.Contains(pod.Name, trafficAgents) {
				for _, container := range pod.Spec.Containers {
					if container.Name == "traffic-agent" {
						pc := PodContainer{pod: pod, container: "traffic-agent"}
						zipPods = append(zipPods, pc)
						foundTA = true
					}
				}
			}
		}
	}

	// We want to let users know if they asked for logs from pods
	// that we could not find.
	if trafficManager && !foundTM {
		fmt.Fprintf(stdout, "did not find a traffic-manager\n")
	}
	if !foundTA {
		switch trafficAgents {
		case "all":
			fmt.Fprintf(stdout, "did not find any pods with traffic-agents installed")
		// they didn't ask for traffic agent logs so we don't need to print anything
		case "False":
		default:
			fmt.Fprintf(stdout, "did not find any pods matching substring: %s", trafficAgents)
		}
	}

	for _, pc := range zipPods {
		if err := addPodLogsZip(ctx, client, pc.pod, pc.container, exportDir); err != nil {
			fmt.Fprintf(stdout, "unable to get logs for pod %s: %s\n", pc.pod.Name, err)
		}
	}

	// Zip up all the files we've created in the zip directory and return that to the user
	var files []string
	dirEntries, err := os.ReadDir(exportDir)
	if err != nil {
		return err
	}
	for _, entry := range dirEntries {
		if !entry.IsDir() {
			files = append(files, fmt.Sprintf("%s/%s", exportDir, entry.Name()))
		}
	}

	if err := zipFiles(files, outputFile); err != nil {
		return err
	}
	return nil
}

func podLogsToFile(ctx context.Context, client *kates.Client, pod *kates.Pod, container, logFile string) error {
	// Create the destination file and prepare it for writing
	fd, err := os.Create(logFile)
	if err != nil {
		return err
	}
	defer fd.Close()
	fdWriter := bufio.NewWriter(fd)

	logEvents := make(chan kates.LogEvent)
	plo := &kates.PodLogOptions{
		Container: container,
	}
	if err := client.PodLogs(ctx, pod, plo, false, logEvents); err != nil {
		return err
	}

	// PodLogs adds the log events to a channel, but since we aren't doing a
	// a watch, we can reliably loop through all the events and add them to
	// the file and end once a closed event is observed
	for {
		event := <-logEvents
		if event.Closed {
			break
		}
		_, _ = fdWriter.WriteString(event.Output)
	}
	fdWriter.Flush()
	return nil
}

func addPodLogsZip(ctx context.Context, client *kates.Client, pod *kates.Pod, container, exportDir string) error {
	// Create the destination file and prepare it for writing
	logFile := fmt.Sprintf("%s/%s.log", exportDir, pod.Name)
	if err := podLogsToFile(ctx, client, pod, container, logFile); err != nil {
		return err
	}
	return nil
}

// copyFiles copies files from one location into another.
func copyFiles(dstFile, srcFile string) error {
	srcWriter, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer srcWriter.Close()

	dstWriter, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer srcWriter.Close()

	if _, err := io.Copy(dstWriter, srcWriter); err != nil {
		return err
	}
	return nil
}

// zipFiles creates a zip file with the contents of all the files passed in.
func zipFiles(files []string, zipFileName string) error {
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	addFileToZip := func(file string) error {
		fd, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fd.Close()

		// Get the basename of the file since that's all we want
		// to include in the zip
		info, err := fd.Stat()
		if err != nil {
			return err
		}
		baseName := info.Name()
		zfd, err := zipWriter.Create(baseName)
		if err != nil {
			return err
		}
		if _, err := io.Copy(zfd, fd); err != nil {
			return err
		}
		return nil
	}

	// Make a note of the files we fail to add to the zip so users know if the
	// zip is incomplete
	errMsg := ""
	for _, file := range files {
		if err := addFileToZip(file); err != nil {
			errMsg += fmt.Sprintf("failed adding %s to zip file: %s", file, err)
		}
	}
	if errMsg != "" {
		return errors.New(errMsg)
	}
	return nil
}
