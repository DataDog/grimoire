# Grimoire

<p align="center">
  <img src="./logo.png" alt="logo" width="300" />
</p>

Grimoire is a "REPL for detection engineering" that allows you to generate datasets of cloud audit logs for common attack techniques.

It currently supports AWS.

## How it works

First, Grimoire detonates an attack. It injects a unique user agent containing a UUID. Then, it polls CloudTrail to retrieve the audit logs caused by the detonation, and streams the resulting logs to an output file or to your terminal.

Supported detonators:
- [Stratus Red Team](https://github.com/DataDog/stratus-red-team)
- AWS CLI interactive shell

Supported logs backend:
- AWS CloudTrail (through the `LookupEvents` API)

## Installation

Requires Go 1.22+:

```bash
go install -v github.com/datadog/grimoire/cmd/grimoire@latest
```

## Getting started

Make sure you're [authenticated against AWS](https://docs.aws.amazon.com/signin/latest/userguide/command-line-sign-in.html) and have `AWS_REGION` set before running Grimoire:

```
export AWS_REGION=us-east-1
```

## Usage

(TODO stable CLI)

### Detonate an attack technique with [Stratus Red Team](https://github.com/DataDog/stratus-red-team):

```bash
$ grimoire run --o /tmp/logs --stratus-red-team-attack-technique aws.credential-access.ssm-retrieve-securestring-parameters
INFO[0000] Warming up Stratus Red Team attack technique aws.credential-access.ssm-retrieve-securestring-parameters
INFO[0000] Detonating Stratus Red Team attack technique aws.credential-access.ssm-retrieve-securestring-parameters
INFO[0003] Stratus Red Team attack technique successfully detonated
INFO[0003] Searching for CloudTrail logs...
INFO[0009] Found new CloudTrail event generated on 2024-07-30T20:58:43Z UTC: DescribeParameters
INFO[0009] Found new CloudTrail event generated on 2024-07-30T20:58:42Z UTC: DescribeParameters
```

In another terminal, you can tail `/tmp/logs` to see the logs as they're discovered in CloudTrail.

After 10 minutes (TODO), Grimoire will stop polling CloudTrail and exit. In the meantime, you can safely use Ctrl+C to exit.

Keep in mind that some Stratus Red Team attack techniques may take some time to complete. These are marked with a `Slow` badge on their documentation page, such as [Steal EC2 Instance Credentials](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/).

### Detonate an attack manually in an interactive shell

You can also detonate an attack manually in an interactive shell. In that case, Grimoire will spin up a new $SHELL for you, and inject the `AWS_EXECUTION_ENV` environment variable to ensure that the AWS CLI commands you run are captured.

```bash
$ grimoire shell -o /tmp/logs
INFO[0000] Grimoire will now run your shell and automatically inject a unique identifier to your HTTP user agent when using the AWS CLI
INFO[0000] You can use the AWS CLI as usual. Press Ctrl+D or type 'exit' to return to Grimoire.
INFO[0000] When you exit the shell, Grimoire will look for the CloudTrail logs that your commands have generated.
INFO[0000] Press ENTER to continue

# We're now in a "Grimoire-instrumented" shell
$ aws sts get-caller-identity
$ aws ec2 describe-instances
$ exit
INFO[0040] Welcome back to Grimoire!
INFO[0040] Searching for CloudTrail logs...
INFO[0090] Found event: DescribeInstances
INFO[0090] Found event: GetCallerIdentity
```

Use `-o -` to stream the logs to your terminal instead of a file.

## Development

Running locally:

```bash
alias grimoire='go run cmd/grimoire/*.go'
grimoire --help
```

Building binaries:

```bash
go build -o grimoire cmd/grimoire/*.go
```

## FAQ

### Why are CloudTrail logs slow to arrive?

Delivery of CloudTrail logs can take up to 15 minutes. If you don't see logs immediately, wait a few minutes and try again. In the majority of cases, though, it's expected that CloudTrail events are made available within 5 minutes.

For more information, see the [AWS documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html) and [How fast is CloudTrail today?](https://tracebit.com/blog/how-fast-is-cloudtrail-today-investigating-cloudtrail-delays-using-athena).

### Why isn't Grimoire part of Stratus Red Team?

We chose to separate Grimoire from Stratus Red Team because we feel that Grimoire should support other ways of detonating attack techniques.

That say, TODO integration