avalokita
=========

a supervise(daemon tools) enhancement.

Usage: avalokita [options] command_path [command options]

Options:

  --restart-interval [seconds]

    Interval of command restart. Can not less than 1. Default is 1.

  --update-interval [seconds]

    Interval of update URL check. Can not less than 1. Default is 300.

  --update-url [URL]

    Automatically fetch the newest version executable of the command from URL
    and restart the command. This implies the argument --signature-url will
    get a default value [URL + ".sig"] if --signature-url was not specified.

    Thus, use --update-url without --signature-url is impossible.

  --signature-url [URL]

    Signature file for verify the executable which fetched from --update-url.
    The certificate is specify by --certificate. Default is the URL specified
    by --update-url and append ".sig".

    The signature file was in PKCS#7 encoding and PEM format.

  --certificate [filename]

    Certificate(in PEM format) used for verify the signature. If this argument
    absent, --signature-url and --update-url is ignored.

  --max-executable-size [size]

    The maximum executable size. If beyond the size, download will failed.
    Default is 10485760(10MiB).

  --file-lock [filename]

    Singletonize the daemon by a file lock. If the file lock is locked, the
    daemon will exit immediately. Default is "./daemon.pid".

  --stdout-file [filename]

    Redirect command's stdout to a file. Default is "./daemon.stdout.log".

  --stderr-file [filename]

    Redirect command's stderr to a file. Default is "./daemon.stderr.log".

Signals:

  SIGTERM

    kill command at first(first SIGTERM, then SIGKILL if command not exit in
    several seconds), then quit.

  SIGINT

    just kill command(SIGTERM, after several seconds then SIGKILL), then
    avalokita will run the command again.

