# StegNet

StegNet is a network steganography toolkit for covert communication over TCP, ICMP, DNS, and HTTP. It integrates encryption, message hiding, packet manipulation, and traffic analysis into a modular, scalable design using OOP principles.

**Usage**:

```console
$ stegnet [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.

**Commands**:

* `send`: Send a covert message over the specified...
* `receive`: Listen for and extract hidden messages.
* `analyze`: Run network traffic analysis to detect...

## `stegnet send`

Send a covert message over the specified protocol.

**Usage**:

```console
$ stegnet send [OPTIONS]
```

**Options**:

* `--mode TEXT`: Mode of communication: tcp, icmp, dns, http  [required]
* `--target TEXT`: Target IP or domain  [required]
* `--message TEXT`: Message to send covertly  [required]
* `--key TEXT`: Encryption key for securing the message  [required]
* `--help`: Show this message and exit.

## `stegnet receive`

Listen for and extract hidden messages.

**Usage**:

```console
$ stegnet receive [OPTIONS]
```

**Options**:

* `--mode TEXT`: Mode of communication: tcp, icmp, dns, http  [required]
* `--key TEXT`: Encryption key for decryption  [required]
* `--help`: Show this message and exit.

## `stegnet analyze`

Run network traffic analysis to detect covert channels.

**Usage**:

```console
$ stegnet analyze [OPTIONS]
```

**Options**:

* `--help`: Show this message and exit.
