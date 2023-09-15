# Log4j Scanner

Discover Log4Shell vulnerability [CVE-2021-44832] in your files and directories.

## Description

This Rust-based Log4j Scanner is designed to help you identify and locate vulnerable files that may contain the Log4Shell vulnerability [CVE-2021-44832]. It scans files and directories to find instances of Logger.class files with "log4j" in their names or JAR files that do not contain "2.17.1" in their names.

## Features

- Scan files and directories for Log4j vulnerabilities.
- Detect Logger.class files with "log4j" in their names.
- Identify JAR files without "2.17.1" in their names.
- Display the path to vulnerable files when found.

## Usage

1. Clone this repository to your local machine.

```bash
git clone https://github.com/yourusername/log4j-scanner.git
cd log4j-scanner
```

2. Build the project using Cargo.

    ```bash
    cargo build --release
    ```

3. Run the Log4j Scanner with the desired path to scan.

    ```bash
    ./target/release/log4j-scanner /path/to/scan
    ```

    Replace /path/to/scan with the directory you want to scan for Log4j vulnerabilities.

## Output

The scanner will display messages indicating the progress and any discovered vulnerable files.

## Contributing

Contributions are welcome! If you find a bug or have suggestions for improvement, please create an issue or submit a pull request.
