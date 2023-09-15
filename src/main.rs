use anyhow::Result;
use clap::{ App, Arg };
use walkdir::WalkDir;
use zip::ZipArchive;

// function to discover vulnerable files in the given directory
fn discover_vulnerable_files(root_path: &str) -> Result<()> {
    for entry in WalkDir::new(root_path)
        .follow_links(true)
        .same_file_system(true)
        .into_iter()
        .filter_map(|e| e.ok()) {
        if let Some(file_name) = entry.file_name().to_str() {
            // check if the file is a Logger.class file and contains "log4j" in its name
            if file_name == "Logger.class" && file_name.contains("log4j") {
                println!("extracted vulnerable file found: {}", entry.path().display());
            } else if file_name.ends_with(".jar") && !file_name.contains("2.17.1") {
                // check if the file is a JAR file and does not contain "2.17.1" in its name
                if let Ok(reader) = std::fs::File::open(entry.path()) {
                    if let Ok(mut zip) = ZipArchive::new(reader) {
                        // iterate through the contents of the JAR file
                        for i in 0..zip.len() {
                            if let Ok(file) = zip.by_index(i) {
                                let name = file.name();
                                // check if the JAR file contains a Logger.class file with "log4j" in its name
                                if name.ends_with("Logger.class") && name.contains("log4j") {
                                    println!("vulnerable file found: {}", entry.path().display());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    // print a message indicating the purpose of the program
    println!("discovering Log4Shell vulnerability [CVE-2021-44832]");

    // define command-line arguments and parse them
    let matches = App::new("log4j-scan")
        .version(env!("CARGO_PKG_VERSION"))
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("path").required(true).help("provide path to scan (e.g. C:\\)"))
        .get_matches();

    // get the provided path from command-line arguments
    let path = matches.value_of("path").unwrap();
    println!("starting discovery on {}\n", path);

    // call the function to discover vulnerable files in the specified directory
    discover_vulnerable_files(path)?;

    // print a message indicating the completion of the discovery process
    println!("\ndiscovery complete.");
    Ok(())
}
