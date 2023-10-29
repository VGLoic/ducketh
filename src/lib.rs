pub use clap::{Parser, Subcommand};
use dirs::home_dir;
use std::path::PathBuf;

mod abis_manager;

extern crate dirs;

#[derive(Parser)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
pub struct Cli {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// try decoding some data
    Woot {
        /// the data to decode
        #[arg(name = "data", value_parser = is_hex_string)]
        data: String,
    },
    /// Manage the list of ABIs
    #[command(subcommand)]
    Abi(AbiCommands),
}

#[derive(Subcommand)]
enum AbiCommands {
    /// List all the ABIs
    List,
    /// Add an ABI
    Add {
        /// path to the ABI file or the ABIs directory
        #[arg(name = "path")]
        path: String,

        /// recursively look for ABIs to add in subfolders of input directory
        #[arg(short, long, name = "recursive")]
        recursive: bool,
    },
    /// Remove an ABI
    Remove {
        /// the names of the ABIs to remove
        #[arg(name = "names")]
        names: Vec<String>,

        /// remove all ABIs
        #[arg(short, long, name = "all")]
        all: bool,
    },
    /// Setup the local ABI directory
    Setup,
}

fn is_hex_string(val: &str) -> Result<String, String> {
    if !val.starts_with("0x") || !val.chars().skip(2).all(|c| c.is_digit(16)) {
        return Err("Value is not a valid hexadecimal string".to_string());
    }
    Ok(val.to_string())
}

impl Cli {
    pub fn run(&self) {
        match self.debug {
            0 => println!("Debug mode is off"),
            1 => println!("Debug mode is kind of on"),
            2 => println!("Debug mode is on"),
            _ => println!("Don't be crazy"),
        }

        let abis_dir_path = default_abis_dir_path().unwrap();

        let abis_manager = abis_manager::AbisManager::new(&abis_dir_path, self.debug);

        match &self.command {
        Some(Commands::Woot { data }) => {
            if self.debug > 0 {
                println!("Decoding data: {}", data);
            }
            let selector_to_search_for = if data.len() <= 10 { data } else { &data[0..10] };
            if self.debug > 0 {
                println!(
                    "Looking for selector starting with: {}",
                    selector_to_search_for
                );
            }
            match abis_manager.find_matching_abi_items(selector_to_search_for) {
                Ok(matching_items) => {
                    if matching_items.len() == 0 {
                        println!("Unable to decode the given data {}\nImprove the decoding by adding more ABI using `ducketh add <abi_path>`.\nMore results may be available on OpenChain: https://openchain.xyz/signatures?query={}", data, data);
                        return;
                    }
                    for (abi_name, abi_item) in matching_items {
                        match abi_item {
                            alloy_json_abi::AbiItem::Function(func) => {
                                println!("Found matching function in ABI {}, function name is: {}", abi_name, func.name);
                            }
                            alloy_json_abi::AbiItem::Event(ev) => {
                                println!("Found matching event in ABI {}, event name is: {}", abi_name, ev.name);
                            }
                            alloy_json_abi::AbiItem::Error(err) => {
                                println!("Found matching error in ABI {}, error name is: {}", abi_name, err.name);
                            }
                            other => {
                                println!(
                                    "Found matching item in ABI {}, full item is: {:?}",
                                    abi_name,
                                    other
                                );
                            }
                        }
                    }
                },
                Err(e) => {
                    println!("An unexpected error occurred during the decoding of the data. Original error is {}", e);
                }
            }
        },
        Some(Commands::Abi(abi_command)) => match abi_command {
            AbiCommands::Setup => {
                match abis_manager.setup_abi_dir() {
                    Ok(_) => {
                        println!("Successfully setup ducketh's ABI directory!");
                    }
                    Err(e) => {
                        println!("Unable to setup ABI directory. Original error is {}", e)
                    }
                }
            },
            AbiCommands::List => {
                match abis_manager.list_abis() {
                    Ok(abis ) => {
                        if abis.len() == 0 {
                            println!("No ABIs registered yet. Add ABI using `ducketh abi add <file or directory>`.");
                        } else {
                            println!(
                                "List of registered ABIs:\n{}",
                                abis
                                    .iter()
                                    .fold("".to_owned(), |acc, n| acc + n + "\n")
                            );
                        }
                    },
                    Err(e) => {
                        match e {
                            abis_manager::AbisManagerError::NotSetup => println!("The ABIs directory needs to be setup before listing the ABIs.\nOne can perform the setup using `ducketh abi setup` or by directly adding an ABI `ducketh abi add <file or folder path>"),
                            other => println!("{}", other)
                        }
                    }
                }
            },
            AbiCommands::Remove { names, all } => {
                if *all {
                    match abis_manager.list_abis() {
                        Ok(all_abis) => {
                            if all_abis.len() == 0 {
                                println!("No ABIs have been registered, nothing to delete");
                                return;
                            }
                            let abi_names = all_abis.iter()
                                .map(|s| s.as_str())
                                .collect();
                            match abis_manager.remove_abis(&abi_names) {
                                Ok(()) => println!("Sucessfully removed ABIs: {}", abi_names.join(", ")),
                                Err(e) => println!("{}", e)
                            }
                        },
                        Err(e) => println!("{}", e)
                    }
                } else {
                    if names.is_empty() {
                        println!("No names provided, command aborted");
                        return;
                    }
                    let abi_names = names.into_iter()
                        .map(|s| s.as_str())
                        .collect();
                    match abis_manager.remove_abis(&abi_names) {
                        Ok(()) => println!("Sucessfully removed ABIs: {}", names.join(", ")),
                        Err(e) => println!("{}", e)
                    }
                }
            },
            AbiCommands::Add { path, recursive} => {
                abis_manager.setup_abi_dir().unwrap();

                let input_abi_path = PathBuf::from(path);
                if !input_abi_path.try_exists().unwrap() {
                    println!("The path given as input {:?} does not exist, please provide a valid path.", input_abi_path);
                    return;
                }
                if input_abi_path.is_file() {
                    match abis_manager.add_abi(&input_abi_path) {
                        Ok(file_name) => {
                            println!("Successfully added ABI:\n{:?}", file_name);
                        }
                        Err(e) => {
                            match e {
                                abis_manager::AbisManagerError::AbiAlreayAdded(abi_name) => println!("An ABI with name {} is already added. Please change the name of the ABI if possible or remove the existing one.", abi_name),
                                abis_manager::AbisManagerError::InexistingInputPath(p) => println!("The path given in input {:?} does not seem to exist, are you sure you input a valid path? Path may be either absolute or relative.", p),
                                other => println!("{}", other)
                            }
                        }
                    };
                } else {
                    match abis_manager.add_abi_from_dir(&input_abi_path, recursive.to_owned()) {
                        Ok((added_abis, addition_errors)) => {
                            if added_abis.len() > 0 {
                                println!(
                                    "Successfully added {} ABIs: {}",
                                    added_abis.len(),
                                    added_abis.iter().fold("".to_owned(), |acc, n| acc + "- " + n + "\n")
                                )
                            } else {
                                println!("No new ABIs have been added. If this is unexpected, run the command with debug `-dd` activated to see the potential errors.");
                            }
                            if self.debug > 0 {
                                if addition_errors.len() > 0 {
                                    println!(
                                      "Got Errors while adding ABIs: {}",
                                      addition_errors.iter().fold("".to_owned(), |acc, (p, e)| acc + "- Path: " + p.to_str().unwrap() + " error: " + &e.to_string() +"\n")
                                    );
                                }
                            }
                        },
                        Err(e) => println!("{}", e)
                    }
                }
            },
        },
        None => {}
    }
        // Continued program logic goes here...
    }
}

fn default_abis_dir_path() -> Result<PathBuf, &'static str> {
    let mut path = home_dir().ok_or("Unable to get home directory")?;
    path.push(".ducketh");
    path.push("abis");
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }
}
