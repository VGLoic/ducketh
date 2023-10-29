use std::path::PathBuf;

use alloy_json_abi::JsonAbi;

pub struct AbisManager<'a> {
    abis_dir_path: &'a PathBuf,
    debug: u8,
}

#[derive(Debug)]
pub enum AbisManagerError {
    NotSetup,
    InexistingInputPath(PathBuf),
    NotFoundAbi(PathBuf),
    AbiAlreayAdded(String),
    InvalidSelector(String),
    InvalidFileContent(serde_json::Error),
    UnexpectedSerializationOrDeserializationError(serde_json::Error),
    UnexpectedIOError(std::io::Error),
    UnexpectedError(String),
}

impl<'a> AbisManager<'a> {
    pub fn new(abis_dir_path: &'a PathBuf, debug: u8) -> Self {
        Self {
            abis_dir_path,
            debug,
        }
    }

    pub fn setup_abi_dir(&self) -> Result<(), AbisManagerError> {
        let abis_dir_path_exist = self.abis_dir_path.try_exists()?;

        if abis_dir_path_exist {
            if self.debug > 0 {
                println!("ABI directory has already been successfully setup");
            }
            return Ok(());
        }
        if self.debug > 0 {
            println!(
                "Starting the setup of the ABIs directory at: {:?}",
                self.abis_dir_path
            );
        }
        std::fs::create_dir_all(self.abis_dir_path)?;
        if self.debug > 0 {
            println!("Successfully created ABIs directory");
        }
        Ok(())
    }

    pub fn list_abis(&self) -> Result<Vec<String>, AbisManagerError> {
        let abis_dir_path_exist = self.abis_dir_path.try_exists()?;
        if !abis_dir_path_exist {
            return Err(AbisManagerError::NotSetup.into());
        }

        let mut abis = vec![];
        for entry in std::fs::read_dir(self.abis_dir_path)? {
            if let Some(name) = entry?.path().file_stem() {
                abis.push(name.to_str().unwrap().to_owned());
            }
        }

        Ok(abis)
    }

    pub fn remove_abis(&self, abi_names: &Vec<&str>) -> Result<(), AbisManagerError> {
        let abis_dir_path_exist = self.abis_dir_path.try_exists()?;
        if !abis_dir_path_exist {
            return Err(AbisManagerError::NotSetup);
        }

        for abi_name in abi_names {
            self.remove_abi(abi_name)?;
        }

        Ok(())
    }
    fn remove_abi(&self, abi_name: &str) -> Result<(), AbisManagerError> {
        let mut destination_abi_path = self.abis_dir_path.clone();
        let file_name_with_extension = PathBuf::from(abi_name).with_extension("json");
        destination_abi_path.push(file_name_with_extension);

        let destination_abi_exist = destination_abi_path.try_exists()?;
        if !destination_abi_exist {
            return Err(AbisManagerError::NotFoundAbi(destination_abi_path));
        }

        std::fs::remove_file(destination_abi_path)?;

        Ok(())
    }

    pub fn add_abi(&self, input_abi_path: &PathBuf) -> Result<String, AbisManagerError> {
        let abis_dir_path_exist = self.abis_dir_path.try_exists()?;
        if !abis_dir_path_exist {
            return Err(AbisManagerError::NotSetup);
        }
        if !input_abi_path.try_exists()? {
            return Err(AbisManagerError::InexistingInputPath(
                input_abi_path.to_owned(),
            ));
        }
        if !input_abi_path.is_file() {
            return Err(AbisManagerError::UnexpectedError("The path given as input does not lead to a file. The path must be the one targeting the ABI that should be added.".to_owned()));
        }

        let input_file_name = input_abi_path
            .file_stem()
            .ok_or(format!(
                "Unable to retrieve file stem of the file associated to input path {:?}",
                input_abi_path
            ))?
            .to_str()
            .unwrap();

        let mut destination_abi_path = self.abis_dir_path.clone();
        destination_abi_path.push(input_file_name);
        destination_abi_path = destination_abi_path.with_extension("json");

        let destination_abi_path_exist = destination_abi_path.try_exists()?;
        if destination_abi_path_exist {
            return Err(AbisManagerError::AbiAlreayAdded(input_file_name.to_owned()));
        }

        let file_contents = std::fs::read_to_string(&input_abi_path)?;

        if self.debug > 0 {
            println!("Trying to deserialise input file content into ABI items...");
        }

        let contract_object: alloy_json_abi::ContractObject = serde_json::from_str(&file_contents)
            .map_err(|e| AbisManagerError::InvalidFileContent(e))?;

        let content = serde_json::to_string(&contract_object.abi).map_err(|e| {
            format!(
                "Unable to serialize back the ABI into JSON format. Original error is {}",
                e
            )
        })?;

        std::fs::write(destination_abi_path, content)?;
        Ok(input_file_name.to_owned())
    }

    pub fn add_abi_from_dir(
        &self,
        input_abi_path: &PathBuf,
        recursive: bool,
    ) -> Result<(Vec<String>, Vec<(PathBuf, AbisManagerError)>), AbisManagerError> {
        let abis_dir_path_exist = self.abis_dir_path.try_exists()?;
        if !abis_dir_path_exist {
            return Err(AbisManagerError::NotSetup);
        }

        if !input_abi_path.is_dir() {
            return Err(AbisManagerError::UnexpectedError("The path given as input does not lead to a directory. The path must be the one targeting the directory containing the ABIs that should be added.".to_owned()));
        }

        let mut added_abis = vec![];
        let mut errors = vec![];

        for entry in std::fs::read_dir(input_abi_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if recursive {
                    match self.add_abi_from_dir(&path, true) {
                        Ok((sub_added_abis, sub_errors)) => {
                            added_abis.extend(sub_added_abis);
                            errors.extend(sub_errors);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    };
                }
            } else {
                match self.add_abi(&path) {
                    Ok(n) => added_abis.push(n),
                    Err(e) => errors.push((path, e)),
                };
            }
        }

        Ok((added_abis, errors))
    }

    pub fn find_matching_abi_items(
        &self,
        input_selector: &str,
    ) -> Result<Vec<(String, alloy_json_abi::AbiItem)>, AbisManagerError> {
        let abis_dir_path_exist = self.abis_dir_path.try_exists()?;
        if !abis_dir_path_exist {
            return Err(AbisManagerError::NotSetup);
        }
        if !input_selector.starts_with("0x") || input_selector.len() > 10 {
            return Err(AbisManagerError::InvalidSelector(input_selector.to_owned()));
        }
        let mut matching_items = vec![];
        for entry in std::fs::read_dir(self.abis_dir_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if self.debug > 0 {
                    println!("Skipping directory: {:?}", path);
                }
                continue;
            }
            if self.debug > 0 {
                println!("Checking file: {:?}", path);
            }
            let json = std::fs::read_to_string(&path)?;
            let abi: JsonAbi = serde_json::from_str(&json)?;
            for event_item in abi.events() {
                let selector =
                    alloy_primitives::FixedBytes::<4>::from_slice(&event_item.selector()[0..4])
                        .to_string();
                if self.debug > 1 {
                    println!(
                        "Considering Event item {} with selector: {}",
                        event_item.name, selector
                    );
                }
                if selector.starts_with(input_selector) {
                    if self.debug > 0 {
                        println!("Found matching event: {}", event_item.name);
                    }
                    matching_items.push((
                        path.file_stem().unwrap().to_str().unwrap().to_owned(),
                        event_item.clone().into(),
                    ));
                }
            }
            for error_item in abi.errors() {
                let selector =
                    alloy_primitives::FixedBytes::<4>::from_slice(&error_item.selector())
                        .to_string();
                if self.debug > 1 {
                    println!(
                        "Considering Error item {} with selector: {}",
                        error_item.name, selector
                    );
                }
                if selector.starts_with(input_selector) {
                    if self.debug > 0 {
                        println!("Found matching error: {}", error_item.name);
                    }
                    matching_items.push((
                        path.file_stem().unwrap().to_str().unwrap().to_owned(),
                        error_item.clone().into(),
                    ));
                }
            }
            for function_item in abi.functions() {
                let selector =
                    alloy_primitives::FixedBytes::<4>::from_slice(&function_item.selector())
                        .to_string();
                if self.debug > 1 {
                    println!(
                        "Considering Function item {} with selector: {}",
                        function_item.name, selector
                    );
                }
                if selector.starts_with(input_selector) {
                    if self.debug > 0 {
                        println!("Found matching function: {}", function_item.name);
                    }
                    matching_items.push((
                        path.file_stem().unwrap().to_str().unwrap().to_owned(),
                        function_item.clone().into(),
                    ));
                }
            }
        }
        Ok(matching_items)
    }
}

impl std::fmt::Display for AbisManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbisManagerError::NotSetup => {
                write!(f, "ABIs directory is not setup.")
            }
            AbisManagerError::InexistingInputPath(p) => {
                write!(f, "Input path {:?} does not exist", p)
            }
            AbisManagerError::AbiAlreayAdded(abi_name) => {
                write!(f, "An ABI with name {} is already added", abi_name)
            }
            AbisManagerError::InvalidSelector(input) => {
                write!(
                    f,
                    "Invalid selector {}, should start with '0x' and have at most 10 characters",
                    input
                )
            }
            AbisManagerError::NotFoundAbi(p) => {
                write!(f, "ABI not found, expected path is {:?}.", p)
            }
            AbisManagerError::InvalidFileContent(serde_err) => {
                write!(
                    f,
                    "Failed to recognize an ABI in input file. The file must either contains directly the ABI items or be a JSON of format {{ \"abi\": [...] }}. Original error is {}",
                    serde_err
                )
            }
            AbisManagerError::UnexpectedSerializationOrDeserializationError(original_error) => {
                write!(
                    f,
                    "Unexpected serialization/deserialization error, original error is {}",
                    original_error
                )
            }
            AbisManagerError::UnexpectedIOError(original_error) => {
                write!(
                    f,
                    "Unexpected IO error, original error is {}",
                    original_error
                )
            }
            AbisManagerError::UnexpectedError(message) => {
                write!(f, "Unexpected error with message {}", message)
            }
        }
    }
}

impl From<std::io::Error> for AbisManagerError {
    fn from(err: std::io::Error) -> Self {
        AbisManagerError::UnexpectedIOError(err)
    }
}
impl From<&str> for AbisManagerError {
    fn from(message: &str) -> Self {
        AbisManagerError::UnexpectedError(message.to_owned())
    }
}
impl From<String> for AbisManagerError {
    fn from(message: String) -> Self {
        AbisManagerError::UnexpectedError(message.to_owned())
    }
}
impl From<serde_json::Error> for AbisManagerError {
    fn from(err: serde_json::Error) -> Self {
        AbisManagerError::UnexpectedSerializationOrDeserializationError(err)
    }
}

impl std::error::Error for AbisManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AbisManagerError::NotSetup => None,
            AbisManagerError::AbiAlreayAdded(_) => None,
            AbisManagerError::InexistingInputPath(_) => None,
            AbisManagerError::NotFoundAbi(_) => None,
            AbisManagerError::InvalidFileContent(e) => Some(e),
            AbisManagerError::UnexpectedSerializationOrDeserializationError(e) => Some(e),
            AbisManagerError::UnexpectedIOError(e) => Some(e),
            AbisManagerError::UnexpectedError(_) => None,
            AbisManagerError::InvalidSelector(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn check_abi_manager_builder() {
        let path = PathBuf::from("./");
        let abi_manager = AbisManager::new(&path, 3);
        assert_eq!(abi_manager.abis_dir_path, &path);
        assert_eq!(abi_manager.debug, 3);
    }

    #[test]
    fn abi_dir_setup_should_create_abi_directory() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        assert!(abi_dir_path.exists());
    }

    #[test]
    fn abi_dir_setup_should_be_idempotent() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        assert!(abi_dir_path.exists());

        abi_manager.setup_abi_dir().unwrap();
        assert!(abi_dir_path.exists());
    }

    #[test]
    fn add_abi_should_fail_when_not_setup() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);

        assert_eq!(
            abi_manager
                .add_abi(&PathBuf::from("./test-data/abis/inner/rcl.json"))
                .unwrap_err()
                .to_string(),
            AbisManagerError::NotSetup.to_string()
        )
    }

    #[test]
    fn add_abi_should_support_abi_only_format() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/inner/rcl.json"))
            .unwrap();

        let mut expected_path = PathBuf::from(abi_dir_path);
        expected_path.push("rcl.json");
        assert!(expected_path.exists());
    }

    #[test]
    fn add_abi_should_support_full_contract_artefact_format() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/IERC20.json"))
            .unwrap();

        let mut expected_path = PathBuf::from(abi_dir_path);
        expected_path.push("IERC20.json");
        assert!(expected_path.exists());
    }

    #[test]
    fn add_abi_should_support_other_format_than_json() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/term-erc20-rewards.txt"))
            .unwrap();

        let mut expected_path = PathBuf::from(abi_dir_path);
        expected_path.push("term-erc20-rewards.json");
        assert!(expected_path.exists());
    }

    #[test]
    fn add_abi_should_fail_with_nonexisting_input_path() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        let non_existing_path = PathBuf::from("./test-data/shabada/shabadou/shabadouwa.shasha");
        let res = abi_manager.add_abi(&non_existing_path);
        assert_eq!(
            res.unwrap_err().to_string(),
            AbisManagerError::InexistingInputPath(non_existing_path).to_string()
        );
    }

    #[test]
    fn add_abi_should_fail_when_already_added() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/inner/rcl.json"))
            .unwrap();
        assert_eq!(
            abi_manager
                .add_abi(&PathBuf::from("./test-data/abis/inner/rcl.json"))
                .unwrap_err()
                .to_string(),
            AbisManagerError::AbiAlreayAdded("rcl".to_owned()).to_string()
        )
    }

    #[test]
    fn add_abi_should_fail_when_input_file_has_wrong_format() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        let file_contents = std::fs::read_to_string("./test-data/abis/random.txt").unwrap();
        let deserialization_res: Result<alloy_json_abi::ContractObject, serde_json::Error> =
            serde_json::from_str(&file_contents);
        let expected_deserialization_err = deserialization_res.unwrap_err();

        assert_eq!(
            abi_manager
                .add_abi(&PathBuf::from("./test-data/abis/random.txt"))
                .unwrap_err()
                .to_string(),
            AbisManagerError::InvalidFileContent(expected_deserialization_err).to_string()
        )
    }

    #[test]
    fn add_abi_from_dir_should_fail_when_not_setup() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);

        assert_eq!(
            abi_manager
                .add_abi_from_dir(&PathBuf::from("./test-data/abis"), false)
                .unwrap_err()
                .to_string(),
            AbisManagerError::NotSetup.to_string()
        );
    }

    #[test]
    fn add_abi_from_dir_without_recursion_should_add_all_possible_abis_from_the_dir_first_level() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        let (added_abis, addition_errors) = abi_manager
            .add_abi_from_dir(&PathBuf::from("./test-data/abis"), false)
            .unwrap();
        let filenames_to_check = vec![
            "IERC20",
            "rcl-rewards-manager",
            "term-erc20-rewards",
            "wrapped-matic",
        ];
        for added_abi in added_abis {
            assert!(
                filenames_to_check.contains(&added_abi.as_str()),
                "Expected {} to be contained in the expected filenames",
                added_abi
            );
        }
        assert_eq!(addition_errors.len(), 3);
        let expected_errors_paths = vec![
            // Already added
            PathBuf::from("./test-data/abis/IERC20.json"),
            // Wrong format
            PathBuf::from("./test-data/abis/random.txt"),
            // Already added
            PathBuf::from("./test-data/abis/term-erc20-rewards.json"),
        ];
        for (addition_error_path, _) in &addition_errors {
            assert!(
                expected_errors_paths.contains(addition_error_path),
                "Expected {:?} to be contained in the expected error path",
                addition_error_path
            );
        }
        for filename in filenames_to_check {
            let mut expected_path = PathBuf::from(&abi_dir_path);
            expected_path.push(filename);
            assert!(
                expected_path.with_extension("json").exists(),
                "{:?} does not exist as expected",
                expected_path
            );
        }
    }

    #[test]
    fn add_abi_from_dir_with_recursion_should_add_all_possible_abis_from_the_dir_all_levels() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        let (added_abis, addition_errors) = abi_manager
            .add_abi_from_dir(&PathBuf::from("./test-data/abis"), true)
            .unwrap();
        let filenames_to_check = vec![
            "IERC20",
            "rcl-rewards-manager",
            "rcl",
            "term-erc20-rewards",
            "wrapped-matic",
            "IERC20-only-abi",
        ];

        for added_abi in added_abis {
            assert!(
                filenames_to_check.contains(&added_abi.as_str()),
                "Expected {} to be contained in the expected filenames",
                added_abi
            );
        }
        assert_eq!(addition_errors.len(), 4);
        let expected_errors_paths = vec![
            // Already added
            PathBuf::from("./test-data/abis/inner/bla.txt"),
            // Already added
            PathBuf::from("./test-data/abis/IERC20.json"),
            // Wrong format
            PathBuf::from("./test-data/abis/random.txt"),
            // Already added
            PathBuf::from("./test-data/abis/term-erc20-rewards.json"),
        ];
        for (addition_error_path, _) in &addition_errors {
            assert!(
                expected_errors_paths.contains(addition_error_path),
                "Expected {:?} to be contained in the expected error path",
                addition_error_path
            );
        }

        for filename in filenames_to_check {
            let mut expected_path = PathBuf::from(&abi_dir_path);
            expected_path.push(filename);
            assert!(expected_path.with_extension("json").exists());
        }
    }

    #[test]
    fn list_abis_should_fail_when_not_setup() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);

        assert_eq!(
            abi_manager.list_abis().unwrap_err().to_string(),
            AbisManagerError::NotSetup.to_string()
        );
    }

    #[test]
    fn list_abis_should_give_empty_vec_when_no_abi() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        assert_eq!(abi_manager.list_abis().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn list_abis_should_give_the_abi_names() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/inner/rcl.json"))
            .unwrap();
        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/rcl-rewards-manager.json"))
            .unwrap();
        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/IERC20.json"))
            .unwrap();

        let expected_list = vec![
            "IERC20".to_owned(),
            "rcl".to_owned(),
            "rcl-rewards-manager".to_owned(),
        ];
        let mut result = abi_manager.list_abis().unwrap();
        result.sort();

        assert_eq!(result, expected_list);
    }

    #[test]
    fn remove_abis_should_fail_when_not_setup() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);

        assert_eq!(
            abi_manager
                .remove_abis(&vec!["test-abi"])
                .unwrap_err()
                .to_string(),
            AbisManagerError::NotSetup.to_string()
        );
    }

    #[test]
    fn remove_abis_should_fail_when_removing_not_added_abi() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        let mut expected_path = PathBuf::from(abi_manager.abis_dir_path);
        expected_path.push("test-abi.json");

        assert_eq!(
            abi_manager
                .remove_abis(&vec!["test-abi"])
                .unwrap_err()
                .to_string(),
            AbisManagerError::NotFoundAbi(expected_path).to_string()
        );
    }

    #[test]
    fn remove_abis_should_remove_found_abi_even_when_failing_for_the_next_one() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        abi_manager
            .add_abi_from_dir(&PathBuf::from("test-data"), true)
            .unwrap();

        let mut expected_error_path = PathBuf::from(abi_manager.abis_dir_path);
        expected_error_path.push("unknown.json");

        let mut expected_removed_path = PathBuf::from(abi_manager.abis_dir_path);
        expected_removed_path.push("wrapped_matic.json");

        assert_eq!(
            abi_manager
                .remove_abis(&vec!["unknown"])
                .unwrap_err()
                .to_string(),
            AbisManagerError::NotFoundAbi(expected_error_path).to_string()
        );

        assert!(!expected_removed_path.try_exists().unwrap());
    }

    #[test]
    fn find_matching_abi_items_should_fail_when_not_setup() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);

        assert_eq!(
            abi_manager
                .find_matching_abi_items("0x123")
                .unwrap_err()
                .to_string(),
            AbisManagerError::NotSetup.to_string()
        );
    }

    #[test]
    fn find_matching_abi_items_should_fail_invalid_input() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        let invalid_selector = "0x123456789abcdef";

        assert_eq!(
            abi_manager
                .find_matching_abi_items(invalid_selector)
                .unwrap_err()
                .to_string(),
            AbisManagerError::InvalidSelector(invalid_selector.to_owned()).to_string()
        );
    }

    #[test]
    fn find_matching_abi_items_should_detect_error_items() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        abi_manager
            .add_abi_from_dir(&PathBuf::from("./test-data"), true)
            .unwrap();

        let error_data = "0x6738fe4f";

        let results = abi_manager.find_matching_abi_items(error_data).unwrap();

        let expected_abi_name = "rcl".to_owned();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, expected_abi_name);
        assert_eq!(results[0].1.name().unwrap(), "RCL_BORROW_AMOUNT_TOO_LOW")
    }

    #[test]
    fn find_matching_abi_items_should_detect_event_items() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        abi_manager
            .add_abi_from_dir(&PathBuf::from("./test-data"), true)
            .unwrap();

        let approval_event_selector = "0x8c5be1e5";

        let results = abi_manager
            .find_matching_abi_items(approval_event_selector)
            .unwrap();

        let expected_abi_names = vec![
            "IERC20-only-abi",
            "IERC20",
            "wrapped-matic",
            "rcl",
            "rcl-rewards-manager",
        ];
        assert_eq!(results.len(), 5);
        for result in results {
            assert!(expected_abi_names.contains(&result.0.as_str()));
            assert_eq!(result.1.name().unwrap(), "Approval");
        }
    }

    #[test]
    fn find_matching_abi_items_should_detect_function_items() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        abi_manager
            .add_abi_from_dir(&PathBuf::from("./test-data"), true)
            .unwrap();

        let transfer_method_selector = "0xa9059cbb";

        let results = abi_manager
            .find_matching_abi_items(transfer_method_selector)
            .unwrap();

        let expected_abi_names = vec!["IERC20-only-abi", "IERC20", "wrapped-matic"];
        assert_eq!(results.len(), 3);
        for result in results {
            assert!(expected_abi_names.contains(&result.0.as_str()));
            assert_eq!(result.1.name().unwrap(), "transfer");
        }
    }

    #[test]
    fn find_matching_abi_items_should_detect_items_with_incomplete_input() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        abi_manager
            .add_abi_from_dir(&PathBuf::from("./test-data"), true)
            .unwrap();

        let approval_event_incomplete_selector = "0x8c5be";

        let results = abi_manager
            .find_matching_abi_items(approval_event_incomplete_selector)
            .unwrap();

        let expected_abi_names = vec![
            "IERC20-only-abi",
            "IERC20",
            "wrapped-matic",
            "rcl",
            "rcl-rewards-manager",
        ];
        assert_eq!(results.len(), 5);
        for result in results {
            assert!(expected_abi_names.contains(&result.0.as_str()));
            assert_eq!(result.1.name().unwrap(), "Approval");
        }
    }

    #[test]
    fn find_matching_abi_items_should_give_empty_if_not_found() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();

        abi_manager
            .add_abi_from_dir(&PathBuf::from("./test-data"), true)
            .unwrap();

        let unknown_selector = "0x123";

        let results = abi_manager
            .find_matching_abi_items(unknown_selector)
            .unwrap();

        assert_eq!(results.len(), 0);
    }

    #[test]
    fn remove_abis_should_remove_the_file_at_expected_destination() {
        let setup = Setup::init().unwrap();
        let abi_dir_path = setup.abi_dir_path();

        let abi_manager = AbisManager::new(&abi_dir_path, 3);
        abi_manager.setup_abi_dir().unwrap();
        abi_manager
            .add_abi(&PathBuf::from("./test-data/abis/IERC20.json"))
            .unwrap();

        let mut expected_path = PathBuf::from(&abi_dir_path);
        expected_path.push("IERC20.json");

        abi_manager.remove_abis(&vec!["IERC20"]).unwrap();
        assert!(!expected_path.exists());
    }

    struct Setup {
        test_dir: String,
    }

    impl Setup {
        fn init() -> Result<Self, std::io::Error> {
            let mut rng = rand::thread_rng();
            let n = rng.gen::<u32>();
            let test_dir = "./test-data/for-test-".to_owned() + &n.to_string() + "/";
            let setup = Setup { test_dir };

            std::fs::create_dir_all(&setup.test_dir)?;

            Ok(setup)
        }

        fn abi_dir_path(&self) -> PathBuf {
            let mut abi_dir = PathBuf::from(&self.test_dir);
            abi_dir.push(".ducketh");
            abi_dir.push("abis");
            abi_dir
        }
    }

    impl Drop for Setup {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.test_dir).unwrap();
        }
    }
}
