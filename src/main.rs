#[allow(unused_imports)]
use std::io::{self, Write};
use std::{
    env::{self, VarError},
    fs::ReadDir,
    path::Path,
};
use std::{fs, path::PathBuf};

fn main() -> Result<()> {
    loop {
        print!("$ ");
        io::stdout().flush()?;

        // Wait for user input
        let stdin = io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input)?;

        let trimmed_input = input.trim();

        let builtin_commands = ["echo", "exit", "type"];

        match trimmed_input {
            "exit 0" => break,
            i if trimmed_input.starts_with("echo") => println!("{}", &i[5..]),
            i => {
                if i.starts_with("type") {
                    let command = &i[5..];

                    if builtin_commands.contains(&command) {
                        println!("{} is a shell builtin", command)
                    } else {
                        let executables = executables_on_path()?;

                        let maybe_executable = executables
                            .into_iter()
                            .find(|executable| executable.starts_with(command));

                        if let Some(executable) = maybe_executable {
                            println!("{} is {}", command, executable.display())
                        } else {
                            println!("{}: not found", command)
                        }
                    }
                } else {
                    println!("{}: not found", i)
                }
            }
        }
    }
    Ok(())
}

fn executables_on_path() -> Result<Vec<PathBuf>> {
    let path_var = "PATH";

    let value = env::var(path_var)?;

    println!("PATH is {}", value);

    let dirs: Vec<&Path> = value.split(":").map(Path::new).collect();

    files_in_dirs(dirs).map_err(Error::Io)
}

fn files_in_dirs(dirs: Vec<&Path>) -> io::Result<Vec<PathBuf>> {
    dirs.iter()
        .map(|dir| fs::read_dir(dir).and_then(files_in_dir))
        .collect::<io::Result<Vec<_>>>()
        .map(|f| f.into_iter().flatten().collect())
}

fn files_in_dir(dir: ReadDir) -> io::Result<Vec<PathBuf>> {
    dir.map(|res| res.map(|e| e.path()))
        .collect::<io::Result<Vec<_>>>()
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    EnvVarError(VarError),
    Io(std::io::Error),
}

impl From<VarError> for Error {
    fn from(value: VarError) -> Self {
        Self::EnvVarError(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}
