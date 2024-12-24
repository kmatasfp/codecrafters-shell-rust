use core::str;
#[allow(unused_imports)]
use std::io::{self, Write};
use std::{
    env::{self, VarError},
    path::Path,
    process::{Command, Output, Stdio},
    string::FromUtf8Error,
};
use std::{fs, path::PathBuf};

fn main() -> Result<()> {
    let home = env::var("HOME")?;
    let path = env::var("PATH")?;

    loop {
        print!("$ ");
        io::stdout().flush()?;

        // Wait for user input
        let stdin = io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input)?;

        let trimmed_input = input.trim();
        let command: Vec<&str> = trimmed_input.split_whitespace().collect();

        match command.as_slice() {
            ["exit", "0"] => break,
            ["echo", rest @ ..] => println!("{}", rest.join(" ")),
            ["type", builtin @ "echo"]
            | ["type", builtin @ "exit"]
            | ["type", builtin @ "type"]
            | ["type", builtin @ "pwd"]
            | ["type", builtin @ "cd"] => {
                println!("{} is a shell builtin", builtin)
            }
            ["type", rest @ ..] => {
                if let Some(program) = rest.first() {
                    if let Some(executable) = find_executable_on_path(&path, program)? {
                        println!("{} is {}", program, executable.display())
                    } else {
                        eprintln!("{}: not found", program)
                    }
                }
            }
            ["pwd", ..] => {
                let curren_dir = env::current_dir()?;

                println!("{}", curren_dir.display())
            }
            ["cd", rest @ ..] => {
                if let Some(directory) = rest.first() {
                    let dir_path = if *directory == "~" {
                        Path::new(&home)
                    } else {
                        Path::new(directory)
                    };

                    if env::set_current_dir(dir_path).is_err() {
                        eprintln!("cd: {}: No such file or directory", directory);
                    }
                }
            }
            [c, rest @ ..] => {
                if let Some(program) = find_executable_on_path(&path, c)? {
                    let output = run_executable_with_args(&program, rest)?;

                    println!("{}", String::from_utf8(output.stdout)?.trim())
                } else {
                    eprintln!("{}: command not found", c)
                }
            }
            [] => eprintln!(": command not found"),
        }
    }
    Ok(())
}

fn find_executable_on_path(path: &str, executable: &str) -> Result<Option<PathBuf>> {
    Ok(path
        .split(":")
        .map(|dir| Path::new(dir).join(executable))
        .find(|path| fs::metadata(path).is_ok()))
}

fn run_executable_with_args(program: &PathBuf, args: &[&str]) -> io::Result<Output> {
    Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .output()
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    EncodingError(FromUtf8Error),
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

impl From<FromUtf8Error> for Error {
    fn from(value: FromUtf8Error) -> Self {
        Self::EncodingError(value)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}
