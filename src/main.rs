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

#[derive(Debug)]
enum ShellCommand {
    Exit(String),
    Echo(String),
    Type(String),
    Pwd,
    Cd(String),
    SysProgram(String, Vec<String>),
    Empty,
}

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
        let command = parse_into_command(trimmed_input);

        let built_in_commands = ["echo", "exit", "type", "pwd", "cd"];

        match command {
            ShellCommand::Exit(s) if s == "0" => break,
            ShellCommand::Exit(s) => eprintln!("Unknown exit code {}", s),
            ShellCommand::Echo(s) => println!("{}", s),
            ShellCommand::Type(c) if built_in_commands.contains(&c.as_str()) => {
                println!("{} is a shell builtin", c)
            }
            ShellCommand::Type(c) => {
                if !c.is_empty() {
                    if let Some(executable) = find_executable_on_path(&path, &c)? {
                        println!("{} is {}", c, executable.display())
                    } else {
                        eprintln!("{}: not found", c)
                    }
                }
            }
            ShellCommand::Pwd => {
                let curren_dir = env::current_dir()?;
                println!("{}", curren_dir.display())
            }
            ShellCommand::Cd(directory) => {
                if !directory.is_empty() {
                    let dir_path = if directory == "~" {
                        Path::new(&home)
                    } else {
                        Path::new(&directory)
                    };

                    if env::set_current_dir(dir_path).is_err() {
                        eprintln!("cd: {}: No such file or directory", directory);
                    }
                }
            }
            ShellCommand::SysProgram(c, args) => {
                println!("cmd: {} args: {:?}", c, args);
                if let Some(program) = find_executable_on_path(&path, &c)? {
                    let output = run_executable_with_args(&program, args.as_slice())?;

                    println!("{}", String::from_utf8(output.stdout)?.trim())
                } else {
                    eprintln!("{}: command not found", c)
                }
            }
            ShellCommand::Empty => continue,
        }
    }
    Ok(())
}

fn parse_into_command(input: &str) -> ShellCommand {
    let mut tokens = Vec::new();
    let mut in_single_quotes = false;
    let mut in_double_quotes = false;
    let mut non_quoted_backslash = false;
    let mut current_word = String::new();

    for c in input.chars() {
        match c {
            '"' | '\\' | '$' | '\n' if non_quoted_backslash && in_double_quotes => {
                non_quoted_backslash = false;
                current_word.push(c);
            }
            '"' | '\'' | '\\' | ' ' | '\t' if non_quoted_backslash => {
                non_quoted_backslash = false;
                current_word.push(c);
            }
            '"' => {
                in_double_quotes = !in_double_quotes;
                if in_single_quotes {
                    current_word.push(c);
                }
            }
            '\'' => {
                // Toggle the state of being inside quotes
                in_single_quotes = !in_single_quotes;
                if in_double_quotes {
                    current_word.push(c);
                }
            }
            '\\' if !in_single_quotes => {
                non_quoted_backslash = true;
            }
            ' ' | '\t' => {
                if !in_single_quotes && !in_double_quotes {
                    // Only consider whitespace as a separator if not inside quotes
                    if !current_word.is_empty() {
                        tokens.push(current_word.clone());
                        current_word.clear();
                    }
                } else {
                    // If inside quotes, treat the space as part of the word
                    current_word.push(c);
                }
            }
            _ => {
                if !in_single_quotes && !in_double_quotes {
                    non_quoted_backslash = false;
                }

                // Add characters to the current word
                current_word.push(c);
            }
        }
    }

    // Don't forget to add the last word if there is one
    if !current_word.is_empty() {
        tokens.push(current_word);
    }

    if let Some((head, tail)) = tokens.split_first() {
        match head.as_str() {
            "echo" => ShellCommand::Echo(tail.join(" ")),
            "exit" => ShellCommand::Exit(tail.join(" ")),
            "type" => ShellCommand::Type(tail.join(" ")),
            "pwd" => ShellCommand::Pwd,
            "cd" => ShellCommand::Cd(tail.join(" ")),
            c => ShellCommand::SysProgram(c.to_owned(), tail.to_vec()),
        }
    } else {
        ShellCommand::Empty
    }
}

fn find_executable_on_path(path: &str, executable: &str) -> Result<Option<PathBuf>> {
    Ok(path
        .split(":")
        .map(|dir| Path::new(dir).join(executable))
        .find(|path| fs::metadata(path).is_ok()))
}

fn run_executable_with_args(program: &PathBuf, args: &[String]) -> io::Result<Output> {
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
