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

fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_escape = false;

    for (i, c) in input.chars().enumerate() {
        match c {
            '\\' if !in_single_quote && !in_double_quote => in_escape = true,
            '\\' if in_double_quote => {
                if let Some(next_char) = input.chars().nth(i + 1) {
                    if next_char == '$'
                        || next_char == '\\'
                        || next_char == '"'
                        || next_char == '\n'
                    {
                        in_escape = true;
                    } else {
                        current_token.push(c);
                    }
                }
            }
            '\'' if in_single_quote => {
                in_single_quote = false;
            }
            '\'' if !in_double_quote => in_single_quote = true,
            '"' if in_escape => {
                current_token.push(c);
                in_escape = false;
            }
            '"' if in_double_quote => {
                in_double_quote = false;
            }
            '"' if !in_single_quote => in_double_quote = true,
            ' ' | '\t' if in_escape => {
                println!("escaped space");
                current_token.push(c);
                in_escape = false;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current_token.is_empty() {
                    tokens.push(current_token.clone());
                    current_token.clear();
                }
            }
            ' ' | '\t' => current_token.push(c),
            '\n' if in_escape => in_escape = false,
            _ => {
                current_token.push(c);
                in_escape = false;
            }
        }
    }

    // Don't forget to add the last word if there is one
    if !current_token.is_empty() {
        tokens.push(current_token);
    }

    tokens
}

fn parse_into_command(input: &str) -> ShellCommand {
    let tokens = tokenize(input);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_should_split_on_whitespace() {
        let result = tokenize("echo foo     bar asd");
        assert_eq!(result, vec!["echo", "foo", "bar", "asd"]);
    }

    #[test]
    fn tokenize_should_preserve_all_characters_in_single_quotes() {
        let test_cases = vec![
            (
                "echo 'foo                  bar'",
                vec!["echo", "foo                  bar"],
            ),
            (
                "cat '/tmp/file name' '/tmp/file name with spaces'",
                vec!["cat", "/tmp/file name", "/tmp/file name with spaces"],
            ),
            (r#"echo 'foo\     bar'"#, vec!["echo", r#"foo\     bar"#]),
            (r#"echo 'foo" bar'"#, vec!["echo", r#"foo" bar"#]),
            (r#"'exe with "quotes"'"#, vec![r#"exe with "quotes""#]),
        ];

        for (test_case, expected_result) in test_cases {
            assert_eq!(tokenize(test_case), expected_result);
        }
    }

    #[test]
    fn tokenize_should_preserve_most_characters_in_double_quotes_except_backslash_in_cases_followed_by_speciacial_character(
    ) {
        let test_cases = vec![
            (r#"echo "/""#, vec!["echo", "/"]),
            (r#"echo "foo"bar"#, vec!["echo", "foobar"]),
            (
                r#"echo "quz  hello"  "bar""#,
                vec!["echo", "quz  hello", "bar"],
            ),
            (
                r#"echo "bar"  "shell's"  "foo""#,
                vec!["echo", "bar", "shell's", "foo"],
            ),
            (
                r#"cat "/tmp/file name" "/tmp/'file name' with spaces""#,
                vec!["cat", "/tmp/file name", "/tmp/'file name' with spaces"],
            ),
            (
                r#"echo "before\   after""#,
                vec!["echo", r#"before\   after"#],
            ),
            (
                r#"cat "/tmp/file\\name" "/tmp/file\ name""#,
                vec!["cat", r#"/tmp/file\name"#, r#"/tmp/file\ name"#],
            ),
            (
                r#"echo "hello'script'\\n'world""#,
                vec!["echo", r#"hello'script'\n'world"#],
            ),
            (r#"echo "\""#, vec!["echo", r#"""#]),
            (
                r#"echo "hello\"insidequotes"script\""#,
                vec!["echo", r#"hello"insidequotesscript""#],
            ),
            (
                r#"cat "/tmp/"file\name"" "/tmp/"file name"""#,
                vec!["cat", "/tmp/filename", "/tmp/file", "name"],
            ),
            (
                r#""exe with 'single quotes'""#,
                vec!["exe with 'single quotes'"],
            ),
        ];

        for (test_case, expected_result) in test_cases {
            assert_eq!(tokenize(test_case), expected_result);
        }
    }

    #[test]
    fn tokenize_should_treat_unquoted_backslash_as_escape_character() {
        let test_cases = vec![
            (r#"echo \"#, vec!["echo"]),
            (r#"echo script\""#, vec!["echo", r#"script""#]),
            (
                r#"echo world\ \ \ \ \ \ script"#,
                vec!["echo", "world      script"],
            ),
            (r#"cat file\ name"#, vec!["cat", "file name"]),
        ];

        for (test_case, expected_result) in test_cases {
            assert_eq!(tokenize(test_case), expected_result);
        }
    }
}
