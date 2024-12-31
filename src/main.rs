use core::str;
#[allow(unused_imports)]
use std::io::{self, Write};
use std::{
    borrow::Cow,
    env::{self, VarError},
    fs::{File, OpenOptions},
    ops::Deref,
    path::Path,
    process::{Output, Stdio},
    string::FromUtf8Error,
};
use std::{fs, path::PathBuf};

#[derive(Debug, PartialEq, Eq)]
enum ShellExec<'a> {
    PrintToStd(Command<'a>),
    RedirectedStdOut(Command<'a>, PathBuf),
    RedirectedStdErr(Command<'a>, PathBuf),
    RedirectedStdOutAppend(Command<'a>, PathBuf),
    RedirectedStdErrAppend(Command<'a>, PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Exit(String),
    Echo(String),
    Type(String),
    Pwd,
    Cd(String),
    SysProgram(Cow<'a, str>, Vec<Cow<'a, str>>),
    Empty,
    Invalid,
}

#[derive(Debug, PartialEq, Eq)]
enum CommandOutput {
    StdOut(String),
    StdErr(String),
    Wrapped(String, Output),
    Noop,
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

        let exec = parse(trimmed_input);

        match exec {
            ShellExec::PrintToStd(Command::Exit(s)) if s == "0" => break,
            ShellExec::RedirectedStdOut(Command::Exit(s), _) if s == "0" => break,
            ShellExec::PrintToStd(Command::Empty) => continue,
            ShellExec::RedirectedStdOut(Command::Empty, _) => continue,
            ShellExec::PrintToStd(c) => {
                let output = exec_command(c, &path, &home)?;

                match output {
                    CommandOutput::StdOut(s) => println!("{}", s),
                    CommandOutput::StdErr(s) => eprintln!("{}", s),
                    CommandOutput::Wrapped(c, output) => {
                        if !output.stdout.is_empty() {
                            println!("{}", String::from_utf8(output.stdout)?.trim())
                        }

                        if !output.stderr.is_empty() {
                            print_sys_program_failure_to_stderr(c, output.stderr)?
                        }
                    }

                    CommandOutput::Noop => continue,
                }
            }
            ShellExec::RedirectedStdOut(command, file) => {
                let file = File::create(file)?;
                let output = exec_command(command, &path, &home)?;

                handle_redirected_std_out(file, output)?
            }
            ShellExec::RedirectedStdOutAppend(command, file) => {
                let file = OpenOptions::new().append(true).create(true).open(file)?;
                let output = exec_command(command, &path, &home)?;

                handle_redirected_std_out(file, output)?
            }
            ShellExec::RedirectedStdErr(command, file) => {
                let file = File::create(file)?;
                let output = exec_command(command, &path, &home)?;

                handle_redirected_std_err(file, output)?
            }
            ShellExec::RedirectedStdErrAppend(command, file) => {
                let file = OpenOptions::new().append(true).create(true).open(file)?;
                let output = exec_command(command, &path, &home)?;

                handle_redirected_std_err(file, output)?
            }
        }
    }
    Ok(())
}

fn handle_redirected_std_out(mut file: File, output: CommandOutput) -> Result<()> {
    match output {
        CommandOutput::StdOut(s) => {
            writeln!(file, "{}", s)?;
            file.flush()?
        }
        CommandOutput::StdErr(s) => eprintln!("{}", s),
        CommandOutput::Wrapped(c, output) => {
            if !output.stdout.is_empty() {
                writeln!(file, "{}", String::from_utf8(output.stdout)?.trim())?;
                file.flush()?
            }

            if !output.stderr.is_empty() {
                print_sys_program_failure_to_stderr(c, output.stderr)?
            }
        }
        CommandOutput::Noop => (),
    }

    Ok(())
}

fn handle_redirected_std_err(mut file: File, output: CommandOutput) -> Result<()> {
    match output {
        CommandOutput::StdOut(s) => eprintln!("{}", s),
        CommandOutput::StdErr(s) => writeln!(file, "{}", s)?,
        CommandOutput::Wrapped(c, output) => {
            if !output.stdout.is_empty() {
                println!("{}", String::from_utf8(output.stdout)?.trim())
            }

            if !output.stderr.is_empty() {
                let raw_error_message = String::from_utf8(output.stderr)?;

                if let Some(split_point) = raw_error_message.find(&c) {
                    if let Some((_, right_half)) = raw_error_message.split_at_checked(split_point) {
                        let err_msg = &right_half[c.len()..];
                        writeln!(file, "{}{}", c, err_msg.trim())?;
                    } else {
                        writeln!(file, "{}", raw_error_message.trim())?;
                    }
                } else {
                    writeln!(file, "{}", raw_error_message.trim())?;
                }

                file.flush()?;
            }
        }
        CommandOutput::Noop => (),
    }

    Ok(())
}

fn print_sys_program_failure_to_stderr(program: String, stderr: Vec<u8>) -> Result<()> {
    let raw_error_message = String::from_utf8(stderr)?;

    if let Some(split_point) = raw_error_message.find(&program) {
        if let Some((_, right_half)) = raw_error_message.split_at_checked(split_point) {
            let err_msg = &right_half[program.len()..];
            eprintln!("{}{}", program, err_msg.trim());
        } else {
            eprintln!("{}", raw_error_message.trim());
        }
    } else {
        eprintln!("{}", raw_error_message.trim());
    }

    Ok(())
}

fn exec_command(command: Command, path: &str, home: &str) -> Result<CommandOutput> {
    let built_in_commands = ["echo", "exit", "type", "pwd", "cd"];

    match command {
        Command::Exit(s) if s == "0" => Ok(CommandOutput::Noop),
        Command::Exit(s) => Ok(CommandOutput::StdErr(format!("Unknown exit code {}", s))),
        Command::Echo(s) => Ok(CommandOutput::StdOut(s.to_string())),
        Command::Type(c) if built_in_commands.contains(&c.as_str()) => {
            Ok(CommandOutput::StdOut(format!("{} is a shell builtin", c)))
        }
        Command::Type(c) => {
            if !c.is_empty() {
                if let Some(executable) = find_executable_on_path(path, &c)? {
                    Ok(CommandOutput::StdOut(format!(
                        "{} is {}",
                        c,
                        executable.display()
                    )))
                } else {
                    Ok(CommandOutput::StdErr(format!("{}: not found", c)))
                }
            } else {
                Ok(CommandOutput::Noop)
            }
        }
        Command::Pwd => {
            let curren_dir = env::current_dir()?;
            Ok(CommandOutput::StdOut(format!("{}", curren_dir.display())))
        }
        Command::Cd(directory) => {
            if !directory.is_empty() {
                let dir_path = if directory == "~" {
                    Path::new(home)
                } else {
                    Path::new(&directory)
                };

                if env::set_current_dir(dir_path).is_err() {
                    Ok(CommandOutput::StdOut(format!(
                        "cd: {}: No such file or directory",
                        directory
                    )))
                } else {
                    Ok(CommandOutput::Noop)
                }
            } else {
                Ok(CommandOutput::Noop)
            }
        }
        Command::SysProgram(c, args) => {
            if let Some(program) = find_executable_on_path(path, &c)? {
                let output = run_executable_with_args(&program, args.as_slice())?;

                Ok(CommandOutput::Wrapped(c.to_string(), output))
            } else {
                Ok(CommandOutput::StdErr(format!("{}: command not found", c)))
            }
        }
        Command::Empty => Ok(CommandOutput::Noop),
        Command::Invalid => Err(Error::InvalidCommand),
    }
}

fn parse(input: &str) -> ShellExec {
    let tokens = tokenize(input);

    if let Some((split_point, redirection_type)) = tokens.iter().enumerate().find(|&(_, token)| {
        token == "1>"
            || token == ">"
            || token == "1>>"
            || token == ">>"
            || token == "2>"
            || token == "2>>"
    }) {
        if redirection_type == "1>" || redirection_type == ">" {
            if let Some((left_half, right_half)) = tokens.split_at_checked(split_point) {
                let command = &left_half[..left_half.len()];
                let file = &right_half[1..];

                let parsed_command = parse_command(command);

                ShellExec::RedirectedStdOut(parsed_command, PathBuf::from(file.join(" ")))
            } else {
                ShellExec::PrintToStd(Command::Invalid)
            }
        } else if redirection_type == "1>>" || redirection_type == ">>" {
            if let Some((left_half, right_half)) = tokens.split_at_checked(split_point) {
                let command = &left_half[..left_half.len()];
                let file = &right_half[1..];

                let parsed_command = parse_command(command);

                ShellExec::RedirectedStdOutAppend(parsed_command, PathBuf::from(file.join(" ")))
            } else {
                ShellExec::PrintToStd(Command::Invalid)
            }
        } else if redirection_type == "2>" {
            if let Some((left_half, right_half)) = tokens.split_at_checked(split_point) {
                let command = &left_half[..left_half.len()];
                let file = &right_half[1..];

                let parsed_command = parse_command(command);

                ShellExec::RedirectedStdErr(parsed_command, PathBuf::from(file.join(" ")))
            } else {
                ShellExec::PrintToStd(Command::Invalid)
            }
        } else if let Some((left_half, right_half)) = tokens.split_at_checked(split_point) {
            let command = &left_half[..left_half.len()];
            let file = &right_half[1..];

            let parsed_command = parse_command(command);

            ShellExec::RedirectedStdErrAppend(parsed_command, PathBuf::from(file.join(" ")))
        } else {
            ShellExec::PrintToStd(Command::Invalid)
        }
    } else {
        let parsed_command = parse_command(tokens.as_slice());

        ShellExec::PrintToStd(parsed_command)
    }
}

fn parse_command<'a>(command: &[Cow<'a, str>]) -> Command<'a> {
    if let Some((head, tail)) = command.split_first() {
        match head.deref() {
            "echo" => Command::Echo(tail.join(" ")),
            "exit" => Command::Exit(tail.join(" ")),
            "type" => Command::Type(tail.join(" ")),
            "pwd" => Command::Pwd,
            "cd" => Command::Cd(tail.join(" ")),
            _ => Command::SysProgram(head.clone(), tail.to_vec()),
        }
    } else {
        Command::Empty
    }
}

fn tokenize(input: &str) -> Vec<Cow<'_, str>> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_escape = false;
    let mut current_token_start = 0;
    let mut current_token_end = current_token_start;

    for (i, c) in input.chars().enumerate() {
        match c {
            '\\' if in_escape => {
                current_token.push(c);
                in_escape = false;
            }
            '\\' if !in_single_quote && !in_double_quote => {
                if current_token.is_empty() && current_token_end > current_token_start {
                    current_token.push_str(&input[current_token_start..current_token_end]);
                }
                in_escape = true
            }
            '\\' if in_double_quote => {
                if let Some(next_char) = input.chars().nth(i + 1) {
                    if next_char == '$'
                        || next_char == '\\'
                        || next_char == '"'
                        || next_char == '\n'
                    {
                        if current_token.is_empty() && current_token_end > current_token_start {
                            current_token.push_str(&input[current_token_start..current_token_end]);
                        }
                        in_escape = true;
                    } else {
                        current_token_end = i + c.len_utf8();
                    }
                }
            }
            '\'' if in_escape => {
                current_token.push(c);
                in_escape = false;
            }
            '\'' if in_single_quote => {
                in_single_quote = false;

                if current_token.is_empty() {
                    if let Some(prev_char) = input.chars().nth(i - 1) {
                        if prev_char == '\'' {
                            current_token_start = i + c.len_utf8();
                        } else if let Some(next_char) = input.chars().nth(i + 1) {
                            if next_char.is_ascii_whitespace() {
                                current_token_end = i;
                            } else if current_token.is_empty()
                                && current_token_end > current_token_start
                            {
                                current_token
                                    .push_str(&input[current_token_start..current_token_end]);
                            }
                        }
                    }
                }
            }
            '\'' if !in_double_quote => {
                in_single_quote = true;

                if i == 0 {
                    current_token_start = i + c.len_utf8();
                } else if let Some(prev_char) = input.chars().nth(i - 1) {
                    if !prev_char.is_ascii_whitespace() {
                        if current_token.is_empty() && i > current_token_start {
                            current_token.push_str(&input[current_token_start..i]);
                        }
                    } else {
                        current_token_start = i + c.len_utf8();
                    }
                }
            }
            '"' if in_escape => {
                current_token.push(c);
                in_escape = false;
            }
            '"' if in_double_quote => {
                in_double_quote = false;
                if current_token.is_empty() {
                    if let Some(prev_char) = input.chars().nth(i - 1) {
                        if prev_char == '"' {
                            current_token_start = i + c.len_utf8();
                        } else if let Some(next_char) = input.chars().nth(i + 1) {
                            if next_char.is_ascii_whitespace() {
                                current_token_end = i;
                            } else if current_token.is_empty()
                                && current_token_end > current_token_start
                            {
                                current_token
                                    .push_str(&input[current_token_start..current_token_end]);
                            }
                        }
                    }
                }
            }
            '"' if !in_single_quote => {
                in_double_quote = true;

                if i == 0 {
                    current_token_start = i + c.len_utf8();
                } else if let Some(prev_char) = input.chars().nth(i - 1) {
                    if !prev_char.is_ascii_whitespace() {
                        if current_token.is_empty() && i > current_token_start {
                            current_token.push_str(&input[current_token_start..i]);
                        }
                    } else {
                        current_token_start = i + c.len_utf8();
                    }
                }
            }
            ' ' | '\t' if in_escape => {
                current_token.push(c);
                in_escape = false;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current_token.is_empty() {
                    tokens.push(current_token.clone().into());
                    current_token.clear();
                } else if current_token_end > current_token_start {
                    tokens.push(Cow::Borrowed(
                        &input[current_token_start..current_token_end],
                    ));
                }
                current_token_start = i + c.len_utf8();
                current_token_end = current_token_start;
            }
            ' ' | '\t' => {
                if !current_token.is_empty() {
                    current_token.push(c)
                } else {
                    current_token_end = i + c.len_utf8();
                }
            }
            '\n' if in_escape => in_escape = false,
            _ => {
                in_escape = false;
                if !current_token.is_empty() {
                    current_token.push(c);
                } else {
                    current_token_end = i + c.len_utf8();
                }
            }
        }
    }

    if !current_token.is_empty() {
        tokens.push(current_token.into());
    } else if current_token_start < current_token_end {
        tokens.push(Cow::Borrowed(
            &input[current_token_start..current_token_end],
        ));
    }

    tokens
}

fn find_executable_on_path(path: &str, executable: &str) -> Result<Option<PathBuf>> {
    Ok(path
        .split(":")
        .map(|dir| Path::new(dir).join(executable))
        .find(|path| fs::metadata(path).is_ok()))
}

fn run_executable_with_args(program: &Path, args: &[Cow<'_, str>]) -> io::Result<Output> {
    std::process::Command::new(program)
        .args(args.iter().map(|arg| arg.as_ref()))
        .stdout(Stdio::piped())
        .output()
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    InvalidCommand,
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
        let test_cases = vec![
            ("echo foo     bar asd", vec!["echo", "foo", "bar", "asd"]),
            ("exit 0", vec!["exit", "0"]),
        ];

        for (test_case, expected_result) in test_cases {
            assert_eq!(tokenize(test_case), expected_result);
        }
    }

    #[test]
    fn tokenize_should_preserve_all_characters_in_single_quotes() {
        let test_cases = vec![
            ("echo foo''bar asd", vec!["echo", "foobar", "asd"]),
            ("echo foo'asd'bar asd", vec!["echo", "fooasdbar", "asd"]),
            ("echo ''foobar asd", vec!["echo", "foobar", "asd"]),
            ("echo foobar'' asd", vec!["echo", "foobar", "asd"]),
            ("echo 'foo'bar asd", vec!["echo", "foobar", "asd"]),
            (
                "echo 'foo                  bar' asd",
                vec!["echo", "foo                  bar", "asd"],
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
            (r#"echo foo""bar asd"#, vec!["echo", "foobar", "asd"]),
            (r#"echo foo"asd"bar asd"#, vec!["echo", "fooasdbar", "asd"]),
            (r#"echo ""foobar asd"#, vec!["echo", "foobar", "asd"]),
            (r#"echo foobar"" asd"#, vec!["echo", "foobar", "asd"]),
            (
                r#"cat "/tmp/"file\name"" "/tmp/"file name"""#,
                vec!["cat", "/tmp/filename", "/tmp/file", "name"],
            ),
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
                r#""exe with 'single quotes'""#,
                vec!["exe with 'single quotes'"],
            ),
            (
                r#"echo "mixed\"quote'example'\\""#,
                vec!["echo", r#"mixed"quote'example'\"#],
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
            (r#"echo \'"#, vec!["echo", r#"'"#]),
            (r#"echo script\""#, vec!["echo", r#"script""#]),
            (
                r#"echo world\ \ \ \ \ \ script"#,
                vec!["echo", "world      script"],
            ),
            (r#"cat file\ name"#, vec!["cat", "file name"]),
            (
                r#"echo \'\"test example\"\'"#,
                vec!["echo", r#"'"test"#, r#"example"'"#],
            ),
        ];

        for (test_case, expected_result) in test_cases {
            assert_eq!(tokenize(test_case), expected_result);
        }
    }

    #[test]
    fn parse_into_command_should_return_redirect_std_out_in_case_tokens_contain_redirection_operator(
    ) {
        let test_cases = vec![
            (
                "ls /tmp/baz > /tmp/foo/baz.md",
                ShellExec::RedirectedStdOut(
                    Command::SysProgram(
                        String::from("ls").into(),
                        vec![String::from("/tmp/baz").into()],
                    ),
                    PathBuf::from("/tmp/foo/baz.md"),
                ),
            ),
            (
                "ls /tmp/baz 1> /tmp/foo/baz.md",
                ShellExec::RedirectedStdOut(
                    Command::SysProgram(
                        String::from("ls").into(),
                        vec![String::from("/tmp/baz").into()],
                    ),
                    PathBuf::from("/tmp/foo/baz.md"),
                ),
            ),
        ];

        for (test_case, expected_result) in test_cases {
            assert_eq!(parse(test_case), expected_result);
        }
    }

    #[test]
    fn parse_into_command_should_return_redirect_std_err_in_case_tokens_contain_redirection_operator(
    ) {
        let test_cases = vec![(
            "ls /tmp/baz 2> /tmp/foo/baz.md",
            ShellExec::RedirectedStdErr(
                Command::SysProgram(
                    String::from("ls").into(),
                    vec![String::from("/tmp/baz").into()],
                ),
                PathBuf::from("/tmp/foo/baz.md"),
            ),
        )];

        for (test_case, expected_result) in test_cases {
            assert_eq!(parse(test_case), expected_result);
        }
    }

    #[test]
    fn parse_into_command_should_return_redirect_std_out_in_case_tokens_contain_appending_redirection_operator(
    ) {
        let test_cases = vec![
            (
                "ls /tmp/baz >> /tmp/foo/baz.md",
                ShellExec::RedirectedStdOutAppend(
                    Command::SysProgram(
                        String::from("ls").into(),
                        vec![String::from("/tmp/baz").into()],
                    ),
                    PathBuf::from("/tmp/foo/baz.md"),
                ),
            ),
            (
                "ls /tmp/baz 1>> /tmp/foo/baz.md",
                ShellExec::RedirectedStdOutAppend(
                    Command::SysProgram(
                        String::from("ls").into(),
                        vec![String::from("/tmp/baz").into()],
                    ),
                    PathBuf::from("/tmp/foo/baz.md"),
                ),
            ),
        ];

        for (test_case, expected_result) in test_cases {
            assert_eq!(parse(test_case), expected_result);
        }
    }

    #[test]
    fn parse_into_command_should_return_redirect_std_err_in_case_tokens_contain_appending_redirection_operator(
    ) {
        let test_cases = vec![(
            "ls /tmp/baz 2>> /tmp/foo/baz.md",
            ShellExec::RedirectedStdErrAppend(
                Command::SysProgram(
                    String::from("ls").into(),
                    vec![String::from("/tmp/baz").into()],
                ),
                PathBuf::from("/tmp/foo/baz.md"),
            ),
        )];

        for (test_case, expected_result) in test_cases {
            assert_eq!(parse(test_case), expected_result);
        }
    }
}
