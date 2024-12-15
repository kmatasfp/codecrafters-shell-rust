#[allow(unused_imports)]
use std::io::{self, Write};

fn main() {
    loop {
        print!("$ ");
        io::stdout().flush().unwrap();

        // Wait for user input
        let stdin = io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();

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
                        println!("{}: not found", command)
                    }
                } else {
                    println!("{}: not found", i)
                }
            }
        }
    }
}
