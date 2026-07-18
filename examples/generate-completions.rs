use std::env;
use std::fs::{self, File};
use std::io;
use std::path::Path;

use clap::CommandFactory;
use clap_complete::{
    generate,
    shells::{Bash, Fish, Zsh},
    Generator,
};
use neutron::cli::Cli;

fn write_completion(generator: impl Generator, output: &Path) -> io::Result<()> {
    let mut command = Cli::command();
    let mut file = File::create(output)?;
    generate(generator, &mut command, "neutron", &mut file);
    Ok(())
}

fn main() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let output = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate-completions OUTPUT_DIRECTORY",
        )
    })?;
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate-completions OUTPUT_DIRECTORY",
        ));
    }

    let output = Path::new(&output);
    fs::create_dir_all(output)?;
    write_completion(Bash, &output.join("neutron.bash"))?;
    write_completion(Zsh, &output.join("_neutron"))?;
    write_completion(Fish, &output.join("neutron.fish"))
}
