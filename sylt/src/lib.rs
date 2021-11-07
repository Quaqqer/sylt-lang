/// Re-export of derived functions for [Args].
pub use gumdrop::Options;

use std::fmt::Debug;
use std::io::Write;
use std::path::{Path, PathBuf};
use sylt_common::error::Error;
use sylt_common::prog::{BytecodeProg, Prog};
use sylt_common::RustFunction;

pub mod formatter;

type ExternFunctionList = Vec<(String, RustFunction, String)>;

/// Generates the linking for the standard library, and lingon if it's active.
pub fn lib_bindings() -> ExternFunctionList {
    let mut lib = Vec::new();

    lib.append(&mut sylt_std::sylt::_sylt_link());

    #[cfg(feature = "lingon")]
    lib.append(&mut sylt_std::lingon::_sylt_link());

    #[cfg(feature = "network")]
    lib.append(&mut sylt_std::network::_sylt_link());

    lib
}

pub fn read_file(path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|_| Error::FileNotFound(path.to_path_buf()))
}

pub fn compile_with_reader_to_writer<R>(
    args: &Args,
    functions: ExternFunctionList,
    reader: R,
    write_file: Option<Box<dyn Write>>,
) -> Result<Prog, Vec<Error>>
where
    R: Fn(&Path) -> Result<String, Error>,
{
    let file = PathBuf::from(args.args.first().expect("No file to run"));
    let tree = sylt_parser::tree(&file, reader)?;
    if args.dump_tree {
        println!("{}", tree);
    }
    sylt_compiler::compile(!args.skip_typecheck, write_file, tree, &functions)
}

// TODO(ed): This name isn't true anymore - since it can compile
pub fn run_file_with_reader<R>(
    args: &Args,
    functions: ExternFunctionList,
    reader: R,
) -> Result<(), Vec<Error>>
where
    R: Fn(&Path) -> Result<String, Error>,
{
    match (&args.lua_run, &args.lua_compile) {
        (true, _) => {
            use std::process::{Command, Stdio};
            let mut child = Command::new("lua")
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to start lua - make sure it's installed correctly");
            let stdin = child.stdin.take().unwrap();
            match compile_with_reader_to_writer(args, functions, reader, Some(Box::new(stdin)))? {
                Prog::Lua => {
                    let output = child.wait_with_output().unwrap();
                    // NOTE(ed): Status is always 0 when piping to STDIN, atleast on my version of lua,
                    // so we check stderr - which is a bad idea.
                    if !output.stderr.is_empty() {
                        return Err(vec![Error::LuaError(
                            String::from_utf8(output.stderr).unwrap(),
                        )]);
                    }
                }
                Prog::Bytecode(_) => unreachable!(),
            };
        }

        (false, Some(s)) if s == "%" => {
            use std::io;
            // NOTE(ed): Lack of running
            compile_with_reader_to_writer(args, functions, reader, Some(Box::new(io::stdout())))?;
        }

        (false, Some(s)) => {
            use std::fs::File;
            let file =
                File::create(PathBuf::from(s)).expect(&format!("Failed to create file: {}", s));
            let writer: Option<Box<dyn Write>> = Some(Box::new(file));
            // NOTE(ed): Lack of running
            compile_with_reader_to_writer(args, functions, reader, writer)?;
        }

        (_, _) => {
            match compile_with_reader_to_writer(args, functions, reader, None)? {
                Prog::Bytecode(prog) => run(&prog, &args)?,
                Prog::Lua => unreachable!(),
            };
        }
    };
    Ok(())
}

/// Compiles, links and runs the given file. The supplied functions are callable
/// external functions.
pub fn run_file(args: &Args, functions: ExternFunctionList) -> Result<(), Vec<Error>> {
    run_file_with_reader(args, functions, read_file)
}

pub fn run(prog: &BytecodeProg, args: &Args) -> Result<(), Vec<Error>> {
    let mut vm = sylt_machine::VM::new();
    vm.print_bytecode = args.verbosity >= 1;
    vm.print_exec = args.verbosity >= 2;
    vm.init(&prog, &args.args);
    if let Err(e) = vm.run() {
        Err(vec![e])
    } else {
        Ok(())
    }
}

#[derive(Default, Debug, Options)]
pub struct Args {
    #[options(
        long = "skip-typecheck",
        no_short,
        help = "Does no type checking what so ever"
    )]
    pub skip_typecheck: bool,

    #[options(long = "dump-tree", no_short, help = "Writes the tree to stdout")]
    pub dump_tree: bool,

    #[options(short = "l", long = "lua", help = "Run using lua")]
    pub lua_run: bool,

    #[options(
        short = "c",
        long = "compile",
        help = "Compile to a lua file - % for stdout"
    )]
    pub lua_compile: Option<String>,

    #[options(short = "v", no_long, count, help = "Increase verbosity, up to max 2")]
    pub verbosity: u32,

    #[options(
        long = "format",
        help = "Run an auto formatter on the supplied file and print the result to stdout."
    )]
    pub format: bool,

    #[options(help = "Print this help")]
    pub help: bool,

    #[options(free)]
    pub args: Vec<String>,
}

impl Args {
    /// Wraps the function with the same name from [gumdrop] for convenience.
    pub fn parse_args_default_or_exit() -> Args {
        <Args as Options>::parse_args_default_or_exit()
    }
}

pub fn path_to_module(current_file: &Path, module: &str) -> PathBuf {
    let mut res = PathBuf::from(current_file);
    res.pop();
    res.push(format!("{}.sy", module));
    res
}

mod test {
    use super::Error;

    #[allow(dead_code)]
    pub fn count_errors(errs: &[Error]) -> (i32, i32, i32) {
        let mut syntax_errors = 0;
        let mut type_errors = 0;
        let mut runtime_errors = 0;
        for err in errs {
            match err {
                Error::NoFileGiven | Error::FileNotFound(_) | Error::IOError(_) => {
                    unreachable!("Unexpected error when testing file\n{}", err)
                }
                Error::GitConflictError { .. } | Error::SyntaxError { .. } => syntax_errors += 1,
                Error::TypeError { .. } | Error::CompileError { .. } => type_errors += 1,
                Error::RuntimeError { .. } | Error::LuaError(_) => runtime_errors += 1,
            }
        }
        (syntax_errors, type_errors, runtime_errors)
    }

    #[derive(Clone, Copy, Debug)]
    pub struct TestSettings {
        pub print: bool,
        pub syntax_errors: i32,
        pub type_errors: i32,
        pub runtime_errors: i32,
    }

    #[allow(dead_code)]
    pub fn parse_test_settings(contents: String) -> TestSettings {
        let mut print = true;
        let mut syntax_errors = 0;
        let mut type_errors = 0;
        let mut runtime_errors = 0;
        for line in contents.split("\n") {
            if line.starts_with("// error: ") {
                let line = line.strip_prefix("// error: ").unwrap().to_string();
                match line.chars().next() {
                    Some('@') => {
                        syntax_errors += 1;
                    }
                    Some('$') => {
                        type_errors += 1;
                    }
                    Some('#') => {
                        runtime_errors += 1;
                    }
                    x => {
                        panic!("Failed to parse test-file, unknown error prefix {:?}", x);
                    }
                }
            } else if line.starts_with("// flags: ") {
                for flag in line.split(" ").skip(2) {
                    match flag {
                        "no_print" => {
                            print = false;
                        }
                        _ => {
                            panic!("Unknown test flag '{}'", flag);
                        }
                    }
                }
            }
        }

        TestSettings { print, syntax_errors, type_errors, runtime_errors }
    }
}

#[macro_export]
macro_rules! assert_errs {
    ($result:expr, $expect:pat) => {
        let errs = $result.err().unwrap_or(Vec::new());

        #[allow(unused_imports)]
        use sylt_common::error::Error;
        #[allow(unused_imports)]
        use sylt_tokenizer::Span;
        if !matches!(errs.as_slice(), $expect) {
            eprintln!("===== Expected =====");
            eprint!("{}\n\n", stringify!($expect));
            assert!(false);
        }
    };
}

#[cfg(test)]
mod bytecode {

    #[macro_export]
    macro_rules! test_file_run {
        ($fn:ident, $path:literal) => {
            #[test]
            fn $fn() {
                use crate::test::{count_errors, parse_test_settings};
                #[allow(unused_imports)]
                use sylt_common::error::RuntimeError;
                #[allow(unused_imports)]
                use sylt_common::error::TypeError;
                #[allow(unused_imports)]
                use sylt_common::Type;

                let mut args = $crate::Args::default();
                let file = format!("../{}", $path);
                let contents = std::fs::read_to_string(file.clone()).unwrap();
                let settings = parse_test_settings(contents);
                args.args = vec![file];
                args.verbosity = if settings.print { 1 } else { 0 };

                let (syn, ty, run) = match $crate::run_file(&args, ::sylt_std::sylt::_sylt_link()) {
                    Err(res) => {
                        println!("===== Got Errors =====");
                        for err in &res {
                            print!("{}", err);
                        }
                        count_errors(&res)
                    }
                    Ok(_) => {
                        println!("===== Ran Correctly =====");
                        (0, 0, 0)
                    }
                };
                println!(" {} {} {}", syn, ty, run);
                println!("===== Expected =====");
                println!(
                    " {} {} {}",
                    settings.syntax_errors, settings.type_errors, settings.runtime_errors
                );
                assert_eq!(syn, settings.syntax_errors);
                assert_eq!(ty, settings.type_errors);
                assert_eq!(run, settings.runtime_errors);
            }
        };
    }

    sylt_macro::find_tests!(test_file_run);
}

#[cfg(test)]
mod lua {
    #[macro_export]
    macro_rules! test_file_lua {
        ($fn:ident, $path:literal) => {
            #[test]
            fn $fn() {
                use crate::test::{count_errors, parse_test_settings};
                use std::io::Write;
                use std::process::{Command, Stdio};
                #[allow(unused_imports)]
                use sylt_common::error::RuntimeError;
                #[allow(unused_imports)]
                use sylt_common::error::TypeError;
                #[allow(unused_imports)]
                use sylt_common::Type;

                let mut args = $crate::Args::default();
                let file = format!("../{}", $path);
                let contents = std::fs::read_to_string(file.clone()).unwrap();
                let settings = parse_test_settings(contents);
                args.args = vec![file];
                args.verbosity = if settings.print { 1 } else { 0 };

                let mut child = Command::new("lua")
                    .stdin(Stdio::piped())
                    .stderr(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect(concat!("Failed to start lua, testing:", $path));

                let stdin = child.stdin.take().unwrap();
                let writer: Option<Box<dyn Write>> = Some(Box::new(stdin));
                let res = $crate::compile_with_reader_to_writer(
                    &args,
                    ::sylt_std::sylt::_sylt_link(),
                    $crate::read_file,
                    writer,
                );

                let (syn, ty, _) = match res {
                    Err(res) => {
                        println!("===== Compile Errors =====");
                        for err in &res {
                            print!("{}", err);
                        }
                        count_errors(&res)
                    }
                    Ok(_) => {
                        println!("===== Compiled Correctly =====");
                        (0, 0, 0)
                    }
                };
                assert_eq!(syn, settings.syntax_errors);
                assert_eq!(ty, settings.type_errors);

                let output = child.wait_with_output().unwrap();
                // HACK(ed): Status is always 0 when piping to STDIN, atleast on my version of lua,
                // so we check stderr - which is a bad idea.
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let success = output.status.success() && stderr.is_empty();
                println!("Success: {}", success);
                if settings.runtime_errors != 0 {
                    assert!(
                        !success,
                        "Program ran to completion when it should crash\n:STDOUT:\n{}\n\n:STDERR:\n{}\n",
                        stdout,
                        stderr
                    );
                } else {
                    assert!(
                        success,
                        "Failed when it should succeed\n:STDOUT:\n{}\n\n:STDERR:\n{}\n",
                        stdout,
                        stderr
                    );
                }
            }
        };
    }

    sylt_macro::find_tests!(test_file_lua);
}
