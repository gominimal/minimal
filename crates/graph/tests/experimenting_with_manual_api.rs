use indoc::indoc;
use nickel_lang_core::cache::resolvers::SimpleResolver;
use nickel_lang_core::error::NullReporter;
use nickel_lang_core::eval::cache::lazy::CBNCache;
use nickel_lang_core::eval::cache::Cache;
use nickel_lang_core::eval::{env_add, env_add_record, Closure, Environment, VirtualMachine};
use nickel_lang_core::files::Files;
use nickel_lang_core::parser::grammar::TermParser;
use nickel_lang_core::parser::lexer::Lexer;
use nickel_lang_core::parser::ErrorTolerantParserCompat;
use nickel_lang_core::transform::import_resolution::strict::resolve_imports;

const BUILDER_CONTRACT: &str = indoc! {
    "{
        BuildSpec | doc \"A minimal build spec, defining inputs to the build as well as outputs which carry build artifacts downstream\" = {
            ty | [| 'Builder, 'Other |] = 'Builder,
            name
              | String,
            inputs
              | Array Builder,
        },
    }"
};

// fn mk_builder_term() -> nickel_lang_core::term::RichTerm {
//     let mut sources = CacheHub::new();
//     let builder_contract_nickel = sources.sources.add_string(
//         SourcePath::Generated("builder contract".into()),
//         BUILDER_CONTRACT.to_string(),
//     );
//     sources
//         .parse(builder_contract_nickel, InputFormat::Nickel)
//         .unwrap();

//     let mut vm: VirtualMachine<_, CBNCache> =
//         VirtualMachine::new(sources, std::io::stderr(), NullReporter {});
//     let program = vm.prepare_eval(builder_contract_nickel).unwrap();

//     vm.eval(program).unwrap()
// }

fn parse(s: &str) -> nickel_lang_core::term::RichTerm {
    let id = Files::new().add("<internal>", String::from(s));

    TermParser::new()
        .parse_strict_compat(id, Lexer::new(s))
        .unwrap()
}

fn mk_stdlib_env<EC: Cache>(eval_cache: &mut EC) -> Environment {
    let mut eval_env = Environment::new();

    let internals = parse(nickel_lang_core::stdlib::StdlibModule::Internals.content());
    env_add_record(
        eval_cache,
        &mut eval_env,
        Closure::atomic_closure(internals),
    )
    .unwrap();

    let stdlib = parse(nickel_lang_core::stdlib::StdlibModule::Std.content());
    env_add(
        eval_cache,
        &mut eval_env,
        nickel_lang_core::stdlib::StdlibModule::Std.name().into(),
        stdlib,
        Environment::new(),
    );

    eval_env
}

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct Builder {
    name: String,

    inputs: Vec<Builder>,
}

#[test]
#[ignore]
fn manual_machinery() {
    let top_level = parse(indoc! {
    "
        let {BuildSpec} = import \"minimal\" in
        {
            name = \"top-level \" ++ \"buildah\",
            inputs = []
        } | BuildSpec
        "
    });

    let mut resolver = SimpleResolver::new();
    resolver.add_source("minimal".to_string(), BUILDER_CONTRACT.to_string());
    let mut vm: VirtualMachine<_, CBNCache> =
        VirtualMachine::new(resolver, std::io::stderr(), NullReporter {});
    let initial_env = mk_stdlib_env(&mut vm.cache);
    let mut vm = vm.with_initial_env(initial_env);

    let top_level = resolve_imports(top_level, vm.import_resolver_mut())
        .map(|resolve_result| resolve_result.transformed_term)
        .map(|rt| nickel_lang_core::transform::transform(rt, None).unwrap())
        .unwrap();

    println!("top_level term: {:#?}\n", top_level);
    println!(
        "top_level eval: {:#?}\n",
        vm.eval_full_for_export(top_level.clone()).unwrap()
    );
    let deserialized_value =
        Builder::deserialize(vm.eval_full_for_export(top_level).unwrap()).unwrap();

    println!("deserialized builder: {:#?}\n", deserialized_value);

    panic!("crash da test 4 science");
}
