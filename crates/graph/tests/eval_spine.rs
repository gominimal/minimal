use indoc::indoc;
use nickel_lang_core::term::Term;
use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};

use std::io;

const SRC: &'static str = indoc! {
    "
let {BuildSpec, ..} = import \"minimal.ncl\" in

                let rec b1 = {
                    name = \"build\" ++ \"1\",
                    inputs = [b1],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"build 2\",
                    inputs = [b1],
                    cmd = \"\",
                } | BuildSpec,
                in
                [b1]
	"
};

#[test]
#[ignore]
fn eval_spine() {
    let lib_path =
        std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("minimal-ncl");

    let mut program: Program<CacheImpl> = Program::new_from_source(
        io::Cursor::new(SRC.to_string()),
        "toplevel",
        std::io::stderr(),
        NullReporter {},
    )
    .unwrap();
    program.add_import_paths([&lib_path].iter());

    program
        .typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk)
        .unwrap();

    let tree = program.eval_record_spine().expect("eval failed");

    match tree.term.as_ref() {
        Term::Record(r) => {
            r.fields.iter().for_each(|(ident_and_loc, field)| {
                println!("field: {}", ident_and_loc);
                println!("\t{:#?}", field);
                // if ident_and_loc.label() == "name" {
                // 	println!("\nname eval: {}", program.eval());
                // }
            });
        }
        _ => {
            println!("\n\nnot a record: {:#?}\n\n", tree.term.as_ref());
        }
    }

    if let Term::Array(a, _) = tree.term.as_ref() {
        let c = if let Term::Closure(c) = a[0].term.as_ref() {
            c
        } else {
            unreachable!();
        };
        println!("first elem closure: {:?}", c);
        println!("thunk UID: {:?}", c.uid());

        let e = program
            .eval_closure(c.clone().into_closure())
            .expect("2nd eval");
        //println!("2nd eval: {:?}", e);

        match e.term.as_ref() {
            Term::Record(r) => {
                r.fields.iter().for_each(|(ident_and_loc, field)| {
                    //println!("2nd field: {}", ident_and_loc);
                    //println!("\t2nd {:#?}", field);
                    if ident_and_loc.label() == "inputs" {
                        //println!("\ninputs: {:?}", field);

                        if let Term::Closure(c2) = field.value.as_ref().unwrap().as_ref() {
                            println!("inputs value is closure");
                            let inputs = program
                                .eval_closure(c2.clone().into_closure())
                                .expect("inputs eval");

                            println!("2nd thunk UID: {:?}", c2.uid());
                            if let Term::Array(a, _) = inputs.as_ref() {
                                let c3 = if let Term::Closure(c3) = a[0].term.as_ref() {
                                    c3
                                } else {
                                    unreachable!();
                                };
                                println!("3rd thunk UID: {:?}", c3.uid());
                                println!("inner closure: {:?}", c3);
                                println!("closures equal 1/3: {}", c.eq(c3));
                                println!("closures equal 2/3: {}", c2.eq(c3));
                                println!("closures equal 1/2: {}", c.eq(c2));

                                let i3 = program
                                    .eval_closure(c3.clone().into_closure())
                                    .expect("i2 eval");

                                //println!("i2 eval: {:#?}", i2);
                                if let Term::Closure(c) = i3.as_ref() {
                                    println!("4th thunk UID: {:?}", c.uid());
                                    println!("inner inner closure: {:?}", c);
                                }
                            }
                        };
                    }
                });
            }
            _ => {
                println!("\n\nnot a record: {:#?}\n\n", e.term.as_ref());
            }
        }
    } else {
        unreachable!();
    }

    panic!("eval: {:?}", tree);
}
