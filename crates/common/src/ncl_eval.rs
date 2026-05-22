use nickel_lang_core::error::Error;
use nickel_lang_core::eval::value::NickelValue;
use nickel_lang_core::files::Files;
use nickel_lang_core::identifier::Ident;
use nickel_lang_core::{
    error::NullReporter,
    eval::cache::CacheImpl,
    program::{Program, ProgramBuilder},
};

/// Resolves string interpolations to given base values.
pub struct VarCtx {
    vars: Vec<(Ident, NickelValue)>,
}

impl VarCtx {
    pub fn eval_string(&self, s: &str) -> Result<String, Box<(Files, Error)>> {
        let mut source = String::with_capacity(s.len() + 6);
        source.push_str("m%\"");
        source.push_str(s);
        source.push_str("\"%");

        let mut program: Program<CacheImpl> = ProgramBuilder::new()
            .add_source_string(source, "toplevel")
            .extend_initial_env(self.vars.clone())
            .with_reporter(NullReporter {})
            .with_trace(std::io::stderr())
            .build()
            .unwrap();

        program
            .typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk)
            .map_err(|e| Box::new((program.files(), e)))?;
        program
            .compile()
            .map_err(|e| Box::new((program.files(), e)))?;

        let result = program
            .eval_full()
            .map_err(|e| Box::new((program.files(), e)))?;
        if let Some(s) = result.as_string() {
            Ok(s.to_string())
        } else {
            Ok("".to_string())
        }
    }
}

impl<S: AsRef<str>> FromIterator<(S, args::Arg)> for VarCtx {
    fn from_iter<T: IntoIterator<Item = (S, args::Arg)>>(iter: T) -> Self {
        let vars = iter
            .into_iter()
            .map(|(ident, value)| (Ident::new(ident.as_ref()), value.to_nickel()))
            .collect();
        Self { vars }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_var_ctx() {
        let ctx = VarCtx::from_iter(std::iter::empty::<(&str, args::Arg)>());
        assert!(ctx.vars.is_empty());
    }

    #[test]
    fn passthrough_basic_strings() {
        let ctx = VarCtx::from_iter(std::iter::empty::<(&str, args::Arg)>());
        assert_eq!(ctx.eval_string("hello").unwrap(), "hello");
        assert_eq!(ctx.eval_string("world").unwrap(), "world");
        assert_eq!(ctx.eval_string("hello world").unwrap(), "hello world");
        assert_eq!(ctx.eval_string("").unwrap(), "");
    }

    #[test]
    fn interpolation_with_vars_scalar() {
        use args::{Arg, ScalarArg};
        let ctx = VarCtx::from_iter(vec![
            ("name", Arg::Scalar(ScalarArg::String("world".to_string()))),
            ("count", Arg::Scalar(ScalarArg::Number(42.0))),
            ("flag", Arg::Scalar(ScalarArg::Boolean(true))),
        ]);
        assert_eq!(ctx.eval_string("hello %{name}").unwrap(), "hello world");
        assert_eq!(
            ctx.eval_string("n=%{std.string.from_number count}")
                .unwrap(),
            "n=42"
        );
        assert_eq!(
            ctx.eval_string("flag=%{std.string.from_bool flag}")
                .unwrap(),
            "flag=true"
        );
    }

    #[test]
    fn interpolation_with_vars_array() {
        use args::{Arg, ScalarArg};
        let ctx = VarCtx::from_iter(vec![
            (
                "a",
                Arg::Array(vec![
                    ScalarArg::String("hello".to_string()),
                    ScalarArg::String("world".to_string()),
                ]),
            ),
            (
                "b",
                Arg::Array(vec![ScalarArg::Boolean(true), ScalarArg::Boolean(false)]),
            ),
        ]);
        assert_eq!(
            ctx.eval_string("%{std.string.from_bool (std.array.at 1 b)}")
                .unwrap(),
            "false"
        );
    }
}
