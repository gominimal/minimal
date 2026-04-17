use nickel_lang_core::error::Error;
use nickel_lang_core::files::Files;
use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};
use std::io;

/// Resolves string interpolations to given base values.
pub struct VarCtx {
    base: String,
}

impl VarCtx {
    pub fn eval_string(&self, s: &str) -> Result<String, Box<(Files, Error)>> {
        let mut source = String::with_capacity(self.base.len() + s.len() + 16);
        source.push_str(&self.base);
        source.push_str("\nm%\"");
        source.push_str(s);
        source.push_str("\"%");

        let mut program: Program<CacheImpl> = Program::new_from_sources(
            [(io::Cursor::new(source), "toplevel")],
            std::io::stderr(),
            NullReporter {},
        )
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
        let mut base = String::with_capacity(512);
        for (ident, value) in iter.into_iter() {
            value.write_nickel_binding(ident.as_ref(), &mut base);
        }
        Self { base }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_var_ctx() {
        let ctx = VarCtx::from_iter(std::iter::empty::<(&str, args::Arg)>());
        assert_eq!(ctx.base, "");
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
