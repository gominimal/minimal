use nickel_lang_core::error::Error;
use nickel_lang_core::files::Files;
use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};
use std::io;

/// Resolves string interpolations to given base values.
pub struct VarCtx {
    base: String,
}

impl VarCtx {
    pub fn new<S: AsRef<str>, I: IntoIterator<Item = (S, toml::Value)>>(values: I) -> Self {
        let mut base = String::with_capacity(512);
        for (ident, value) in values.into_iter() {
            base.push_str("let ");
            base.push_str(ident.as_ref());
            base.push_str(" = ");
            match value {
                toml::Value::Boolean(b) => {
                    if b {
                        base.push_str("true")
                    } else {
                        base.push_str("false")
                    }
                }
                toml::Value::Float(f) => base.push_str(&f.to_string()),
                toml::Value::String(s) => {
                    base.push('"');
                    base.push_str(&s);
                    base.push('"');
                }
                toml::Value::Integer(i) => base.push_str(&i.to_string()),
                // TODO: This is shit and also only works one level. Make a trait
                // for serializing to nickel which is recursive and use that?
                toml::Value::Array(v) => v.into_iter().for_each(|e| match e {
                    toml::Value::String(s) => {
                        base.push('"');
                        base.push_str(&s);
                        base.push('"');
                    }
                    toml::Value::Boolean(b) => {
                        if b {
                            base.push_str("true")
                        } else {
                            base.push_str("false")
                        }
                    }
                    toml::Value::Float(f) => base.push_str(&f.to_string()),
                    _ => todo!(),
                }),
                _ => todo!(),
            }

            base.push_str(" in\n");
        }

        Self { base }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_var_ctx() {
        let ctx = VarCtx::new(std::iter::empty::<(&str, toml::Value)>());
        assert_eq!(ctx.base, "");
    }

    #[test]
    fn passthrough_basic_strings() {
        let ctx = VarCtx::new(std::iter::empty::<(&str, toml::Value)>());
        assert_eq!(ctx.eval_string("hello").unwrap(), "hello");
        assert_eq!(ctx.eval_string("world").unwrap(), "world");
        assert_eq!(ctx.eval_string("hello world").unwrap(), "hello world");
        assert_eq!(ctx.eval_string("").unwrap(), "");
    }

    #[test]
    fn interpolation_with_vars() {
        let ctx = VarCtx::new(vec![
            ("name", toml::Value::String("world".to_string())),
            ("count", toml::Value::Integer(42)),
            ("flag", toml::Value::Boolean(true)),
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
}
