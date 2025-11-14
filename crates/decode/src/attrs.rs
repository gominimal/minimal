use nickel_lang_core::{
    eval::cache::CacheImpl,
    program::Program,
    term::{IndexMap, RichTerm, Term},
};

use crate::{Error, eval_if_closure};

/// The value of an attribute.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AttrValue {
    String(String),
    Bool(bool),
    List(Vec<AttrValue>),
    Map(IndexMap<String, AttrValue>),
}

impl Default for AttrValue {
    fn default() -> Self {
        AttrValue::String(String::new())
    }
}

impl AttrValue {
    pub(crate) fn from_term(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        match rt.term.as_ref() {
            Term::Str(s) => Ok(Self::String(s.to_string())),
            Term::Bool(b) => Ok(Self::Bool(*b)),
            Term::Enum(a) => Ok(Self::String(a.into_label())),
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                let mut map = IndexMap::with_capacity(6);
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        map.insert(
                            ident_and_loc.label().to_string(),
                            AttrValue::from_term(field.value.as_ref().unwrap(), program)?,
                        );
                        Ok(())
                    })?;
                Ok(Self::Map(map))
            }
            Term::Array(e, _attrs) => Ok(Self::List(
                e.iter()
                    .map(|e| AttrValue::from_term(e, program))
                    .collect::<Result<Vec<_>, Error>>()?,
            )),
            _ => todo!(
                "error for unexpected attribute value type: {:?}",
                rt.term.as_ref()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::*;

    #[test]
    fn parse_str() {
        let (term, mut program, _origin) = Loader::new("\"a\"", &LoadOptions::for_test())
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("load failed");
            })
            .finish()
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("finish failed");
            });

        assert_eq!(
            AttrValue::from_term(&term, &mut program).unwrap(),
            AttrValue::String("a".to_string()),
        );
    }
    #[test]
    fn parse_bool() {
        let (term, mut program, _origin) = Loader::new("true", &LoadOptions::for_test())
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("load failed");
            })
            .finish()
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("finish failed");
            });

        assert_eq!(
            AttrValue::from_term(&term, &mut program).unwrap(),
            AttrValue::Bool(true),
        );
    }
    #[test]
    fn parse_enum() {
        let (term, mut program, _origin) = Loader::new("'Uwu", &LoadOptions::for_test())
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("load failed");
            })
            .finish()
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("finish failed");
            });

        assert_eq!(
            AttrValue::from_term(&term, &mut program).unwrap(),
            AttrValue::String("Uwu".to_string()),
        );
    }

    #[test]
    fn parse_record() {
        let (term, mut program, _origin) = Loader::new("{key = \"a\"}", &LoadOptions::for_test())
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("load failed");
            })
            .finish()
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("finish failed");
            });

        assert_eq!(
            AttrValue::from_term(&term, &mut program).unwrap(),
            AttrValue::Map(IndexMap::from_iter([(
                "key".to_string(),
                AttrValue::String("a".to_string())
            )])),
        );
    }

    #[test]
    fn parse_list() {
        let (term, mut program, _origin) = Loader::new("[\"a\", \"b\"]", &LoadOptions::for_test())
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("load failed");
            })
            .finish()
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("finish failed");
            });

        assert_eq!(
            AttrValue::from_term(&term, &mut program).unwrap(),
            AttrValue::List(vec![
                AttrValue::String("a".to_string()),
                AttrValue::String("b".to_string()),
            ]),
        );
    }
}
