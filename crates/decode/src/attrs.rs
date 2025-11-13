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
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                todo!("rec: {:?}", r);
            }
            _ => todo!("error for unexpected attribute value type"),
        }
    }
}
