use std::path::PathBuf;

use crate::{Error, Options, Runnable};
use graph::SubsetInput;
use lcache::PendingDir;

/// Constructs a subset, storing the resulting object in the cache.
pub struct SubsetBuild<'a> {
    pub subset: &'a SubsetInput,
    pub from_dir: Option<PathBuf>,
}

impl<'a> Runnable for SubsetBuild<'a> {
    type Result = PendingDir;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(&self.subset.from).unwrap();
        let build_hash = opts.graph.spec_hash(&self.subset.from);
        let subset_hash = opts.graph.subset_hash(self.subset);

        let build_dir = match &self.from_dir {
            None => opts.cache.read_dir(&build_hash)?.path().to_path_buf(),
            Some(dir) => dir.clone(),
        };
        let out = opts.cache.write_dir(&subset_hash).unwrap();

        // Collect the set of files which should be copied from the upstream build
        // to the subset.
        let mut files: Vec<_> = self
            .subset
            .outputs
            .iter()
            .map(|output_name| {
                common::match_files_for_glob(
                    &build_dir,
                    build.outputs.get(output_name).unwrap().glob(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap() // GlobError - shouldnt error if we got this far
            .into_iter()
            .flatten()
            .collect();
        files.sort();
        files.dedup();

        // Copy all matched files into the under-construction subset
        let out_base = out.path();
        for file in files.into_iter() {
            let trimmed = file.strip_prefix(&build_dir).unwrap();
            if let Some(parent) = trimmed.parent() {
                std::fs::create_dir_all(out_base.join(parent))?;
            }
            std::fs::copy(&file, out_base.join(trimmed))?;
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use graph::Graph;
    use indoc::indoc;
    use lcache::{Cache, EntryMeta, MetaInner};
    use smallvec::smallvec;
    use tempfile::TempDir;

    #[test]
    fn run() {
        let tmp_dir = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp_dir.path()).unwrap();

        // Make a fake upstream build.
        let dg = Graph::new()
            .ingest(
                Layer::new_for_test(
                    indoc! {
                        "
                let {BuildSpec, Source, OutputData, ..} = import \"minimal.ncl\" in
                {
                    name = \"fake build\",
                    build_deps = [],
                    cmd = \"\",
                    outputs = {
                    a = {glob = \"a\"} | OutputData,
                    b = {glob = \"b\"} | OutputData,
                    c = {glob = \"c\"} | OutputData,
                    },
                } | BuildSpec"
                    }
                    .to_string(),
                )
                .unwrap(),
            )
            .unwrap();
        // Write some files into a cache entry to fake existence of a completed build of it.
        let build_hash = dg.spec_hash(dg.by_name("fake build").unwrap());
        let build_files_dir = cache.write_dir(&build_hash).unwrap();
        for letter in &["a", "b", "c"] {
            std::fs::write(
                build_files_dir.path().join(letter),
                "some data".to_string().as_bytes(),
            )
            .unwrap();
        }
        build_files_dir
            .finalize(EntryMeta {
                inner: MetaInner::Spec("fake build".to_string()),
                ..Default::default()
            })
            .unwrap();

        // Make + run a subset with just outputs a and c.
        let mut sb = SubsetBuild {
            subset: &SubsetInput {
                from: *dg.by_name("fake build").unwrap(),
                outputs: smallvec!["a".to_string(), "c".to_string()],
            },
            from_dir: None,
        };
        let run_opts = &Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };
        let pending_dir = futures::executor::block_on(sb.run(run_opts)).unwrap();
        pending_dir
            .finalize(lcache::EntryMeta {
                inner: MetaInner::Subset(sb.subset.as_spec(&dg)),
                fetched: false,
                origin: Some(
                    dg.get(dg.by_name("fake build").unwrap())
                        .unwrap()
                        .from
                        .as_ref()
                        .clone(),
                ),
                ..Default::default()
            })
            .unwrap();

        // Check that only a and c were present.
        let out_dir = cache.read_dir(&dg.subset_hash(sb.subset)).unwrap();
        assert!(out_dir.path().join("a").exists());
        assert!(!out_dir.path().join("b").exists());
        assert!(out_dir.path().join("c").exists());
    }
}
