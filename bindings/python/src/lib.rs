use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Invoke the Rust crawler and return the parsed canonical ScrapeProof dictionary.
///
/// `options` accepts a Python dictionary. Keyword arguments are merged on top, so callers can use
/// either `scrape(url, {"formats": [...]})` or `scrape(url, formats=[...])`.
#[pyfunction]
#[pyo3(signature = (url, options = None, **kwargs))]
fn scrape(
    py: Python<'_>,
    url: String,
    options: Option<&Bound<'_, PyAny>>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let options = merged_options_json(py, options, kwargs)?;
    let canonical_json = basecrawl_ffi::scrape_json(&url, Some(&options))
        .map_err(|error| PyValueError::new_err(error.to_json_string().to_owned()))?;
    let json = PyModule::import(py, "json")?;
    Ok(json.getattr("loads")?.call1((canonical_json,))?.unbind())
}

fn merged_options_json(
    py: Python<'_>,
    options: Option<&Bound<'_, PyAny>>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<String> {
    let merged = PyDict::new(py);
    if let Some(options) = options {
        if !options.is_none() {
            let options = options.downcast::<PyDict>()?;
            copy_items(&merged, options)?;
        }
    }
    if let Some(kwargs) = kwargs {
        copy_items(&merged, kwargs)?;
    }
    PyModule::import(py, "json")?
        .getattr("dumps")?
        .call1((merged,))?
        .extract()
}

fn copy_items(target: &Bound<'_, PyDict>, source: &Bound<'_, PyDict>) -> PyResult<()> {
    for (key, value) in source.iter() {
        target.set_item(key, value)?;
    }
    Ok(())
}

#[pymodule]
fn _basecrawl(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(scrape, module)?)?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
