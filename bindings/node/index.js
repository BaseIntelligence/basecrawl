"use strict";

const native = require("./basecrawl_sdk.node");

/**
 * Scrape a URL through the Rust core and return its canonical ScrapeProof object.
 *
 * @param {string} url
 * @param {import("./index").ScrapeOptions} [options]
 * @returns {import("./index").ScrapeProof}
 */
function scrape(url, options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("options must be an object");
  }
  return JSON.parse(native.scrapeJson(url, JSON.stringify(options)));
}

module.exports = {
  scrape,
  version: native.version,
};
