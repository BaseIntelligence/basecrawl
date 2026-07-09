execute_process(
  COMMAND "${PROGRAM}" "https://example.com" "rawHtml"
  RESULT_VARIABLE scrape_result
  OUTPUT_VARIABLE proof
  ERROR_VARIABLE scrape_error
)

if(NOT scrape_result EQUAL 0)
  message(FATAL_ERROR "C SDK scrape failed: ${scrape_error}")
endif()

string(JSON version GET "${proof}" version)
if(NOT version EQUAL 1)
  message(FATAL_ERROR "expected ScrapeProof version 1, got ${version}")
endif()

string(JSON top_level_count LENGTH "${proof}")
if(NOT top_level_count EQUAL 8)
  message(FATAL_ERROR "expected exactly 8 top-level ScrapeProof keys, got ${top_level_count}")
endif()

foreach(key request tls response result egress attestation sdk_signature)
  string(JSON type TYPE "${proof}" "${key}")
  if(NOT type STREQUAL "OBJECT")
    message(FATAL_ERROR "ScrapeProof top-level key '${key}' must be an object")
  endif()
endforeach()
