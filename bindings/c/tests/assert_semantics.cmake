function(assert_c_error label url options expected_kind)
  execute_process(
    COMMAND "${PROGRAM}" "${url}" "--options" "${options}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
  )

  if(result EQUAL 0)
    message(FATAL_ERROR "${label}: C binding unexpectedly succeeded")
  endif()
  if(NOT output STREQUAL "")
    message(FATAL_ERROR "${label}: C binding emitted a partial ScrapeProof: ${output}")
  endif()

  string(JSON kind GET "${error}" error kind)
  if(NOT kind STREQUAL expected_kind)
    message(FATAL_ERROR "${label}: expected ${expected_kind}, got ${kind}")
  endif()
endfunction()

function(assert_cli_error label url formats expected_kind)
  execute_process(
    COMMAND "${CLI}" "${url}" "--formats" "${formats}" "--no-js" "--output" "json"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
  )

  if(result EQUAL 0)
    message(FATAL_ERROR "${label}: CLI unexpectedly succeeded")
  endif()
  if(NOT output STREQUAL "")
    message(FATAL_ERROR "${label}: CLI emitted a partial ScrapeProof: ${output}")
  endif()

  string(JSON kind GET "${error}" error kind)
  if(NOT kind STREQUAL expected_kind)
    message(FATAL_ERROR "${label}: expected ${expected_kind}, got ${kind}")
  endif()
endfunction()

assert_c_error(
  "invalid URL"
  "not a url"
  [[{"formats":["rawHtml"],"renderEnabled":false}]]
  "invalid_url"
)
assert_cli_error("invalid URL" "not a url" "rawHtml" "invalid_url")

assert_c_error(
  "unknown format"
  "https://example.com"
  [[{"formats":["bogusfmt"],"renderEnabled":false}]]
  "invalid_format"
)
assert_cli_error("unknown format" "https://example.com" "bogusfmt" "invalid_format")

execute_process(
  COMMAND "${PROGRAM}" "--version"
  RESULT_VARIABLE c_version_result
  OUTPUT_VARIABLE c_version
  ERROR_VARIABLE c_version_error
)
if(NOT c_version_result EQUAL 0)
  message(FATAL_ERROR "C version query failed: ${c_version_error}")
endif()
string(STRIP "${c_version}" c_version)

execute_process(
  COMMAND "${CLI}" "--version"
  RESULT_VARIABLE cli_version_result
  OUTPUT_VARIABLE cli_version
  ERROR_VARIABLE cli_version_error
)
if(NOT cli_version_result EQUAL 0)
  message(FATAL_ERROR "CLI version query failed: ${cli_version_error}")
endif()
string(STRIP "${cli_version}" cli_version)

if(NOT cli_version STREQUAL "basecrawl ${c_version}")
  message(FATAL_ERROR "C header version ${c_version} differs from CLI ${cli_version}")
endif()
