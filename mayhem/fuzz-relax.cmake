# Included by mayhem/build.sh via -DCMAKE_PROJECT_INCLUDE for the fuzz build only.
# csp_id.c and csp_buffer.c point packet->frame_begin a few bytes before packet->data[], into the
# header[] padding that precedes it in csp_packet_t, by design ("data - CSP_ID2_HEADER_SIZE").
# UBSan's array-bounds check reports that index -6 on every packet, so it is turned off for these
# two files only; the rest of UBSan and ASan stay on and halting.
set_source_files_properties(
  ${CMAKE_SOURCE_DIR}/src/csp_id.c
  ${CMAKE_SOURCE_DIR}/src/csp_buffer.c
  PROPERTIES COMPILE_OPTIONS "-fno-sanitize=array-bounds")
