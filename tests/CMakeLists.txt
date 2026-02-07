add_executable(test_oggtag test_oggtag.c)
target_link_libraries(test_oggtag PRIVATE oggtag)
target_include_directories(test_oggtag PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME oggtag_tests COMMAND test_oggtag)
