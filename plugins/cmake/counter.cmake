find_package (Python3 COMPONENTS Interpreter)
execute_process (COMMAND "${Python3_EXECUTABLE}" -m venv ${CMAKE_BINARY_DIR}/.venv)

# Here is the trick
## update the environment with VIRTUAL_ENV variable (mimic the activate script)
set (ENV{VIRTUAL_ENV} ${CMAKE_BINARY_DIR}/.venv)
## change the context of the search
set (Python3_FIND_VIRTUALENV FIRST)
## unset Python3_EXECUTABLE because it is also an input variable (see documentation, Artifacts Specification section)
unset (Python3_EXECUTABLE)
## Launch a new search
find_package (Python3 COMPONENTS Interpreter Development)

# install PyPI Python package using pip
set (_pypkg "pydantic")
set (_pip_args "")
execute_process(COMMAND ${Python3_EXECUTABLE} -m pip install ${_pip_args} ${_pypkg})

# set (CounterName vcdp_services/nat/nat_counter)
# add_custom_command(
#     COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/counters.py --header ${CMAKE_CURRENT_SOURCE_DIR}/${CounterName}.json > ${CMAKE_BINARY_DIR}/plugins/${CounterName}.h
#     COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/counters.py ${CMAKE_CURRENT_SOURCE_DIR}/${CounterName}.json > ${CMAKE_BINARY_DIR}/plugins/${CounterName}.c
#     DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/counters.py ${CounterName}.json
#     OUTPUT ${CounterName}.c ${CounterName}.h
#     COMMENT "Generating code for ${CounterName}."
# )



macro(add_vpp_counters)
  set(multiValueArgs COUNTERS)
  cmake_parse_arguments(CNT "" "" "${multiValueArgs}" ${ARGN})

  
  foreach (f ${CNT_COUNTERS})
        set (CounterName ${f})
        set (HeaderFile ${CMAKE_BINARY_DIR}/plugins/${CounterName}.h)
        set (CFile ${CMAKE_BINARY_DIR}/plugins/${CounterName}.c)
        message(STATUS, "Compile counter ${f} into ${HeaderFile}")
        add_custom_command(
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/counters.py --header ${CMAKE_CURRENT_SOURCE_DIR}/${CounterName} ${CounterName}> ${HeaderFile}
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/counters.py ${CMAKE_CURRENT_SOURCE_DIR}/${CounterName} ${CounterName}> ${CFile}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/counters.py ${CounterName}
            OUTPUT ${HeaderFile} ${CFile}

            COMMENT "Generating code for ${CounterName}."
        )
    endforeach()
endmacro()
