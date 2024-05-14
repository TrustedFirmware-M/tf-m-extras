#-------------------------------------------------------------------------------
# Copyright (c) 2024, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.21)

add_custom_target(docs)

project("Trusted Firmware M Extras. Documentation" LANGUAGES)

set(SPHINX_EXECUTABLE sphinx-build)
set(SPHINXCFG_SOURCE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(SPHINXCFG_CONFIG_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(SPHINXCFG_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB_RECURSE SPHINXCFG_DOC_FILES ${SPHINXCFG_SOURCE_PATH}/*.rst ${SPHINXCFG_SOURCE_PATH}/*.md)

add_custom_target(tfm_docs_extras_html ALL
    COMMAND "${SPHINX_EXECUTABLE}" -W -b html -j 8 -c ${SPHINXCFG_CONFIG_PATH} ${SPHINXCFG_SOURCE_PATH} "${SPHINXCFG_OUTPUT_PATH}/html"
    WORKING_DIRECTORY ${SPHINXCFG_SOURCE_PATH}
    DEPENDS ${SPHINXCFG_DOC_FILES}
)
add_dependencies(docs tfm_docs_extras_html)

add_custom_target(tfm_docs_extras_pdf ALL
    COMMAND "${SPHINX_EXECUTABLE}" -W -b latex -j 8 -c ${SPHINXCFG_CONFIG_PATH} ${SPHINXCFG_SOURCE_PATH} "${SPHINXCFG_OUTPUT_PATH}/latex"
    COMMAND ${PDFLATEX_COMPILER} -output-directory "${SPHINXCFG_OUTPUT_PATH}/latex" TF-M.tex
    COMMAND ${CMAKE_COMMAND} -E copy "${SPHINXCFG_OUTPUT_PATH}/latex/TF-M.pdf" "${SPHINXCFG_OUTPUT_PATH}/tf-m_user_guide.pdf"
    WORKING_DIRECTORY ${SPHINXCFG_SOURCE_PATH}
    DEPENDS ${SPHINXCFG_DOC_FILES}
)
add_dependencies(docs tfm_docs_extras_pdf)

