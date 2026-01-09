cmake_minimum_required(VERSION 3.31)
project(PEHeader_Analyzer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC OFF)

set(CMAKE_PREFIX_PATH "E:/Qt/6.10.1/msvc2022_64")

find_package(Qt6 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

#set(CMAKE_UIC_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ui)
#
#set(UI_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ui/mainwindow.ui)
#
#QT6_WRAP_UI(UI_HEADERS ${UI_FILES})
#
## 3. 强制指定 UI 生成文件的输出目录（关键：通过 set_property 单独配置）
#set_property(SOURCE ${UI_HEADERS} PROPERTY GENERATED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/ui)


# 1. 定义 UI 源文件和生成文件路径（新增 dialog.ui 配置）
set(UI_MAIN_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ui/mainwindow.ui)
set(UI_MAIN_DST ${CMAKE_CURRENT_SOURCE_DIR}/ui/ui_mainwindow.h)  # mainwindow 的 UI 头文件
set(UI_DIALOG_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ui/dialog.ui)
set(UI_DIALOG_DST ${CMAKE_CURRENT_SOURCE_DIR}/ui/ui_dialog.h)    # dialog 的 UI 头文件

# 2. 自定义命令：生成 mainwindow.ui 头文件（原有逻辑保留）
add_custom_command(
    OUTPUT ${UI_MAIN_DST}
    COMMAND ${Qt6Core_DIR}/../../../bin/uic.exe
            ${UI_MAIN_SRC}
            -o ${UI_MAIN_DST}
    DEPENDS ${UI_MAIN_SRC}
    COMMENT "Generating UI header: ${UI_MAIN_DST}"
)

# 新增：自定义命令：生成 dialog.ui 头文件（仅新增此段）
add_custom_command(
    OUTPUT ${UI_DIALOG_DST}
    COMMAND ${Qt6Core_DIR}/../../../bin/uic.exe
            ${UI_DIALOG_SRC}
            -o ${UI_DIALOG_DST}
    DEPENDS ${UI_DIALOG_SRC}
    COMMENT "Generating UI header: ${UI_DIALOG_DST}"
)

# 3. 自定义目标：依赖改为包含两个 UI 头文件（仅修改 DEPENDS 部分）
add_custom_target(
    GenerateUIHeader
    DEPENDS ${UI_MAIN_DST} ${UI_DIALOG_DST}  # 新增 ${UI_DIALOG_DST}
)

# ========== 构建可执行文件 ==========
add_executable(PEHeader_Analyzer WIN32
        "main.cpp"
        "src/PEHeaderReader.cpp"
        "include/PEHeaderReader.h"
        "src/PEHeaderModifier.cpp"
        "include/PEHeaderModifier.h"
        "src/mainwindow.cpp"
        "include/mainwindow.h"
        ${UI_SRC}  # 源 UI 文件
        ${UI_DST}
        src/CharacteristicsDialog.cpp
        include/CharacteristicsDialog.h  # 手动生成的 UI 头文件
)

# 4. 强制：先生成 UI 头文件，再编译主程序
add_dependencies(PEHeader_Analyzer GenerateUIHeader)



#add_executable(PEHeader_Analyzer WIN32
#        "main.cpp"
#        "src/PEHeaderReader.cpp"
#        "include/PEHeaderReader.h"
#
#        "src/PEHeaderModifier.cpp"
#        "include/PEHeaderModifier.h"
#
#        "src/mainwindow.cpp"
#        "include/mainwindow.h"
#
#        ${UI_FILES}       # 仅包含源 UI 文件
#        ${UI_HEADERS}     # 包含生成的 UI 头文件（无需手动写 ui/ui_mainwindow.h）
##        "ui/ui_mainwindow.h"
#)


#搜索头文件
#include_directories(include/)
#file(GLOB HEADER_FILES "include/*.h")
#
##搜索源文件
#file(GLOB SRC_LIST "src/*.cpp")
#
## 搜索ui文件
#file(GLOB UI_FILES "ui/*.ui")
#
## 搜索资源文件（图片、图标、音乐等）
#file(GLOB_RECURSE RESOURCES "sources/*.qrc")
#
#
## 生成头文件的 MOC 文件
#QT6_WRAP_CPP(HEADERS_MOC ${HEADER_FILES})
## 生成 UI 文件对应的头文件
#QT6_WRAP_UI(FORMS_HEADERS ${UI_FILES})
## 添加资源文件
#QT6_ADD_RESOURCES(RCC ${RESOURCES})
#
#add_executable(PEHeader_Analyzer main.cpp ${HEADERS_MOC} ${SRC_LIST} ${FORMS_HEADERS} ${RCC})
#
#set_target_properties(PEHeader_Analyzer PROPERTIES
#        WIN32_EXECUTABLE ON)




target_link_libraries(PEHeader_Analyzer
        Qt::Core
        Qt::Gui
        Qt::Widgets
)

#set_target_properties(PEHeader_Analyzer PROPERTIES
#    AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui # UI文件所在目录（比如SRC根目录）
#    UIC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ui  # 生成的ui_xxx.h输出到/ui目录
#)


if (WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(DEBUG_SUFFIX)
    if (MSVC AND CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif ()
    set(QT_INSTALL_PATH "${CMAKE_PREFIX_PATH}")
    if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
        set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
            set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        endif ()
    endif ()
    if (EXISTS "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
    endif ()
    foreach (QT_LIB Core Gui Widgets)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/bin/Qt6${QT_LIB}${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endforeach (QT_LIB)
endif ()
