###  AUTHOR: wangshijie  ###

# 1. source code
AUX_SOURCE_DIRECTORY(. SRCS_LIST)

# 2. include path


# 3. set output path
#SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# 4. generate shared lib
ADD_LIBRARY(kcapi SHARED ${SRCS_LIST})

# 5. generate static lib
ADD_LIBRARY(kcapi_static STATIC ${SRCS_LIST})
# change static lib name
SET_TARGET_PROPERTIES(kcapi_static PROPERTIES OUTPUT_NAME "kcapi")
# 使动态库和静态库同时存在
SET_TARGET_PROPERTIES(kcapi PROPERTIES CLEAN_DIRECT_OUTPUT 1)
SET_TARGET_PROPERTIES(kcapi_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)

# 6. 指定动态库版本
# VERSION 动态库版本
# SOVERSION API版本
SET_TARGET_PROPERTIES(kcapi PROPERTIES VERSION 1.0 SOVERSION 1)