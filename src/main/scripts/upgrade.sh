#!/bin/bash
set -e

ARTIFACT=$1
APP_DIR=$2

WORK_DIR=./upgrading

mkdir -p ${WORK_DIR}

tar zxf ${ARTIFACT} -C ${WORK_DIR}

NEW_ARTIFACT_DIR=`ls ${WORK_DIR}`

if [ -e "${APP_DIR}/current" ]; then
  CURRENT_LINK_DIR=`readlink ${APP_DIR}/current`
  echo "CURRENT APP: ${CURRENT_LINK_DIR}"
  rm -f ${APP_DIR}/current
fi

echo "NEW APP: ${NEW_ARTIFACT_DIR}"

mv ${WORK_DIR}/${NEW_ARTIFACT_DIR} ${APP_DIR}
ln -sf ${NEW_ARTIFACT_DIR} ${APP_DIR}/current

rm -rf ${WORK_DIR}

exit $?
