#!/bin/bash

set -e

ARTIFACT=$1
APP_DIR=$2

WORK_DIR=./upgrading

mkdir -p ${WORK_DIR}
tar xzf ${ARTIFACT} -C ${WORK_DIR}

CURRENT_LINK_DIR=`readlink ${APP_DIR}/current`

NEW_ARTIFACT_DIR=`ls ${WORK_DIR}`

echo "NEW APP: ${NEW_ARTIFACT_DIR}"
echo "CURRENT APP: ${CURRENT_LINK_DIR}"

mv ${WORK_DIR}/${NEW_ARTIFACT_DIR} ${APP_DIR}
rm ${APP_DIR}/current
ln -sf ${NEW_ARTIFACT_DIR} ${APP_DIR}/current

rm -rf ${WORK_DIR}
rm -rf ${APP_DIR}/${CURRENT_LINK_DIR}

exit $?