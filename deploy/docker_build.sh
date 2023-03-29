#!/bin/bash

set -eu

IMAGE_NAME="appbrew/chat-gpt-bot"

docker build -t "${IMAGE_NAME}" .
docker tag ${IMAGE_NAME} 987776079498.dkr.ecr.ap-northeast-1.amazonaws.com/${IMAGE_NAME}:${CIRCLE_BUILD_NUM}
docker tag ${IMAGE_NAME} 987776079498.dkr.ecr.ap-northeast-1.amazonaws.com/${IMAGE_NAME}:latest
