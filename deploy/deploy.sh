#!/bin/bash

set -eu

# Update API service
python "`dirname $0`/generate_task_definition.py"
TASK_DEFINITION_JSON=$(aws ecs register-task-definition --family chat-gpt-bot --cli-input-json "file://`dirname $0`/task_definition.json")
TASK_REVISION=$(echo ${TASK_DEFINITION_JSON} | jq .taskDefinition.revision)

aws ecs update-service \
    --cluster appbrew-tools \
    --service chatgpt-bot \
    --task-definition "chat-gpt-bot:${TASK_REVISION}"
