#!/bin/sh
# Create the auth table (idempotent). Works against AWS or DynamoDB Local.
#   DYNAMODB_TABLE=auth ./scripts/create-table.sh
#   DYNAMODB_TABLE=auth DYNAMODB_ENDPOINT=http://localhost:8000 ./scripts/create-table.sh
set -eu

TABLE="${DYNAMODB_TABLE:-auth}"
ENDPOINT_ARGS=""
if [ -n "${DYNAMODB_ENDPOINT:-}" ]; then
  ENDPOINT_ARGS="--endpoint-url ${DYNAMODB_ENDPOINT}"
fi

# Wait for DynamoDB Local to accept connections.
i=0
until aws dynamodb list-tables $ENDPOINT_ARGS >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then echo "DynamoDB not reachable" >&2; exit 1; fi
  sleep 1
done

if aws dynamodb describe-table --table-name "$TABLE" $ENDPOINT_ARGS >/dev/null 2>&1; then
  echo "Table $TABLE already exists"
  exit 0
fi

aws dynamodb create-table $ENDPOINT_ARGS \
  --table-name "$TABLE" \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST >/dev/null

aws dynamodb wait table-exists --table-name "$TABLE" $ENDPOINT_ARGS

aws dynamodb update-time-to-live $ENDPOINT_ARGS \
  --table-name "$TABLE" \
  --time-to-live-specification "Enabled=true, AttributeName=ttl" >/dev/null

echo "Created table $TABLE"
