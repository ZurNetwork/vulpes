SELECT cid, "type" AS op_type, prev, operation
FROM plc_operations
WHERE did = $1
ORDER BY seq DESC
LIMIT 1
