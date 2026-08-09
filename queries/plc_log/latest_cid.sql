SELECT cid
FROM plc_operations
WHERE did = $1
ORDER BY seq DESC
LIMIT 1
