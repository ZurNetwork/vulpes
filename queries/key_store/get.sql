-- The envelope scheme comes back WITH the blob: which associated data opens
-- these bytes is a property of the row, never an assumption of the reader.
SELECT wrapped_keys, key_version FROM account_keys WHERE did = $1
