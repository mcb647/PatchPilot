-- Older AST payloads can include raw call expressions. Rebuild them on demand.
DELETE FROM ast_cache;
