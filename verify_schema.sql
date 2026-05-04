-- verify_schema.sql
-- Ejecutar en psql: \i verify_schema.sql

\echo 'Verificando estructura de la tabla assets...'
\d assets

\echo 'Verificando índices de la tabla assets...'
SELECT
    indexname,
    indexdef
FROM
    pg_indexes
WHERE
    tablename = 'assets';

\echo 'Verificando tipos ENUM creados...'
SELECT n.nspname as schema, t.typname as type 
FROM pg_type t 
LEFT JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace 
WHERE (n.nspname = 'public') 
AND (t.typtype = 'e');
