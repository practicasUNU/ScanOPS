-- Verificación previa (revisar antes de borrar)
SELECT COUNT(*) AS total_basura
FROM assets
WHERE hostname LIKE 'discovered-%'
  AND responsable = 'Pendiente asignar';

-- Borrado de activos registrados automáticamente por el discovery
DELETE FROM assets
WHERE hostname LIKE 'discovered-%'
  AND responsable = 'Pendiente asignar';
