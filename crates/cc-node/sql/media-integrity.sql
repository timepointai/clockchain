-- One snapshot for the denominator, findings and assertion; shared with ops.
WITH bindings AS (
    SELECT a.attachment_id, a.entity_id, a.source_body_hash,
        EXISTS (SELECT 1 FROM moments m
                WHERE m.body_hash = a.source_body_hash) AS projected,
        EXISTS (SELECT 1 FROM moments m
                WHERE m.body_hash = a.source_body_hash
                  AND m.subject = a.entity_id) AS current
    FROM image_attachments a
)
SELECT json_build_object(
    'image_attachment_count', count(*),
    'orphan_image_attachment_count', count(*) FILTER (WHERE NOT projected),
    'stale_image_attachment_count', count(*) FILTER (WHERE NOT current),
    'integrity', CASE WHEN bool_or(NOT projected) THEN 'fail' ELSE 'pass' END,
    'orphan_attachments', COALESCE(json_agg(json_build_object(
        'attachment_id', attachment_id,
        'entity_id', entity_id::text,
        'source_body_hash', encode(source_body_hash, 'hex')
    ) ORDER BY attachment_id) FILTER (WHERE NOT projected), '[]'::json),
    'historical_evidence', false,
    'anchor_scope', 'independent media signatures; not historical ledger anchors'
)::text FROM bindings;
