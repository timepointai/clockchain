-- One snapshot: state must not be computed from separately raced/truncated lists.
WITH images AS (
    SELECT * FROM image_attachments WHERE entity_id=$1 AND admitted_coord <= $2
), absences AS (
    SELECT * FROM media_absence_decisions WHERE entity_id=$1 AND admitted_coord <= $2
), hashes AS (
    SELECT body_hash FROM moments WHERE subject=$1 AND coord <= $2
    UNION SELECT source_body_hash FROM images
    UNION SELECT source_body_hash FROM absences
)
SELECT encode(h.body_hash, 'hex') AS source_body_hash,
    EXISTS (SELECT 1 FROM moments m WHERE m.subject=$1 AND m.body_hash=h.body_hash) AS current,
    COALESCE((SELECT json_agg(json_build_object(
        'attachment_id', i.attachment_id, 'manifest', i.manifest::json,
        'author', i.author, 'signature', i.signature,
        'admitted_coord', '0x' || encode(i.admitted_coord, 'hex')
    ) ORDER BY i.attachment_id) FROM images i WHERE i.source_body_hash=h.body_hash), '[]')::text AS images,
    COALESCE((SELECT json_agg(json_build_object(
        'decision_id', a.decision_id, 'manifest', a.manifest::json,
        'author', a.author, 'signature', a.signature,
        'admitted_coord', '0x' || encode(a.admitted_coord, 'hex')
    ) ORDER BY a.decision_id) FROM absences a WHERE a.source_body_hash=h.body_hash), '[]')::text AS absence_decisions
FROM hashes h ORDER BY h.body_hash;
