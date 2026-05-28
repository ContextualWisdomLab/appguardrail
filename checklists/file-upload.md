# File Upload Security Checklist

File uploads are a common attack vector in web apps. AI-generated upload handlers frequently miss critical server-side validations.

---

## Server-Side Validation (Required)

- [ ] **File type** is validated server-side by inspecting the file's MIME type (from the `Content-Type` header or by reading file bytes), not just the file extension or client-supplied type.
- [ ] **File extension** is validated against an allowlist of permitted extensions.
- [ ] **File size** is limited server-side. The limit is enforced before the file is fully read or stored.
- [ ] Validation happens on the **server**, not just in the browser's `<input accept="...">` or JavaScript.

```typescript
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp', '.pdf'];
const MAX_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

const ext = path.extname(file.originalname).toLowerCase();
if (
  !ALLOWED_MIME_TYPES.includes(file.mimetype) ||
  !ALLOWED_EXTENSIONS.includes(ext) ||
  file.size > MAX_SIZE_BYTES
) {
  return res.status(400).json({ error: 'Invalid file' });
}
```

## Filename Handling

- [ ] User-supplied filenames are **never** used directly as the stored filename.
- [ ] Filenames are sanitized or replaced with a server-generated name (UUID + extension).
- [ ] Path traversal is not possible: filenames do not contain `../`, `/`, or null bytes.

```typescript
// ✅ Correct: generate a safe filename
const safeFilename = `${randomUUID()}${path.extname(file.originalname).toLowerCase()}`;

// ❌ Wrong: using the original filename
const filePath = `uploads/${req.file.originalname}`; // path traversal risk!
```

## Storage Location

- [ ] Uploaded files are stored outside the web root (not directly accessible via a URL by default).
- [ ] Private user files are in a **private** storage bucket; access requires authentication.
- [ ] Signed, time-limited URLs are generated server-side to serve private files.
- [ ] Public files (profile pictures, public assets) are stored separately from private files.

## Authentication & Ownership

- [ ] The upload endpoint requires authentication.
- [ ] Users can only view and delete their own uploaded files.
- [ ] Ownership is stored in the database alongside the file record.

## Upload to Cloud Storage (Supabase / S3 / GCS)

- [ ] Uploads go directly to cloud storage (pre-signed URL or server-side); files are not stored on the server disk.
- [ ] Pre-signed upload URLs are scoped to a specific path that prevents users from overwriting each other's files.
- [ ] Bucket policies / IAM roles restrict access appropriately.

## Protection Against Malicious Files

- [ ] Uploaded files are **not** executed or interpreted by the server (no `.php`, `.sh`, `.exe`, etc. uploads).
- [ ] HTML and SVG uploads are treated as static data, not rendered with scripts (risk of stored XSS).
- [ ] Images are processed through an image library (e.g., Sharp) to strip potentially malicious metadata (EXIF, embedded scripts).
- [ ] Antivirus / malware scanning is considered for uploads that are served to other users.

## Common File Upload Mistakes in AI-Generated Code

| Mistake | Fix |
|---|---|
| Using `req.file.originalname` as stored filename | Generate `uuid + extension` server-side |
| Checking `mimetype` from the client only | Read file bytes to detect actual type |
| No size limit before reading file | Set `limits.fileSize` in multer or equivalent |
| Storing uploads in `public/uploads/` | Store outside web root; serve via signed URL |
| No auth check on the upload endpoint | Verify session before accepting upload |
| Allowing `.html`, `.svg` uploads served to users | Strip scripts; serve with `Content-Disposition: attachment` |
