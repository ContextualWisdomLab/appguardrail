# Firebase Security Checklist

Firebase is commonly used in vibe-coded apps. These are the most critical Firebase security issues and how to fix them.

---

## Firestore Security Rules

- [ ] Firestore security rules are **not** set to `allow read, write: if true` in production.
- [ ] Every collection has explicit rules that validate authentication.
- [ ] Rules enforce ownership:
  ```javascript
  rules_version = '2';
  service cloud.firestore {
    match /databases/{database}/documents {
      // Users can only read/write their own data
      match /users/{userId} {
        allow read, write: if request.auth != null && request.auth.uid == userId;
      }

      // Only the owner can read/write their projects
      match /projects/{projectId} {
        allow read, write: if request.auth != null
          && request.auth.uid == resource.data.ownerId;
        allow create: if request.auth != null
          && request.auth.uid == request.resource.data.ownerId;
      }
    }
  }
  ```
- [ ] Rules are tested with the Firebase Emulator Suite or the Rules Playground.
- [ ] Rules do not expose admin collections to regular users.
- [ ] Server-side operations that bypass rules use Firebase Admin SDK in a secure server environment (not the client).

## Firebase Authentication

- [ ] Authentication is enforced in every Firestore rule (`request.auth != null`).
- [ ] Email verification is required before users can access sensitive features.
- [ ] Custom claims (roles, permissions) are set server-side using Firebase Admin SDK.
- [ ] Client cannot set its own custom claims.

## Firebase Storage Rules

- [ ] Storage rules are **not** set to `allow read, write: if true`.
- [ ] Users can only read/write their own files:
  ```javascript
  rules_version = '2';
  service firebase.storage {
    match /b/{bucket}/o {
      match /users/{userId}/{allPaths=**} {
        allow read, write: if request.auth != null && request.auth.uid == userId;
      }
    }
  }
  ```
- [ ] File size limits are enforced in storage rules:
  ```javascript
  allow write: if request.resource.size < 10 * 1024 * 1024; // 10 MB
  ```
- [ ] MIME type restrictions are enforced:
  ```javascript
  allow write: if request.resource.contentType.matches('image/.*');
  ```

## Firebase Admin SDK

- [ ] `firebase-admin` is only used server-side (Next.js API routes, Cloud Functions, backend services).
- [ ] Service account JSON key is stored as an environment variable, not committed to the repo.
- [ ] Service account has the minimum required permissions (principle of least privilege).

## Realtime Database (if used)

- [ ] Rules are not set to `".read": true` or `".write": true` at the root.
- [ ] Rules enforce authentication: `".read": "auth != null"`.
- [ ] Data is scoped to the authenticated user: `"$uid": { ".read": "$uid === auth.uid" }`.

## Common Firebase Mistakes in AI-Generated Code

| Mistake | Fix |
|---|---|
| `allow read, write: if true;` | Add `request.auth != null` and ownership check |
| Admin SDK in a client component | Move to Cloud Function or API route |
| Service account key in source code | Use environment variable; add to `.gitignore` |
| No size/type limits in Storage rules | Add `request.resource.size` and `contentType` checks |
| Using client SDK for privileged operations | Use Admin SDK server-side |
| Custom claims set from the client | Set custom claims only from Firebase Admin SDK |
