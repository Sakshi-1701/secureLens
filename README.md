# Vigil - Security Scan Web App

Backend: Spring Boot 3.5.5 (Java 17). Frontend: React 18 + Vite + Tailwind + MUI. Database: PostgreSQL. Scanner: OWASP Dependency-Check.

## Backend

- Configure `src/main/resources/application.properties` for PostgreSQL, SMTP, and AI endpoint.
- Run database schema: `db/schema.sql`.
- Build & run:

```bash
mvn spring-boot:run
```

## Frontend

- Create `.env` and set `VITE_API_BASE_URL`.
- Install and run:

```bash
cd frontend
npm i
npm run dev
```

## Notes

- `POST /api/upload-plugin` (multipart) uploads a ZIP.
- `POST /api/upload-plugin/git` saves a Git URL.
- `POST /api/scan-plugin/{pluginId}` triggers async scan.
- Reports endpoints: `GET /api/reports`, `GET /api/scan-results/{pluginId}`, CSV download and email sending are available.
- AI suggestions are populated via `AiSuggestionService`.


