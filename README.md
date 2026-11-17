# WANTED CONTROL

Private control panel for interactive wanted-level OBS overlays.

## Quick setup

1. Create a Supabase project.
2. Run [sql/setup.sql](sql/setup.sql) in the Supabase SQL Editor.
3. In GitHub open **Settings → Secrets and variables → Actions**:
   - Repository variable: `VITE_SUPABASE_URL` — the Supabase project URL.
   - Repository secret: `VITE_SUPABASE_PUBLISHABLE_KEY` — the Publishable/anon key.
4. Open **Settings → Pages** and select **GitHub Actions** as the deployment source.
5. Push to `main` or run the **Build and deploy site** workflow.

The application source is in [widget-source.zip](widget-source.zip). It contains the Vite project, database setup instructions, styles and client code. The workflow extracts it and publishes the built site.

The initial administrator username is `cjlakc`. The initial password is supplied separately; it is not stored in plaintext in this repository. Change it from **Account Security** after the first login.

The Supabase `service_role` key must never be added to Actions variables or frontend code. Only the Publishable/anon key is used in the browser.

The published address follows this pattern:

```
https://YOUR_GITHUB_ACCOUNT.github.io/widget-gta-VI/
```

From the dashboard, create a widget profile and copy its OBS Display URL. Open the main site on a second device to control that same profile.