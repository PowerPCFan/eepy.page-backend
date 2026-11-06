- I18n: remove button/text fixed widths / other size constraints and switch to tricks like this to avoid buttons from jumping around when their content changes:
-
```svelte
<Button>
<span class="inline-grid">
  <!-- conditionally set an "invisible class" on the <span>s below, based on which text you want to show -->
  <span class="col-start-1 row-start-1">Save Changes</span>
  <span class="col-start-1 row-start-1">All Changes Saved</span>
</span>
</Button>
```
- Add i18n to the backend (currently frontend-only; this update will go along with the )
  - separate backend files? also just improve locale organization it seems a bit messed up
- Possibly switch to an existing auth system of some sort? Or at least look into options and possibly test some of them out
- Standardize status codes
  - basically the idea is to switch to a few standard HTTP codes, and then use JSON response bodies to distinguish what they mean. So for example, a possible response on an endpoint where user info is being retrieved:
  - 
  ```json
  {
    // HTTP Code: 404 Not Found (this is standard, and not some random code that might have been returned on the old backend)

    // A code that ALWAYS stays the same, and can be safely relied upon for error handling
      "error": "USER_NOT_FOUND",

    // A human-readable, localized error message (you can display this on frontends but do not do like `if message == 'User not found.'` -- the error code is for that purpose)
      "message": "User not found."
  }
  ```
  - There's also some weird stuff going on with the current response bodies outside of the wonky status codes, like conflicts between FastAPI responses, Pydantic model stuff, etc and sometimes it causes really cryptic errors and hard to parse responses that are super messed up on the frontend, others are simpler and just pass like a unique HTTP code, error message, and other relevant data. So I can fix/standardize this along with the HTTP codes as well since this is all part of restructuring the response bodies.
  - And since I'm using FastAPI there might be a better/more "native" method than the one I proposed in the codeblock above, that was mainly just an idea/PoC of a system that would work better than the current one
- Possibly separate scripts/ stuff from this repo since it's not really related to the backend, it's mainly just stuff for my VPS
  - Improve how I'm hosting stuff on my VPS, it's a mess
- Make sure emails are rate limited
- Make sure email verification is secure, with the codes and stuff - I think old codes still work, also improve the verification flow, maybe add another DB value like if the user has ever tried to log in and if it's their first login attempt + unverified THEN it'll show a dedicated "Verify your email" page and THAT'S when the verification email sends (instead of right at signup) and then they verify from there? Or is that an anti-pattern of some sort? Unsure. Also maybe check a user's standing when performing actions? If I were to set a user's status to unverified, or disable their account, they might still be logged in and stuff. Have to do some testing and messing around with this
- API response body JSON keys: migrate to snake_case or camelCase? kebab-case works badly in both Python and JS so i have no clue why it was chosen, annoying as it forces bracket syntax (like `var["key-name"]`) instead of just `var.keyName`
- Secrets + SSH key maintenance on VPS
- Implement a full audit log for all actions, for many purposes
- Remove old migrations (e.g. I'm pretty sure theres a no username -> username migration but since eepy.page started this summer, all users should have a username anyways since usernames were added before that so it's needlessly stealing CPU time)
  - And also, just figure out what's going on with migrations in general, it feels quite messed up
- Custom status page (Atlassian Statuspage / Uptime Kuma style)
- Write how-to guides on docs.eepy.page
- Modernize and streamline all infrastructure
- Migrate from MongoDB to PostgreSQL and use SQLModel
- Improve GDPR export system
- Figure out wtf I'm doing with git. Like I need to stop doing 100000-line commits that get instantly pushed to main with me crossing my fingers that it works in prod. That just can't be happening anymore bro what are we doinggg. like it's not really a big deal since eepy.page doesn't have many users but i need to learn how to actually work on public, production systems because i do a shit ton of breaking changes out of nowhere as well. so i need proper versioning, release workflows, checklists/reminders, more incremental commits, semantic commit messages, more organization overall, using dev branches and pull requests, etc.