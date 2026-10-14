- fix the fact that a user can register domain.eepy.page, sub.domain.eepy.page, and then delete domain.eepy.page and sub.domain will (i think) still work
- backend password requirements
- remove old items from this todo list
- add back internationalization? likely a backend-frontend hybrid system where the frontend sends a locale code to the backend on requests, so then the backend returns responses in that language, but frontend text is also localized through shared json files across frontend/backend
  - if i do this make sure on the frontend to make sure things are fit for i18n so remove button/text fixed widths etc and switch to tricks like this to avoid buttons from jumping around, and similar stuff for other text issues:
  -
  ```html
  <Button>
    <span class="inline-grid">
      <!-- conditionally set invisible class on the <span>s below, based on which text you want to show -->
      <span class="col-start-1 row-start-1">Save Changes</span>
      <span class="col-start-1 row-start-1">All Changes Saved</span>
    </span>
  </Button>
  ```
- make usernames case-insensitive, case-preserving - so let's say a user's username is AwesomeUser, they can log in with awesomeuser or awesomeUser and it'll work, but then everywhere where username is displayed it'll still show AwesomeUser
- possibly switch to an existing auth system of some sort??
- abuse detection
- status codes (they seem quite odd)
- maybe set up some sort of api docs system (theres api.eepy.page/docs for the openapi thing but those arent too good, like a mkdocs type thing)
- possibly separate scripts/ stuff from this repo since thats not really related to the backend its just stuff for my vps atp
  - also improve how im hosting stuff on my vps lol, its a mess
- add some sort of audit log every time an endpoint is called, action is done, etc -- can probably be stored locally on server
- rate limit emails!!!!!!!! + make sure email verification is secure, with the codes and stuff i think old ones still work also improve the verification flow, maybe add another db value like if the user has ever tried to log in and if its their first login attempt + unverified then itll show a dedicated Verify your email page and THAT'S when the verification email sends (instead of right at signup) and then they verify from there. also maybe check verification for actions? if i were to set a user's status to unverified they'd still be logged in and stuff
- switch to postgresql? w/ sqlalchemy orm?
- maybe add tests for api stuff with the user api keys like if i add stricter security around the recovery email endpoint, make sure it can still work somehow with users' keys if it was ever intended to to begin with
  - maybe make a separate api for users? like the main api.eepy.page would be linked to only work with the frontend via captchas or session tokens or something and then there could be a userapi.eepy.page which is what users would use with their api keys and it would be scoped to the account that generated the api key and have limited permissions and stuff and that would also just make it much easier to separate things
