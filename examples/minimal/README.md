
# Minimal example of Authcode

This is an minimal example on how you use Authcode. It's so minimal than the reset password system can't send emails.

## How to run locally

1. Create a virtualenv to contain the required python libraries (eg: `virtualenv env`)
   and activate it (eg: `source env/bin/activate`).

2. Install the required python libraries by doing

    `pip install -r requirements-dev.txt`

4. Run the development server with: `python app.py`

--------
**Note**:  The `Procfile`, `runtime.txt` and `os.getenv(…)` stuff is for deploying on Heroku.
