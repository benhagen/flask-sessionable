flask-sessionable
=================

Different sessions for Flask. Flask-sessionable stores user sessions in two seperate cookies:
* "app.session_cookie_name" is unencrypted but cryptographically signed. This cookie can be used and referenced by client-side Javascript. Client-side changes are prohibited via the cryptographic signature.
* "app.session_cookie_name + _secure" is encrypted and should be unreadable by the client.

## Example Usage

```python

#!/usr/bin/env python

from flask import Flask, session, request
import flask_sessionable
import cgi

app = Flask(__name__)
app.secret_key = "BIGOL'SECRET"
app.session_interface = flask_sessionable.session_interface()


@app.route("/")
def root():
	return """
	Current Session:
	Insecure Cookie: <pre>{}</pre>
	Secure Cookie: <pre>{}</pre>
	Values:
	<pre>{}</pre>""".format(
		request.cookies.get(app.session_cookie_name),
		request.cookies.get(app.session_cookie_name + "_secure"),
		cgi.escape(session.debug()))


if __name__ == "__main__":
	app.debug = True
	app.run(use_reloader=True)

```
