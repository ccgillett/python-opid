
import urllib

import paste.urlmap
import paste.httpserver
import beaker.middleware

import opid


def index_app(environ, start_response):
    sessions = environ['test.session']

    if 'opid.identity_url' in sessions:
        response = ["<p>"
                    "Logged in with identity %s at %f" % (sessions['opid.identity_url'],
                                                          sessions['opid.auth_time']),
                    "</p>"
                    "<p><a href=\"/signout\">Sign out.</a></p>"]
    else:
        base_url = "%s://%s" % (environ['wsgi.url_scheme'],
                                environ['HTTP_HOST'])
        opid_queries = urllib.urlencode({'url': 'www.google.com/accounts/o8/id',
                                         'success': '/',
                                         'failure': '/failure'})
        response = ["<p>"
                    "Not logged in."
                    "</p>",
                    "<a href=\"", base_url, "/opid/verify?", opid_queries, "\">",
                    "Click to log into Google."
                    "</a>"]

    start_response('200 OK', [('Content-Type', 'text/html')])
    return ["<html>",
            "<head><title>opid test</title></head>",
            "<body>"] + response + \
            ["</body>",
             "</html>"]


def failure_app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    return "<html><head><title>Login failure</title></head>" + \
        "<body><p>Failed to log in.</p></body></html>"


def logged_out_app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    return "<html><head><title>Logged out.</title></head>" + \
        "<body><p>Logged out. <a href=\"/\">Go back to main page.</a></p></body></html>"


opid_session_key = 'test.session'
opid_app = opid.App(session_key=opid_session_key,
                    #store=opid.FileStore('opid.store')
                    )
session_app = lambda app: beaker.middleware.SessionMiddleware(app, environ_key=opid_session_key)

urls = paste.urlmap.URLMap()
urls['/'] = session_app(index_app)
urls['/opid'] = session_app(opid_app)
urls['/signout'] = session_app(opid_app.unauth_app('/logged_out'))
urls['/failure'] = session_app(failure_app)
urls['/logged_out'] = session_app(logged_out_app)

paste.httpserver.serve(urls)
