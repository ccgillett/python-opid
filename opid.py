

# Copyright (c) 2009, S7 Labs, LLC
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of S7 Labs, LLC nor the names of its contributors
# may be used to endorse or promote products derived from this
# software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""
Opid is a simple, flexible OpenID consumer WSGI app written by Wes
Chow <wes.chow@s7labs.com>. You can use it to add OpenID login support
to your WSGI application.
"""


import time
import urlparse

import openid.consumer.consumer
import openid.store.memstore
import openid.store.filestore



if hasattr(urlparse, 'parse_qs'):
    # Python 2.6 parse_* functions are in urlparse
    _parse_qs = urlparse.parse_qs
    _parse_qsl = urlparse.parse_qsl
else:
    # Python 2.5 parse_* functions are in cgi
    import cgi
    _parse_qs = cgi.parse_qs
    _parse_qsl = cgi.parse_qsl



class OpidException(RuntimeError):
    # fixme: we might want to provide a WSGI wrapper that converts
    # Opid specific exceptions into paste.httpexceptions.
    pass


_enforce_single_q_no_def = []
def _enforce_single_q(environ, q_key, default=_enforce_single_q_no_def):
    """Retrieves the query value at q_key, and requires there to be
    exactly one value. If multiple values exist, raises ValueError. If
    no value is given, returns the default value, or raises ValueError
    if no default is specified."""

    try:
        vals = _parse_qs(environ['QUERY_STRING'])[q_key]
        if len(vals) == 0:
            raise KeyError()
        if len(vals) > 1:
            raise ValueError("wrong number of queries '%s' given (%d, need 1)" % (q_key, len(vals)))

        return vals[0]
    except KeyError, e:
        if default is _enforce_single_q_no_def:
            raise ValueError("no query '%s' specified" % q_key)
        else:
            return default


def default_redirect_app(environ, start_response):
    """Default redirect app. Opid gives the redirect via an environ item
    with key 'opid.redirect_url'. For most uses, this app is
    sufficient."""

    # fixme: btw...
    #
    # environ['some-key'] = 'some-val'   <-- is modifying this bad?
    # return continue_app(environ, start_response)
    #
    # or, should we be doing this...
    #
    # new_environ = environ.copy()
    # new_environ['some-key'] = 'some-val'
    # return continue_app(new_environ, start_response)
    #
    # ... the second form removes the ability from continue_app (and
    # its children) to pass environment changes up the chain.

    loc_url = environ['opid.redirect_url']
    start_response("302 Found",
                   [('Content-Type', 'text/html'),
                    ('Location', loc_url)])
    return [" "] # gzipper.middleware barfs unless there's some content here, even if it's empty


def default_post_app(environ, start_response):
    """Default post app. Opid gives the form html via an environ item with
    key 'opid.form_html'. You may want to override this default app so
    that it displays a page that's styled for your site. Your custom
    page must call submit on the form with id 'opid_post', like so:

    <body onload='document.getElementById("opid_post").submit()'>
    """

    form_html = environ['opid.form_html']
    content = \
        "<html><head><title>OpenID transaction in progress</title></head>" \
        "<body onload='document.getElementById(\"opid_post\").submit()'>" \
        +form_html+ \
        "</body></html>"

    start_response("200 OK",
                   [('Content-Type', 'text/html'),
                    ('Content-Length', len(content))])
    return [content]


def _get_session(environ, key):
    """Default session retrieval. Opid currently does not allow you to use
    anything beside Beaker, however its design allows for other
    session middleware."""

    # fixme: it'd be nicer to use context manager:
    # http://python.org/doc/2.5.2/lib/typecontextmanager.html

    try:
        return environ[key]
    except KeyError, e:
        raise OpidException("No session '%s' -- session middleware probably unconfigured" % key)


class App(object):
    """Opid WSGI app."""

    def __init__(self, realm=None, session_key='beaker.session',
                 store=None,
                 redirect_app=default_redirect_app, post_app=default_post_app):
        """Sets up an OpenID authentication app on /verify and /return. If no
        realm is given, it defaults to the HTTP host, found from the
        WSGI environment. If no store is specified, defaults to a
        memory based store. Otherwise, it expects you to supply the
        required store.

        Opid pulls success and failure redirect paths from the query
        string. In all, you can pass in values for the keys "url",
        "success", and "failure". Opid will automatically
        unauthenticate any current session before attempting discovery
        on the identity url, unless you give it no_unauth=1 in the
        query string. Failure to unauthenticate could have subtle
        security implications, so think carefully before setting
        no_unauth=1.

        You can set up Opid with custom redirect and
        post apps. See default_redirect_app and default_post_app
        docstrings for details."""

        self.realm = realm
        self.session_key = session_key
        self.redirect_app = redirect_app
        self.post_app = post_app
        self.store = store or openid.store.memstore.MemoryStore()


    def __call__(self, environ, start_response):
        path_info = environ['PATH_INFO']
        if path_info == '/verify':
            return self.verify_path(environ, start_response)
        if path_info == '/return':
            return self.return_path(environ, start_response)

        raise OpidException("No path defined for '%s'" % path_info)


    def _return_to(self, environ):
        """Return path OpenID provider takes to get back to our app."""

        return "%s://%s%s/return" % (environ['wsgi.url_scheme'],
                                     environ['HTTP_HOST'],
                                     environ['SCRIPT_NAME'])


    def verify_path(self, environ, start_response):
        realm = self.realm or "%s://%s" % (environ['wsgi.url_scheme'],
                                           environ['HTTP_HOST'])
        openid_url = _enforce_single_q(environ, 'url')
        success_url = _enforce_single_q(environ, 'success', default='/')
        failure_url = _enforce_single_q(environ, 'failure', default='/')
        no_unauth = _enforce_single_q(environ, 'no_unauth', default=None)

        if no_unauth == '1':
            self.unauth(environ)

        session = _get_session(environ, self.session_key)
        session['opid.realm'] = realm
        session['opid.openid_url'] = openid_url
        session['opid.success_url'] = success_url
        session['opid.failure_url'] = failure_url
        session['opid.session'] = {}

        consumer = openid.consumer.consumer.Consumer(session['opid.session'],
                                                     self.store)
        authreq = consumer.begin(openid_url)
        session.save()

        if authreq.shouldSendRedirect():
            redirect_url = authreq.redirectURL(realm,
                                               self._return_to(environ))
            environ['opid.redirect_url'] = redirect_url
            return self.redirect_app(environ, start_response)
        else:
            return_form = authreq.formMarkup(realm,
                                             self._return_to(environ),
                                             form_tag_attrs={'id': 'opid_post'})
            environ['opid.form_html'] = return_form
            return self.post_app(environ, start_response)


    def return_path(self, environ, start_response):
        session = _get_session(environ, self.session_key)
        consumer = openid.consumer.consumer.Consumer(session['opid.session'],
                                                     self.store)

        # Consumer.complete expects a dictionary, whereas a query
        # string represents a multidict. We flatten it here.
        qdict = {}
        for k,v in _parse_qsl(environ['QUERY_STRING']):
            qdict[k] = v

        resp = consumer.complete(qdict, self._return_to(environ))
        environ['opid.auth_status'] = resp.status


        # fixme: we could theoretically make success and failure user
        # definable apps. In this case, it'd be better to generalize
        # handling of success/failure urls. Ie, we might not want them
        # at all. Rather, when opid gets a hit at /verify, store the
        # query string in the session. We can then pass it on to the
        # success and failure apps, so that they can determine what to
        # do next.

        if resp.status == 'success':
            session['opid.identity_url'] = resp.identity_url
            session['opid.auth_time'] = time.time()
            session.save()

            environ['opid.redirect_url'] = session['opid.success_url']
            return self.redirect_app(environ, start_response)
        else:
            environ['opid.redirect_url'] = session['opid.failure_url']
            return self.redirect_app(environ, start_response)


    def unauth(self, environ):
        """Removes opid session state, thereby unauthenticating user."""

        session = _get_session(environ, self.session_key)
        for k in ['opid.realm', 'opid.openid_url', 'opid.success_url', 'opid.failure_url',
                  'opid.session', 'opid.identity_url', 'opid.auth_time', 'opid.auth_status']:
            if k in session:
                del session[k]
        session.save()


    def unauth_app(self, return_url='/'):
        """Produces a WSGI app that unauthenticates, and then redirects to the
        given return URL."""

        # fixme: we might want to have the option to pass the return
        # url via a query argument. This would allow people to set up
        # signout buttons that hit pages that send them right back to
        # the referring page. In other words, someone on page
        # example.com/A that hits the signout button gets sent to
        # example.com/opid/signout, which then redirects right back to
        # example.com/A.

        def wsgi(environ, start_response):
            self.unauth(environ)
            environ['opid.redirect_url'] = return_url
            return self.redirect_app(environ, start_response)

        return wsgi


# alias a couple stores for convenience
MemStore = openid.store.memstore.MemoryStore
FileStore = openid.store.filestore.FileOpenIDStore
