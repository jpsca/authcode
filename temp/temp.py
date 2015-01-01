# coding=utf-8
import cherrypy
import authcode


auth = authcode.Auth(u'qwertyuiopqwertyuiopqwertyuio', wsgi=authcode.wsgi.cherrypy)
authcode.setup_for_cherrypy(auth)

"""
'app', 'args', 'base', 'body', 'body_params', 'close', 'closed', 'config', 'cookie', 'dispatch', 'error_page', 'error_response', 'get_resource', 'handle_error', 'handler', 'header_list', 'headers', 'hooks', 'is_index', 'kwargs', 'local', 'login', 'method', 'methods_with_bodies', 'multiprocess', 'multithread', 'namespaces', 'params', 'path_info', 'prev', 'process_headers', 'process_query_string', 'process_request_body', 'protocol', 'query_string', 'query_string_encoding', 'remote', 'request_line', 'respond', 'rfile', 'run', 'scheme', 'script_name', 'server_protocol', 'show_mismatched_params', 'show_tracebacks', 'stage', 'throw_errors', 'throws', 'toolmaps', 'user', 'wsgi_environ']
"""


class Index(object):
    @cherrypy.expose
    @cherrypy.tools.protected()
    def index(self):
        return "Hello World!"

    @cherrypy.expose
    # @cherrypy.tools.protected()
    def meh(self, year, yeah=None):
        return str(cherrypy.request.path_info)
        return "Hello World!"


conf = {
    '/': {
        'tools.sessions.on': True,
    }
}

if __name__ == '__main__':
    cherrypy.engine.autoreload.on = True
    cherrypy.quickstart(Index(), config=conf)
